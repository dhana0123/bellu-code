package facade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	bgeengine "github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/metrics"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/otlp"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
)

const (
	defaultOpenTimeout = 5 * time.Second
	otlpStopTimeout    = 5 * time.Second
	dirMode            = 0o700
	fileMode           = 0o600
)

// umaskMu serialises the process-wide umask change used while the store
// creates its files.
var umaskMu sync.Mutex

// Open starts the engine in-process. Disabled config returns a disabled
// engine without opening anything. If the store cannot be opened (insecure
// permissions, lock held, corrupt, or slower than the open timeout) Open
// returns a failed engine whose routes answer 503 graph_unavailable, together
// with the error; callers keep serving non-graph routes with that engine.
func Open(ctx context.Context, cfg Config) (Engine, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	if !cfg.Enabled {
		log.Info("graph engine disabled")
		return newUnavailable(State{StateDisabled, "disabled by " + EnvEnabled}), nil
	}
	timeout := cfg.OpenTimeout
	if timeout <= 0 {
		timeout = defaultOpenTimeout
	}
	if cfg.Dir == "" {
		d, err := DefaultDir()
		if err != nil {
			return fail(log, cfg, err)
		}
		cfg.Dir = d
	}

	type result struct {
		e   *engine
		err error
	}
	done := make(chan result, 1)
	go func() {
		e, err := openStore(cfg, log)
		done <- result{e, err}
	}()
	release := func() { // release a late success; never leak the lock
		if r := <-done; r.e != nil {
			_ = r.e.stack.Close(context.Background())
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		if r.err != nil {
			return fail(log, cfg, r.err)
		}
		r.e.start()
		return r.e, nil
	case <-timer.C:
		go release()
		return fail(log, cfg, fmt.Errorf("opening graph store timed out after %s", timeout))
	case <-ctx.Done():
		go release()
		return fail(log, cfg, ctx.Err())
	}
}

func fail(log *slog.Logger, cfg Config, err error) (Engine, error) {
	if errors.Is(err, ErrLocked) {
		// The single error-level entry for lock contention names the holder path.
		log.Error("graph engine disabled: store lock is held by another process",
			"holder_path", filepath.Join(store.Path(cfg.Dir), "LOCK"), "err", err)
	} else {
		log.Error("graph engine disabled: store unavailable", "err", err)
	}
	return newUnavailable(State{StateFailed, err.Error()}), err
}

// checkDir validates (or creates) the data dir without altering the
// permissions of an existing one.
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return os.MkdirAll(dir, dirMode)
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("graph data path %s is not a directory", dir)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%w: %s has mode %04o, want 0700", ErrInsecurePermissions, dir, fi.Mode().Perm())
	}
	return nil
}

func openStore(cfg Config, log *slog.Logger) (*engine, error) {
	if err := checkDir(cfg.Dir); err != nil {
		return nil, err
	}
	umaskMu.Lock()
	old := setUmask(0o077) // every file/dir the store creates is 0600/0700
	defer func() { setUmask(old); umaskMu.Unlock() }()

	// The engine opens an existing store read-only and loads it before it
	// opens it for writing, so a locked or damaged store is reported (ErrLocked,
	// ErrCorrupt) before any file is written.
	core, err := bgeengine.Open(cfg.Dir, bgeengine.Options{Logger: log, Retention: cfg.Retention})
	if err != nil {
		return nil, err
	}
	en := &engine{cfg: cfg, log: log, stack: core}
	if fa, err := openFileAudit(cfg.Dir); err != nil {
		log.Error("audit log unavailable; annotate_entity will be refused", "err", err)
	} else {
		en.auditFile, en.audit = fa, fa
	}
	tightenFiles(cfg.Dir)
	return en, nil
}

// tightenFiles makes every file below dir 0600 (files created after the open
// by compaction run under the caller's umask). The 0700 dir already shields
// them; this closes the gap for defense in depth. Only runs on a dir we opened.
func tightenFiles(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if fi, e := d.Info(); e == nil && fi.Mode().Perm()&0o077 != 0 {
				_ = os.Chmod(p, dirMode)
			}
			return nil
		}
		if fi, e := d.Info(); e == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(p, fileMode)
		}
		return nil
	})
}

type engine struct {
	cfg   Config
	log   *slog.Logger
	stack *bgeengine.Core

	recv *otlp.Server

	audit     AuditSink // annotate_entity audit trail; nil refuses annotations
	auditFile *fileAudit
	closeOnce sync.Once
	closeErr  error
}

func (e *engine) start() {
	if e.cfg.OTLPListen == "" {
		return
	}
	if err := e.startOTLP(); err != nil {
		e.log.Error("otlp listener failed; continuing without it", "listen", e.cfg.OTLPListen, "err", err)
	}
}

func (e *engine) startOTLP() error {
	lis, err := net.Listen("tcp", e.cfg.OTLPListen)
	if err != nil {
		return err
	}
	e.recv = otlp.New(otlp.Config{
		Applier:   e.stack,
		Authorize: e.authorizeIngest,
		Ready:     e.ready,
		Metrics:   metrics.New(),
		Logger:    e.log,
	})
	go func(recv *otlp.Server) {
		if err := recv.Serve(lis); err != nil {
			e.log.Error("otlp receiver stopped", "err", err)
		}
	}(e.recv)
	return nil
}

// State maps the engine core's lifecycle onto the Facade states.
func (e *engine) State() State {
	switch e.stack.State() {
	case bgeengine.StateReady:
		return State{StateReady, ""}
	case bgeengine.StateStarting:
		return State{StateStarting, "opening"}
	case bgeengine.StateFailed:
		return State{StateFailed, fmt.Sprint(e.stack.Failure())}
	}
	return State{StateDisabled, "closed"}
}

func (e *engine) Ingest() Ingest { return e }
func (e *engine) Query() Query   { return e }

// Close stops the OTLP receiver, writes a final snapshot and closes the store.
func (e *engine) Close(ctx context.Context) error {
	e.closeOnce.Do(func() { e.closeErr = e.close(ctx) })
	return e.closeErr
}

func (e *engine) close(ctx context.Context) error {
	var errs []error
	if e.recv != nil {
		sctx, cancel := context.WithTimeout(ctx, otlpStopTimeout)
		if err := e.recv.Shutdown(sctx); err != nil {
			e.log.Error("otlp receiver shutdown failed", "err", err)
		}
		cancel()
	}
	errs = append(errs, e.stack.Close(ctx))
	if e.auditFile != nil {
		errs = append(errs, e.auditFile.Close())
	}
	tightenFiles(e.cfg.Dir)
	return errors.Join(errs...)
}

// --- unavailable (disabled / failed) engine ---

type unavailable struct{ state State }

func newUnavailable(s State) *unavailable { return &unavailable{s} }

func (u *unavailable) State() State { return u.state }
func (u *unavailable) err() error {
	return fmt.Errorf("%s: %w: %s", CodeUnavailable, ErrUnavailable, u.state.Reason)
}
func (u *unavailable) Ingest() Ingest {
	return unavailableIngest{u}
}
func (u *unavailable) Query() Query                { return unavailableQuery{u} }
func (u *unavailable) Close(context.Context) error { return nil }
func (u *unavailable) MCPHandler() http.Handler    { return UnavailableHandler(u.state.Reason) }

// UnavailableHandler answers every request with 503 {"code":"graph_unavailable"}.
func UnavailableHandler(reason string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": CodeUnavailable, "message": "graph engine unavailable: " + reason})
	})
}

type unavailableIngest struct{ u *unavailable }

func (i unavailableIngest) Apply(context.Context, Batch) (Receipt, error) {
	return Receipt{}, i.u.err()
}

type unavailableQuery struct{ u *unavailable }

func (q unavailableQuery) Entity(context.Context, EntityID, *time.Time) (Entity, error) {
	return Entity{}, q.u.err()
}
func (q unavailableQuery) Find(context.Context, FindQuery) (Page[Entity], error) {
	return Page[Entity]{}, q.u.err()
}
func (q unavailableQuery) Neighbors(context.Context, EntityID, NeighborOpts) (Page[Edge], error) {
	return Page[Edge]{}, q.u.err()
}
func (q unavailableQuery) History(context.Context, EntityID, TimeRange, Paging) (Page[Change], error) {
	return Page[Change]{}, q.u.err()
}
func (q unavailableQuery) Changes(context.Context, TimeRange, ChangeFilter) (Page[Change], error) {
	return Page[Change]{}, q.u.err()
}
func (q unavailableQuery) Diff(context.Context, time.Time, time.Time) (Diff, error) {
	return Diff{}, q.u.err()
}
