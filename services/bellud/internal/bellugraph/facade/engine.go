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
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/change"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/ingest"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/registry"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/store"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/tenant"
)

const (
	defaultOpenTimeout = 5 * time.Second
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
			return fail(log, err)
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
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		if r.err != nil {
			return fail(log, r.err)
		}
		r.e.start()
		return r.e, nil
	case <-timer.C:
		go func() { // release a late success; never leak the lock
			if r := <-done; r.e != nil {
				_ = r.e.reg.Close()
			}
		}()
		return fail(log, fmt.Errorf("opening graph store timed out after %s", timeout))
	case <-ctx.Done():
		go func() {
			if r := <-done; r.e != nil {
				_ = r.e.reg.Close()
			}
		}()
		return fail(log, ctx.Err())
	}
}

func fail(log *slog.Logger, err error) (Engine, error) {
	var le *lockedError
	if errors.As(err, &le) {
		// The single error-level entry for lock contention names the holder path.
		log.Error("graph engine disabled: store lock is held by another process", "holder_path", le.path, "err", err)
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

func isLockErr(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "lock") || strings.Contains(s, "temporarily unavailable")
}

type lockedError struct {
	path string
	err  error
}

func (l *lockedError) Error() string        { return fmt.Sprintf("%v: %s: %v", ErrLocked, l.path, l.err) }
func (l *lockedError) Is(target error) bool { return target == ErrLocked }

func classify(dir string, err error) error {
	if isLockErr(err) {
		return &lockedError{path: filepath.Join(dir, tenant.Default, "LOCK"), err: err}
	}
	return fmt.Errorf("%w: %v", ErrCorrupt, err)
}

func openStore(cfg Config, log *slog.Logger) (*engine, error) {
	if err := checkDir(cfg.Dir); err != nil {
		return nil, err
	}
	umaskMu.Lock()
	old := setUmask(0o077) // every file/dir the store creates is 0600/0700
	defer func() { setUmask(old); umaskMu.Unlock() }()

	// A read-only pre-flight proves an existing log opens before the writable
	// open, which could otherwise rewrite manifests or WAL of a damaged log.
	tdir := filepath.Join(cfg.Dir, tenant.Default)
	if _, err := os.Stat(filepath.Join(tdir, "CURRENT")); err == nil {
		ro, err := store.OpenReadOnly(tdir, store.DefaultConfig())
		if err != nil {
			return nil, classify(cfg.Dir, err)
		}
		_ = ro.Close()
	}

	scfg := store.DefaultConfig()
	scfg.RetentionMaxAge = cfg.Retention
	// Collector kinds (process, listening_port, secret_finding, ...) are not in
	// the upstream vocabulary; identity shape is validated by Hash instead.
	scfg.AcceptUnknownTypes = true
	reg, err := registry.OpenWithLimits(cfg.Dir, scfg, 30*time.Second,
		registry.Limits{AutoCreate: false, Allowlist: []string{tenant.Default}}, log)
	if err != nil {
		return nil, classify(cfg.Dir, err)
	}
	st, err := reg.For(tenant.Default)
	if err != nil {
		_ = reg.Close()
		return nil, classify(cfg.Dir, err)
	}
	en := &engine{cfg: cfg, log: log, reg: reg, stack: st, state: State{StateStarting, "opening"}}
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
	reg   *registry.Registry
	stack *registry.Stack

	mu    sync.Mutex
	state State

	applyMu sync.Mutex // serialises Apply so validation and append see one projection

	recv   *ingest.Receiver
	cancel context.CancelFunc
	wg     sync.WaitGroup

	audit     AuditSink // annotate_entity audit trail; nil refuses annotations
	auditFile *fileAudit
	closeOnce sync.Once
	closeErr  error
}

func (e *engine) start() {
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	if e.cfg.OTLPListen != "" {
		if err := e.startOTLP(); err != nil {
			e.log.Error("otlp listener failed; continuing without it", "listen", e.cfg.OTLPListen, "err", err)
		}
	}
	e.wg.Add(1)
	go e.maintain(ctx)
	e.setState(State{StateReady, ""})
}

func (e *engine) startOTLP() error {
	lis, err := net.Listen("tcp", e.cfg.OTLPListen)
	if err != nil {
		return err
	}
	engineFor := func(t string) (*change.Engine, error) {
		st, err := e.reg.For(t)
		if err != nil {
			return nil, err
		}
		return st.Engine, nil
	}
	e.recv = ingest.NewRoutedReceiver(engineFor,
		func(_ context.Context, t string) bool { return t == tenant.Default },
		ingest.NewMetrics(), false, e.log)
	go func() {
		if err := e.recv.Serve(lis); err != nil {
			e.log.Error("otlp receiver stopped", "err", err)
		}
	}()
	return nil
}

// maintain runs liveness sweep, compaction/retention and snapshots, as the
// upstream server does.
func (e *engine) maintain(ctx context.Context) {
	defer e.wg.Done()
	sweep := time.NewTicker(30 * time.Second)
	compact := time.NewTicker(time.Hour)
	snap := time.NewTicker(5 * time.Minute)
	defer sweep.Stop()
	defer compact.Stop()
	defer snap.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			if _, err := e.stack.Engine.Sweep(); err != nil {
				e.log.Error("liveness sweep failed", "err", err)
			}
		case <-compact.C:
			if _, err := e.stack.Store.CoalesceHeartbeats(); err != nil {
				e.log.Error("heartbeat coalescing failed", "err", err)
			}
			if e.cfg.Retention > 0 {
				if _, _, err := e.stack.Store.PruneOlderThan(time.Now().Add(-e.cfg.Retention)); err != nil {
					e.log.Error("retention pruning failed", "err", err)
				}
			}
		case <-snap.C:
			if err := e.snapshot(); err != nil {
				e.log.Error("snapshot write failed", "err", err)
			}
		}
	}
}

func (e *engine) snapshot() error {
	st := e.stack
	seq := st.Store.Sequence()
	events := st.Graph.SnapshotEvents(time.Now())
	live, err := st.Engine.LivenessBlob()
	if err != nil {
		e.log.Error("liveness snapshot failed; writing snapshot without it", "err", err)
	}
	return st.Store.WriteSnapshot(seq, events, live)
}

func (e *engine) State() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

func (e *engine) setState(s State) {
	e.mu.Lock()
	e.state = s
	e.mu.Unlock()
}

func (e *engine) Ingest() Ingest { return e }
func (e *engine) Query() Query   { return e }

// Close stops background work, writes a final snapshot and closes the store.
func (e *engine) Close(ctx context.Context) error {
	e.closeOnce.Do(func() { e.closeErr = e.close() })
	return e.closeErr
}

func (e *engine) close() error {
	e.setState(State{StateDisabled, "closed"})
	e.cancel()
	if e.recv != nil {
		e.recv.Stop()
	}
	e.wg.Wait()
	var errs []error
	if err := e.snapshot(); err != nil {
		e.log.Error("final snapshot failed", "err", err)
	}
	errs = append(errs, e.reg.Close())
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
func (u *unavailable) err() error   { return fmt.Errorf("%w: %s", ErrUnavailable, u.state.Reason) }
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
