package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
	"github.com/bellu/bellucode/services/bellud/internal/cveupdate"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	intelstore "github.com/bellu/bellucode/services/bellud/internal/intel/store"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/misconfig"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/secretscan"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/syft"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/vulnmatch"
	"github.com/bellu/bellucode/services/bellud/internal/securitymcp"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// findingsFlag is the feature flag guarding the findings store, its graph
// projection and the scan queue.
const findingsFlag = "security_findings"

// cveGraphFlag enables Graph_Mode and Both_Mode of the CVE_Source.
const cveGraphFlag = "security_cve_graph"

// findingsWiring is the findings and scan queue surface of the process. It is
// nil while the flag is off or any part fails to open: no database, route,
// job or background task exists then.
type findingsWiring struct {
	db      *sqlite.Store
	dataDir string
	store   *findings.Store
	mgr     *scanners.Manager
	sched   *scanners.Scheduler

	mu       sync.Mutex
	eng      graph.Engine       // set by attachScanners when the graph is ready
	adapters []scanners.Adapter // registered with mgr by attachScanners
	cve      *cvesource.DB      // set by attachScanners; serves /api/experimental/cve

	// Posture hooks, set late by openPosture; nil until then.
	onBatch func(ctx context.Context, b graph.Batch) error
	onScan  func(ctx context.Context, j scanners.Job)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	log    interface{ Println(...any) }
}

// openFindings opens the workspace database and starts the scan queue, the
// scheduler and the snooze expiry ticker. dataDir is the bellucode data
// directory and roots the configured repository roots. A disabled flag or any
// failure yields nil and serving continues.
func openFindings(logger interface{ Println(...any) }, getenv func(string) string, lookup func(string) (string, bool), dataDir string, roots []string) *findingsWiring {
	if !config.FeatureEnabled(getenv, findingsFlag, graph.IsRelease()) {
		return nil
	}
	settings, err := config.LoadScanners(lookup)
	if err != nil {
		logger.Println("warning: findings unavailable:", err)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	db, err := sqlite.Open(ctx, dataDir, cveupdate.CLIWorkspace, sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		cancel()
		logger.Println("warning: findings unavailable:", err)
		return nil
	}
	w := &findingsWiring{db: db, dataDir: dataDir, store: findings.New(db), ctx: ctx, cancel: cancel, log: logger}
	w.mgr, err = scanners.New(scanners.Config{
		Store:    db,
		Settings: settings,
		Adapters: []scanners.Adapter{}, // no scanner adapters exist yet
		Resolve:  resolveTarget(roots),
		OnSucceeded: func(ctx context.Context, j scanners.Job) {
			w.mu.Lock()
			f := w.onScan
			w.mu.Unlock()
			if f != nil {
				f(ctx, j)
			}
		},
		SinkFor: func(j scanners.Job) scanners.JobSink {
			return scanners.FindingsSink{JobSink: w.store.JobSink(ctx, findings.ScanRef{JobID: j.ID}), Ingest: w.ingest(ctx)}
		},
	})
	if err == nil {
		err = w.mgr.Start(ctx)
	}
	if err != nil {
		logger.Println("warning: findings unavailable:", err)
		w.stop()
		w.release()
		return nil
	}
	w.sched = scanners.NewScheduler(w.mgr)
	w.sched.Start(ctx)
	w.run(func() {
		w.store.RunExpiry(ctx, findings.ExpiryInterval, func(err error) { logger.Println("findings expiry:", err) })
	})
	return w
}

// ingest returns the graph ingest for a sink, or nil while no ready engine is attached.
func (w *findingsWiring) ingest(ctx context.Context) func(batch.Batch) error {
	w.mu.Lock()
	eng := w.eng
	w.mu.Unlock()
	if eng == nil {
		return nil
	}
	return func(b batch.Batch) error { _, err := eng.Ingest().Apply(ctx, b); return err }
}

// scannerList returns the registered adapters.
func (w *findingsWiring) scannerList() []scanners.Adapter {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]scanners.Adapter(nil), w.adapters...)
}

// attachScanners registers the syft, vulnmatch, misconfig and secretscan adapters when security_scanners
// is on, and gives job sinks the graph ingest when the engine is ready. The
// CVE_Source reads the intel store (nil is fine: lookups then report a gap);
// the Local_CVE_Graph is not opened by bellud, so it is not passed. Safe on nil.
func (w *findingsWiring) attachScanners(logger interface{ Println(...any) }, getenv func(string) string, lookup func(string) (string, bool), eng graph.Engine, intel *intelStack) {
	if w == nil || !config.FeatureEnabled(getenv, scannersFlag, graph.IsRelease()) {
		return
	}
	var is *intelstore.Store
	if intel != nil {
		is = intel.store
	}
	opts := cvesource.Options{Store: is, Audit: w.db}
	if config.FeatureEnabled(getenv, cveGraphFlag, graph.IsRelease()) {
		// TODO: set config.VaultLookup to the connectors vault (entry cve/bskg_api_key)
		// once the connectors service is open before this point; the env var
		// BELLUCODE_CVE_BSKG_API_KEY works meanwhile.
		if cc, cerr := config.LoadCVE(lookup); cerr != nil {
			logger.Println("warning: cve graph mode unavailable:", cerr)
		} else {
			opts.Mode, opts.GraphCacheTTL, opts.StaleLimit, opts.BSKG = cc.Mode, cc.GraphCacheTTL, cc.StaleLimit, cvesource.NewBSKGClient(cc)
		}
	}
	src, err := cvesource.New(opts)
	if err != nil {
		logger.Println("warning: scanners unavailable:", err)
		return
	}
	sy := syft.New().WithStore(sbomstore.New(w.db))
	vm, err := vulnmatch.New(vulnmatch.Options{Source: src, SBOM: sy})
	if err != nil {
		logger.Println("warning: scanners unavailable:", err)
		return
	}
	sec, err := config.LoadSecrets(lookup)
	if err != nil {
		logger.Println("warning: scanners unavailable:", err)
		return
	}
	mc := misconfig.New().WithCustomDir(config.LoadMisconfig(lookup).CustomDir)
	// TODO: wire a credential Verifier (secrets verification) once an
	// allow-listed HTTP client exists. Verification is off by default.
	wsDir, err := sqlite.WorkspaceDir(w.dataDir, cveupdate.CLIWorkspace)
	if err != nil {
		logger.Println("warning: scanners unavailable:", err)
		return
	}
	ss := secretscan.NewAdapter(secretscan.Options{WorkspaceDir: wsDir}).WithHistory(sec.HistoryCommits)
	w.mu.Lock()
	if eng != nil && graph.StateOf(eng).Kind == graph.StateReady {
		w.eng = eng
	}
	w.adapters = []scanners.Adapter{sy, vm, mc, ss}
	w.cve = src
	w.mu.Unlock()
	w.mgr.Register(sy, vm, mc, ss)
}

// mcpExtras returns the read-only security MCP tools, or nil without wiring.
// Each tool registers only when its flag is on and its store exists.
func (w *findingsWiring) mcpExtras(getenv func(string) string) func(*mcp.Server) {
	if w == nil {
		return nil
	}
	release := graph.IsRelease()
	var cve cvesource.Source
	if w.cve != nil {
		cve = w.cve
	}
	return securitymcp.Extras(securitymcp.Deps{
		CVE:        cve,
		Findings:   w.store,
		IssueDB:    w.db.DB(),
		SBOM:       sbomstore.New(w.db),
		FindingsOn: config.FeatureEnabled(getenv, findingsFlag, release),
		ScannersOn: config.FeatureEnabled(getenv, scannersFlag, release),
	})
}

// run starts f in a goroutine that stop waits for.
func (w *findingsWiring) run(f func()) {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		f()
	}()
}

// collectorOptions returns the runner options that queue scans after a
// collection. Nil wiring adds none.
func (w *findingsWiring) collectorOptions() []collectors.Option {
	if w == nil {
		return nil
	}
	return []collectors.Option{collectors.WithOnBatch(func(ctx context.Context, b graph.Batch) error {
		err := w.mgr.AutoScan(ctx, b)
		w.mu.Lock()
		f := w.onBatch
		w.mu.Unlock()
		if f != nil {
			if perr := f(ctx, b); err == nil {
				err = perr
			}
		}
		return err
	})}
}

// registerAdapter adds an adapter to the manager and the scanner list.
func (w *findingsWiring) registerAdapter(a scanners.Adapter) {
	w.mu.Lock()
	w.adapters = append(w.adapters, a)
	w.mu.Unlock()
	w.mgr.Register(a)
}

// setPostureHooks sets the re-evaluation triggers after a batch and a scan.
func (w *findingsWiring) setPostureHooks(batch func(context.Context, graph.Batch) error, scan func(context.Context, scanners.Job)) {
	w.mu.Lock()
	w.onBatch, w.onScan = batch, scan
	w.mu.Unlock()
}

// project starts the graph projector. It does nothing without a ready engine.
func (w *findingsWiring) project(eng graph.Engine) {
	if w == nil || eng == nil || graph.StateOf(eng).Kind != graph.StateReady {
		return
	}
	p := findings.NewProjector(w.store, eng, findings.WithProjectorLogger(slog.Default()))
	w.run(func() { p.Run(w.ctx) })
}

// stop ends the background tasks and waits for them. It must run before the
// graph engine closes (the projector writes to it) and may run while the
// collector runner still lives. Safe on nil.
func (w *findingsWiring) stop() {
	if w == nil {
		return
	}
	w.cancel()
	w.sched.Close()
	w.mgr.Close()
	w.store.Close() // closes the projector's subscription
	w.wg.Wait()
}

// release closes the database. Call it after the runner has stopped, since the
// runner's batch hook enqueues scans. Safe on nil.
func (w *findingsWiring) release() {
	if w == nil {
		return
	}
	if err := w.db.Close(); err != nil {
		w.log.Println("findings close:", err)
	}
}

// resolveTarget resolves scan targets. An image exists when its id is the local
// path of an OCI or docker-archive tar (or an OCI layout directory) and resolves
// to that path. A repository
// exists when its id is the graph identity of one of the configured roots and
// resolves to that root's path. A host exists when its id is the identity of
// this machine's hostname (as the host collector reports it). Other target
// types are not found.
func resolveTarget(roots []string) func(context.Context, scanners.TargetType, string) (scanners.Target, bool, error) {
	return func(_ context.Context, typ scanners.TargetType, id string) (scanners.Target, bool, error) {
		t := scanners.Target{Type: typ, ID: id}
		switch typ {
		case scanners.TargetRepository:
			for _, r := range roots {
				abs, err := filepath.Abs(r)
				if err != nil {
					return t, false, err
				}
				h, err := identity.Hash("repository", map[string]string{"path": abs})
				if err != nil {
					return t, false, err
				}
				if string(h) == id {
					t.Path = abs
					return t, true, nil
				}
			}
		case scanners.TargetImage:
			abs, err := filepath.Abs(id)
			if err != nil || !filepath.IsAbs(id) {
				return t, false, nil
			}
			fi, err := os.Stat(abs)
			if err != nil {
				return t, false, nil
			}
			if fi.IsDir() { // OCI layout directory
				if _, err := os.Stat(filepath.Join(abs, "index.json")); err != nil {
					return t, false, nil
				}
			} else if !fi.Mode().IsRegular() {
				return t, false, nil
			}
			t.Path = abs
			return t, true, nil
		case scanners.TargetHost:
			name, err := os.Hostname()
			if err != nil {
				return t, false, err
			}
			h, err := identity.Hash("host", map[string]string{"hostname": name})
			if err != nil {
				return t, false, err
			}
			return t, string(h) == id, nil
		}
		return t, false, nil
	}
}
