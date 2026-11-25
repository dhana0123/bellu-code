package main

import (
	"context"
	"encoding/json"
	apirules "github.com/bellu/bellucode/services/bellud/internal/api/rules"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	apiissues "github.com/bellu/bellucode/services/bellud/internal/api/issues"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/issues"
	"github.com/bellu/bellucode/services/bellud/internal/posture"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/dataclass"
)

// postureFlag is the feature flag guarding the rule engine, issues and data
// classification.
const postureFlag = "security_posture"

// postureDebounce collects changes before one re-evaluation.
const postureDebounce = 2 * time.Second

// postureWiring is the running rule engine and issue builder. It is nil while
// the flag is off or any part fails to start.
type postureWiring struct {
	fnd    *findingsWiring
	engine *posture.Engine
	reev   *issues.Reevaluator
	issues *issues.Store

	allowedPorts []any
	data         atomic.Pointer[map[string]any]

	mu      sync.Mutex
	pending map[facade.EntityID]bool
	kick    chan struct{}

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// openPosture builds the engine, the issues builder and the dataclass adapter,
// starts the re-evaluation loop and hooks collector batches and scan jobs.
// Findings and a ready graph engine are required. Any failure yields nil.
func openPosture(logger interface{ Println(...any) }, getenv func(string) string, lookup func(string) (string, bool), eng graph.Engine, fnd *findingsWiring) *postureWiring {
	if fnd == nil || !config.FeatureEnabled(getenv, postureFlag, graph.IsRelease()) {
		return nil
	}
	if eng == nil || graph.StateOf(eng).Kind != graph.StateReady {
		logger.Println("warning: posture unavailable: graph engine is not ready")
		return nil
	}
	ctx, cancel := context.WithCancel(fnd.ctx)
	packs, rejected, err := posture.LoadAll(posture.Bundled())
	if err != nil {
		cancel()
		logger.Println("warning: posture unavailable:", err)
		return nil
	}
	pcfg := config.LoadPosture(lookup)
	if pcfg.CustomDir != "" {
		custom, rej, cerr := posture.LoadCustom(pcfg.CustomDir)
		if cerr != nil {
			logger.Println("warning: custom rule packs:", cerr)
		}
		packs, rejected = append(packs, custom...), append(rejected, rej...)
	}
	for _, r := range rejected {
		logger.Println("warning: rule rejected:", r.Error())
	}
	pe, compileErrs := posture.NewEngine(ctx, packs, eng.Query())
	for _, r := range compileErrs {
		logger.Println("warning: rule rejected:", r.Error())
	}
	pe.Configure(fnd.db, func(ctx context.Context) posture.FindingsSink {
		return fnd.store.JobSink(ctx, findings.ScanRef{JobID: "posture-" + time.Now().UTC().Format("20060102T150405.000000000")})
	})
	is := issues.New(fnd.db)
	w := &postureWiring{
		fnd: fnd, engine: pe, issues: is, cancel: cancel,
		pending: map[facade.EntityID]bool{}, kick: make(chan struct{}, 1),
	}
	for _, p := range pcfg.AllowedPorts {
		w.allowedPorts = append(w.allowedPorts, float64(p))
	}
	pe.Data = w.inputData
	w.reev = &issues.Reevaluator{Engine: pe, Reader: eng.Query(), Store: is, Finds: fnd.store, Packs: packs}

	// Data classification. Sampling stays off until a reader exists.
	dcfg, derr := config.LoadData(lookup, config.DefaultData())
	if derr != nil {
		logger.Println("warning: data config:", derr)
	}
	home, _ := config.ConfigDir()
	ad := dataclass.New(dataclass.GraphSource{Query: eng.Query()}, dataclass.NewResults(fnd.db), filepath.Join(home, "data-patterns.d"))
	// TODO(30.1): pass the AWS ObjectSampler as Sampling.Reader. It is the
	// connectors/aws client, which is unexported and not reachable from here.
	// Until then sampling is off, whatever data.sample_stores says.
	stores := map[string]bool{}
	for _, s := range dcfg.SampleStores {
		stores[s] = true
	}
	ad = ad.WithSampling(dataclass.Sampling{Limit: dcfg.SampleLimit, Stores: stores})
	fnd.registerAdapter(ad)

	fnd.setPostureHooks(w.onBatch, w.onScan)
	w.run(func() { w.reev.Watch(ctx) })
	w.run(func() { w.loop(ctx, logger) })
	w.trigger(nil, true) // full run on startup
	return w
}

func (w *postureWiring) run(f func()) {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		f()
	}()
}

// inputData is the cached `input.data` handed to rules.
func (w *postureWiring) inputData() map[string]any {
	if p := w.data.Load(); p != nil {
		return *p
	}
	return nil
}

// refreshData reloads the classifications from the data_classification table.
func (w *postureWiring) refreshData(ctx context.Context) error {
	rows, err := w.fnd.db.DB().QueryContext(ctx, `SELECT entity_id, classes FROM data_classification WHERE workspace_id=?`, w.fnd.db.WorkspaceID())
	if err != nil {
		return err
	}
	defer rows.Close()
	cls := map[string]any{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		var c []string
		if json.Unmarshal([]byte(raw), &c) != nil {
			continue
		}
		list := make([]any, len(c))
		for i, v := range c {
			list[i] = v
		}
		cls[id] = list
	}
	if err := rows.Err(); err != nil {
		return err
	}
	d := map[string]any{"classifications": cls}
	if len(w.allowedPorts) > 0 { // unset keeps the rule's default list
		d["allowed_ports"] = w.allowedPorts
	}
	w.data.Store(&d)
	return nil
}

// trigger queues a re-evaluation of the changed entities, or a full one.
func (w *postureWiring) trigger(changed []facade.EntityID, full bool) {
	w.mu.Lock()
	for _, id := range changed {
		w.pending[id] = true
	}
	if full {
		w.pending[""] = true // marker: full run
	}
	w.mu.Unlock()
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// onBatch re-evaluates the entities of a collector batch.
func (w *postureWiring) onBatch(_ context.Context, b graph.Batch) error {
	ids := make([]facade.EntityID, 0, len(b.Entities))
	for _, e := range b.Entities {
		h, err := identity.Hash(e.Type, e.Identity)
		if err != nil {
			continue
		}
		ids = append(ids, facade.EntityID(h))
	}
	if len(ids) > 0 {
		w.trigger(ids, false)
	}
	return nil
}

// onScan re-evaluates the target of a succeeded scan job.
func (w *postureWiring) onScan(_ context.Context, j scanners.Job) {
	w.trigger([]facade.EntityID{facade.EntityID(j.Target.ID)}, false)
}

// loop debounces triggers, then runs the engine and the issue builder.
func (w *postureWiring) loop(ctx context.Context, logger interface{ Println(...any) }) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.kick:
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(postureDebounce):
		}
		w.mu.Lock()
		scope := posture.Scope{Full: w.pending[""]}
		for id := range w.pending {
			if id != "" {
				scope.Changed = append(scope.Changed, id)
			}
		}
		clear(w.pending)
		w.mu.Unlock()
		if err := w.refreshData(ctx); err != nil {
			logger.Println("posture data:", err)
		}
		// A pack version change turns the scope into a full run inside Evaluate.
		if _, err := w.engine.Evaluate(ctx, scope); err != nil && ctx.Err() == nil {
			logger.Println("posture evaluate:", err)
			continue
		}
		if _, err := w.reev.Reevaluate(ctx, scope); err != nil && ctx.Err() == nil {
			logger.Println("issues reevaluate:", err)
		}
	}
}

// stop ends the loops and waits for them. Safe on nil.
func (w *postureWiring) stop() {
	if w == nil {
		return
	}
	w.cancel()
	w.wg.Wait()
}

// issueStore returns the issues store for the HTTP handlers, or nil.
func (w *postureWiring) issueStore() apiissues.Store {
	if w == nil {
		return nil
	}
	return w.issues
}

// rulesEngine returns the rule engine for the rules API, or nil. It returns a
// plain nil interface (not a typed nil) when the wiring is absent.
func (w *postureWiring) rulesEngine() apirules.Engine {
	if w == nil || w.engine == nil {
		return nil
	}
	return w.engine
}
