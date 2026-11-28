package posture

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime/metrics"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

// Limits per entity evaluation (Requirements 10.5, 10.12, 10.15).
const (
	MaxQueryCalls     = 100         // GraphReader calls per entity evaluation
	MaxQueryEntities  = 1000        // entities or edges returned by one call
	CPULimit          = time.Second // wall-clock budget per entity evaluation
	MemoryLimitBytes  = 256 << 20   // heap growth allowed per entity evaluation
	memorySampleEvery = 2 * time.Millisecond
)

// Limit names a limit that stopped an evaluation.
type Limit string

const (
	LimitCPU      Limit = "cpu"
	LimitMemory   Limit = "memory"
	LimitQueries  Limit = "queries"
	LimitEntities Limit = "entities"
)

// EvalError records that one rule failed on one entity. Limit is set when a
// resource limit stopped the evaluation.
type EvalError struct {
	PackID, RuleID, EntityID string
	Limit                    Limit
	Detail                   string
}

func (e EvalError) Error() string {
	what := e.Detail
	if e.Limit != "" {
		what = string(e.Limit) + " limit exceeded"
	}
	return fmt.Sprintf("%s/%s on %s: %s", e.PackID, e.RuleID, e.EntityID, what)
}

// GraphReader is the read side of the graph. facade.Query satisfies it.
type GraphReader interface {
	Entity(ctx context.Context, id facade.EntityID, at *time.Time) (facade.Entity, error)
	Find(ctx context.Context, q facade.FindQuery) (facade.Page[facade.Entity], error)
	Neighbors(ctx context.Context, id facade.EntityID, opt facade.NeighborOpts) (facade.Page[facade.Edge], error)
}

// Input is the entity a rule is evaluated on. Rules see it as `input`.
type Input struct {
	ID, Type, Label string
	Attributes      map[string]any
}

// Memory enforcement (Design Open Item 3).
//
// OPA exposes no memory cap and has no instruction limit, and a goroutine's
// allocations cannot be measured on their own, so the limit is a watchdog.
// Evaluations run one at a time (evalMu), so growth of the process heap during
// an evaluation is that evaluation's growth. A goroutine samples
// /memory/classes/heap/objects:bytes (live objects plus not yet swept garbage,
// so it rises as fast as the allocator) every 2 ms. It tracks the lowest value
// seen as the baseline and cancels the evaluation's context when the heap is
// MemoryLimitBytes above it. OPA checks that context in its evaluation loop,
// so the evaluation stops within a few milliseconds, long before a bomb that
// allocates a few GB/s could reach twice the limit. The risk is a single
// builtin call that allocates more than the limit without returning to the
// loop; TestMemoryBombStopped covers the comprehension and string-building
// cases and the capabilities drop nothing else that allocates unboundedly.
// The CPU limit is a context deadline of CPULimit.

var heapSample = []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}

// deniedBuiltins are removed in addition to every non-deterministic builtin
// (which already covers http.send, opa.runtime, net.lookup_ip_addr, time.now_ns,
// rand.intn and uuid.*), so rules cannot reach the network, files or the clock.
var deniedBuiltins = []string{
	"http.send", "opa.runtime", "net.lookup_ip_addr", "time.now_ns", "rand.intn",
	"uuid.rfc4122", "providers.aws.sign_req", "trace",
}

func capabilities() *ast.Capabilities {
	c := ast.CapabilitiesForThisVersion()
	c.Builtins = slices.DeleteFunc(c.Builtins, func(b *ast.Builtin) bool {
		return b.Nondeterministic || slices.Contains(deniedBuiltins, b.Name)
	})
	c.AllowNet = []string{}
	return c
}

// evalState is the per-evaluation query budget, carried in the context.
type evalState struct {
	reader GraphReader
	calls  atomic.Int32
	limit  atomic.Value // Limit
}

type stateKey struct{}

func (s *evalState) trip(l Limit) error {
	s.limit.CompareAndSwap(nil, l)
	return errors.New(string(l) + " limit exceeded")
}

func stateOf(ctx context.Context) *evalState {
	s, _ := ctx.Value(stateKey{}).(*evalState)
	return s
}

func (s *evalState) enter() error {
	if s.calls.Add(1) > MaxQueryCalls {
		return s.trip(LimitQueries)
	}
	return nil
}

func str(t *ast.Term) (string, bool) {
	s, ok := t.Value.(ast.String)
	return string(s), ok
}

func toTerm(v any) (*ast.Term, error) {
	val, err := ast.InterfaceToValue(v)
	if err != nil {
		return nil, err
	}
	return ast.NewTerm(val), nil
}

func entityValue(e facade.Entity) map[string]any {
	return map[string]any{"id": string(e.ID), "type": e.Type, "label": e.Label, "attributes": jsonSafe(e.Attributes)}
}

func jsonSafe(m map[string]any) any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch x := v.(type) {
		case nil, bool, string, float64, int, int64, []any, map[string]any:
			out[k] = x
		default:
			out[k] = fmt.Sprint(x)
		}
	}
	return out
}

// builtins declares bellu.entity, bellu.neighbors and bellu.find. They read the
// graph through the evalState in the context; without one (compile-only use)
// they return undefined.
func builtins() []func(*rego.Rego) {
	obj := types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))
	return []func(*rego.Rego){
		rego.Function1(&rego.Function{Name: "bellu.entity", Decl: types.NewFunction(types.Args(types.S), types.A)},
			func(bc rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
				st := stateOf(bc.Context)
				id, ok := str(a)
				if st == nil || !ok {
					return nil, nil
				}
				if err := st.enter(); err != nil {
					return nil, err
				}
				e, err := st.reader.Entity(bc.Context, facade.EntityID(id), nil)
				if err != nil {
					return nil, nil // unknown entity: undefined
				}
				return toTerm(entityValue(e))
			}),
		rego.Function2(&rego.Function{Name: "bellu.neighbors", Decl: types.NewFunction(types.Args(types.S, types.S), types.NewArray(nil, types.A))},
			func(bc rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
				st := stateOf(bc.Context)
				id, ok1 := str(a)
				rel, ok2 := str(b)
				if st == nil || !ok1 || !ok2 {
					return nil, nil
				}
				if err := st.enter(); err != nil {
					return nil, err
				}
				pg, err := st.reader.Neighbors(bc.Context, facade.EntityID(id),
					facade.NeighborOpts{RelationType: rel, Paging: facade.Paging{PageSize: facade.MaxPageSize}})
				if err != nil {
					return nil, nil
				}
				if pg.Truncated || len(pg.Items) > MaxQueryEntities {
					return nil, st.trip(LimitEntities)
				}
				out := make([]any, 0, len(pg.Items))
				for _, e := range pg.Items {
					out = append(out, map[string]any{"from": string(e.From), "to": string(e.To), "type": e.Type, "direction": e.Direction})
				}
				return toTerm(out)
			}),
		rego.Function2(&rego.Function{Name: "bellu.find", Decl: types.NewFunction(types.Args(types.S, obj), types.NewArray(nil, types.A))},
			func(bc rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
				st := stateOf(bc.Context)
				typ, ok := str(a)
				attrs, ok2 := ast.JSONWithOpt(b.Value, ast.JSONOpt{})
				m, ok3 := attrs.(map[string]any)
				if st == nil || !ok || ok2 != nil || !ok3 {
					return nil, nil
				}
				if err := st.enter(); err != nil {
					return nil, err
				}
				q := facade.FindQuery{Type: typ, Paging: facade.Paging{PageSize: facade.MaxPageSize}}
				if len(m) > 0 {
					q.Attributes = map[string]string{}
					for k, v := range m {
						q.Attributes[k] = fmt.Sprint(v)
					}
				}
				pg, err := st.reader.Find(bc.Context, q)
				if err != nil {
					return nil, nil
				}
				if pg.Truncated || len(pg.Items) > MaxQueryEntities {
					return nil, st.trip(LimitEntities)
				}
				out := make([]any, 0, len(pg.Items))
				for _, e := range pg.Items {
					out = append(out, entityValue(e))
				}
				return toTerm(out)
			}),
	}
}

func prepare(ctx context.Context, name, src string) (rego.PreparedEvalQuery, error) {
	mod, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	opts := append([]func(*rego.Rego){
		rego.Module(name, src),
		rego.Query(mod.Package.Path.String() + ".violation"),
		rego.Capabilities(capabilities()),
		rego.StrictBuiltinErrors(true),
	}, builtins()...)
	return rego.New(opts...).PrepareForEval(ctx)
}

// CompileRego checks that src compiles under the restricted capabilities. The
// Rule_Pack loader and checkpacks use it, so a rule that calls a removed builtin
// is rejected at load time (Requirements 10.4, 10.14).
func CompileRego(ctx context.Context, src string) error {
	_, err := prepare(ctx, "rule.rego", src)
	return err
}

type preparedRule struct {
	pack string
	rule Rule
	q    rego.PreparedEvalQuery
}

// Engine evaluates rules with OPA. Build it with NewEngine and reuse it.
//
// A rule is a Rego module whose `violation` set holds objects with optional
// "discriminator" (string), "evidence" (object of strings) and "path" (array of
// {"entity","relation"}). `input` is {"id","type","label","attributes"}.
type Engine struct {
	reader   GraphReader
	rules    []preparedRule
	cpuLimit time.Duration
	evalMu   sync.Mutex        // one evaluation at a time, so heap growth is attributable
	versions map[string]string // pack id -> version
	run      runConfig
	// Data supplies `input.data` for the rules (allowed ports, classifications).
	// It is called once per rule evaluation, so it should return a cached value.
	// Nil means rules see no `input.data`.
	Data func() map[string]any
}

// NewEngine prepares every rule of packs once. A rule that does not compile is
// left out and returned as a RuleError.
func NewEngine(ctx context.Context, packs []Pack, reader GraphReader) (*Engine, []RuleError) {
	e := &Engine{reader: reader, cpuLimit: CPULimit, versions: map[string]string{}, run: runConfig{backoff: defaultBackoff}}
	var errs []RuleError
	for _, p := range packs {
		e.versions[p.ID] = p.Version
		for _, r := range p.Rules {
			var q rego.PreparedEvalQuery
			src, err := fs.ReadFile(p.Source, r.Rego)
			if err == nil {
				q, err = prepare(ctx, r.Rego, string(src))
			}
			if err == nil {
				e.rules = append(e.rules, preparedRule{pack: p.ID, rule: r, q: q})
				continue
			}
			errs = append(errs, RuleError{Pack: p.ID, RuleID: r.ID, Check: "compile", Detail: err.Error()})
		}
	}
	return e, errs
}

// EvalEntity runs every rule that applies to in.Type. A rule that errors or hits
// a limit is recorded in the returned errors and the next rule still runs.
func (e *Engine) EvalEntity(ctx context.Context, in Input) ([]Match, []EvalError) {
	var matches []Match
	var errs []EvalError
	for i := range e.rules {
		pr := &e.rules[i]
		if !slices.Contains(pr.rule.AppliesTo, in.Type) {
			continue
		}
		if ctx.Err() != nil {
			return matches, errs
		}
		m, err := e.evalRule(ctx, pr, in)
		matches = append(matches, m...)
		if err != nil {
			errs = append(errs, *err)
		}
	}
	return matches, errs
}

func (e *Engine) evalRule(parent context.Context, pr *preparedRule, in Input) ([]Match, *EvalError) {
	e.evalMu.Lock()
	defer e.evalMu.Unlock()

	fail := func(l Limit, detail string) *EvalError {
		return &EvalError{PackID: pr.pack, RuleID: pr.rule.ID, EntityID: in.ID, Limit: l, Detail: detail}
	}
	st := &evalState{reader: e.reader}
	ctx, cancel := context.WithTimeout(context.WithValue(parent, stateKey{}, st), e.cpuLimit)
	defer cancel()
	ctx, cancelMem := context.WithCancel(ctx)
	defer cancelMem()

	var memHit atomic.Bool
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sample := make([]metrics.Sample, 1)
		copy(sample, heapSample)
		base := ^uint64(0)
		t := time.NewTicker(memorySampleEvery)
		defer t.Stop()
		for {
			metrics.Read(sample)
			cur := sample[0].Value.Uint64()
			base = min(base, cur)
			if cur-base > MemoryLimitBytes {
				memHit.Store(true)
				cancelMem()
				return
			}
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	}()
	input := map[string]any{
		"id": in.ID, "type": in.Type, "label": in.Label, "attributes": jsonSafe(in.Attributes),
	}
	if e.Data != nil {
		input["data"] = e.Data()
	}
	rs, err := pr.q.Eval(ctx, rego.EvalInput(input))
	close(done)
	wg.Wait()

	switch {
	case memHit.Load():
		return nil, fail(LimitMemory, "")
	case st.limit.Load() != nil:
		return nil, fail(st.limit.Load().(Limit), "")
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fail(LimitCPU, "")
	case err != nil:
		return nil, fail("", err.Error())
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	set, _ := rs[0].Expressions[0].Value.([]any)
	var out []Match
	for _, v := range set {
		o, _ := v.(map[string]any)
		m := Match{PackID: pr.pack, RuleID: pr.rule.ID, EntityID: in.ID, Evidence: map[string]string{}}
		m.Discriminator, _ = o["discriminator"].(string)
		if ev, ok := o["evidence"].(map[string]any); ok {
			for k, x := range ev {
				m.Evidence[k] = fmt.Sprint(x)
			}
		}
		if path, ok := o["path"].([]any); ok {
			for _, h := range path {
				hm, _ := h.(map[string]any)
				ent, _ := hm["entity"].(string)
				rel, _ := hm["relation"].(string)
				m.Path = append(m.Path, Hop{EntityID: ent, Relation: rel})
			}
		}
		out = append(out, m)
	}
	return out, nil
}
