// Package collectors runs in-process graph collectors: it schedules them,
// scrubs every batch through the redaction guard, and appends it to the engine.
package collectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// Collector produces the full current observation for its scope.
type Collector interface {
	Name() string
	Interval() time.Duration
	// Collect returns the full current observation; the engine derives
	// added/changed/removed by diffing against the projection.
	Collect(ctx context.Context) (graph.Batch, error)
}

// Timeouter is an optional Collector interface overriding the per-tick timeout.
type Timeouter interface{ Timeout() time.Duration }

// RateLimitWait is one wait a collector performed for a source's rate limit.
type RateLimitWait = store.RateLimitWait

// Truncation is one cap a collector reached: Omitted items of Scope were left out.
type Truncation = store.Truncation

// RunStatus is what a collector reports about its last run beyond the batch.
type RunStatus struct {
	RateLimitWaits []RateLimitWait // waits performed until the source's reset time
	AuthError      string          // set when credentials were rejected; the run ended
	DeniedScopes   []string        // access-denied scopes; the run continued
	Truncations    []Truncation    // caps reached; the run continued
	Gaps           []Gap           // resource types or scopes that could not be read; persisted to collector_gap
}

// StatusReporter is an optional Collector interface. RunStatus is read after
// Collect returns and describes that call.
type StatusReporter interface{ RunStatus() RunStatus }

// StatusRecorder collects a RunStatus while a collector runs. The zero value
// is ready to use and is safe for concurrent use.
type StatusRecorder struct {
	mu sync.Mutex
	st RunStatus
}

// Reset clears the recorded status at the start of a run.
func (r *StatusRecorder) Reset() {
	r.mu.Lock()
	r.st = RunStatus{}
	r.mu.Unlock()
}

// Wait records a rate-limit wait.
func (r *StatusRecorder) Wait(scope string, until time.Time, waited time.Duration) {
	r.mu.Lock()
	r.st.RateLimitWaits = append(r.st.RateLimitWaits, RateLimitWait{Scope: scope, Until: until.UTC(), WaitedMS: waited.Milliseconds()})
	r.mu.Unlock()
}

// Auth records an authorization error. The first one wins.
func (r *StatusRecorder) Auth(msg string) {
	r.mu.Lock()
	if r.st.AuthError == "" {
		r.st.AuthError = msg
	}
	r.mu.Unlock()
}

// Deny records an access-denied scope once.
func (r *StatusRecorder) Deny(scope string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.st.DeniedScopes {
		if s == scope {
			return
		}
	}
	r.st.DeniedScopes = append(r.st.DeniedScopes, scope)
}

// Truncate records that a cap was reached in scope and omitted items were left out.
func (r *StatusRecorder) Truncate(scope string, omitted int) {
	r.mu.Lock()
	r.st.Truncations = append(r.st.Truncations, Truncation{Scope: scope, Omitted: omitted})
	r.mu.Unlock()
}

// Status returns a copy of the recorded status.
func (r *StatusRecorder) Status() RunStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RunStatus{
		RateLimitWaits: append([]RateLimitWait(nil), r.st.RateLimitWaits...),
		AuthError:      r.st.AuthError,
		DeniedScopes:   append([]string(nil), r.st.DeniedScopes...),
		Truncations:    append([]Truncation(nil), r.st.Truncations...),
		Gaps:           append([]Gap(nil), r.st.Gaps...),
	}
}

// ConnectorTimeout is the per-run timeout for cloud connector collectors.
const ConnectorTimeout = 120 * time.Second

// PartialError is returned by Collect together with a usable batch when some
// resource types failed. The batch is still applied and the run is recorded as
// ok with last_error "partial: <types>".
type PartialError struct{ Types []string }

func (e PartialError) Error() string { return "partial: " + strings.Join(e.Types, ",") }

const (
	// TickTimeout bounds one Collect+Apply cycle.
	TickTimeout = 30 * time.Second
	// StatusCollector is the batch source used for collector_status entities.
	StatusCollector = "collector_status"

	minBackoff = time.Minute
	maxBackoff = 15 * time.Minute
)

// Status values recorded in collector_status.
const (
	StatusOK      = "ok"
	StatusError   = "error"
	StatusTimeout = "timeout"
	StatusLeak    = "leak"
)

// Logger is the subset of *log.Logger the runner needs.
type Logger interface{ Println(v ...any) }

type nopLogger struct{}

func (nopLogger) Println(...any) {}

type state struct {
	status    string
	lastError string
	lastRun   time.Time
	// logging backoff
	nextLog time.Time
	backoff time.Duration
}

// Runner schedules collectors and feeds their batches to the engine.
type Runner struct {
	engine     graph.Engine
	guard      redact.Guard
	collectors []Collector
	log        Logger
	now        func() time.Time
	timeout    time.Duration
	onBatch    func(ctx context.Context, b graph.Batch) error
	gapSink    GapSink

	mu     sync.Mutex // guards states, forgot and serializes status writes
	states map[string]*state
	forgot bool // a state was removed; the next status write must publish it

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Option customizes a Runner.
type Option func(*Runner)

// WithLogger sets the logger (default: discard).
func WithLogger(l Logger) Option { return func(r *Runner) { r.log = l } }

// WithGuard overrides the redaction guard (default: redact.New()).
func WithGuard(g redact.Guard) Option { return func(r *Runner) { r.guard = g } }

// WithClock overrides the time source.
func WithClock(now func() time.Time) Option { return func(r *Runner) { r.now = now } }

// WithTickTimeout overrides the per-tick timeout (default 30s).
func WithTickTimeout(d time.Duration) Option { return func(r *Runner) { r.timeout = d } }

// WithOnBatch sets a hook called after a collector's batch was applied, with
// the applied batch. The hook runs inside the tick, so the tick timeout bounds
// it. Its error is logged and does not change the collector's status. The
// engine receipt does not say which entities changed, so the hook gets every
// entity of the batch.
func WithOnBatch(f func(ctx context.Context, b graph.Batch) error) Option {
	return func(r *Runner) { r.onBatch = f }
}

// New builds a runner. The engine is only used through Ingest().Apply.
func New(e graph.Engine, cols []Collector, opts ...Option) *Runner {
	r := &Runner{
		engine: e, guard: redact.New(), collectors: cols,
		log: nopLogger{}, now: time.Now, timeout: TickTimeout,
		states: map[string]*state{},
	}
	for _, o := range opts {
		o(r)
	}
	for _, c := range cols {
		r.states[c.Name()] = &state{}
	}
	return r
}

// Start launches one goroutine per collector. It is a no-op without collectors.
func (r *Runner) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	for _, c := range r.collectors {
		r.wg.Add(1)
		go r.loop(ctx, c)
	}
}

// Stop cancels all collectors and waits for in-flight ticks to finish.
func (r *Runner) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

func (r *Runner) loop(ctx context.Context, c Collector) {
	defer r.wg.Done()
	iv := c.Interval()
	if iv <= 0 {
		iv = 30 * time.Second
	}
	for {
		r.RunOnce(ctx, c)
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		}
	}
}

// RunOnce executes one tick for c, records its status, and logs failures with
// backoff. Failures never propagate to other collectors.
func (r *Runner) RunOnce(ctx context.Context, c Collector) error {
	timeout := r.timeout
	if t, ok := c.(Timeouter); ok && t.Timeout() > 0 {
		timeout = t.Timeout()
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	partial, err := r.tick(tctx, c)
	timedOut := errors.Is(tctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	cancel()
	if ctx.Err() != nil && err != nil {
		return err // shutting down: do not record a spurious failure
	}
	status, msg := StatusOK, ""
	switch {
	case err == nil && partial != nil:
		msg = partial.Error()
	case err == nil:
	case errors.Is(err, redact.ErrSecretLeak):
		status, msg = StatusLeak, err.Error()
	case timedOut || errors.Is(err, context.DeadlineExceeded):
		status, msg = StatusTimeout, "tick exceeded "+timeout.String()
	default:
		status, msg = StatusError, err.Error()
	}
	r.record(ctx, c.Name(), status, msg)
	r.persistGaps(ctx, c)
	return err
}

// tick is Algorithm E: collect, scrub, leak-check, apply.
func (r *Runner) tick(ctx context.Context, c Collector) (partial *PartialError, err error) {
	b, err := c.Collect(ctx)
	var pe PartialError
	if errors.As(err, &pe) {
		partial, err = &pe, nil
	}
	if err != nil {
		return nil, err
	}
	if b.Collector == "" {
		b.Collector = c.Name()
	}
	defer func() { // guard failure discards the batch
		if p := recover(); p != nil {
			err = fmt.Errorf("redaction guard failed: %v", p)
		}
	}()
	b = r.guard.Scrub(b)
	if rule, leaked := r.guard.FirstLeak(b); leaked || r.guard.Leaks(b) {
		// Audit line: collector and rule id only.
		r.log.Println("audit: secret leak blocked collector=" + c.Name() + " rule=" + rule)
		return nil, redact.ErrSecretLeak
	}
	if _, err = r.engine.Ingest().Apply(ctx, b); err != nil {
		return partial, err
	}
	if r.onBatch != nil {
		if herr := r.onBatch(ctx, b); herr != nil {
			r.log.Println("collector", c.Name(), "on-batch hook failed:", herr)
		}
	}
	return partial, nil
}

// Forget drops a collector's state so its collector_status entity is removed
// on the next status write.
func (r *Runner) Forget(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.states[name]; ok {
		delete(r.states, name)
		r.forgot = true
	}
}

func (r *Runner) record(ctx context.Context, name, status, msg string) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.states[name]
	if st == nil {
		st = &state{}
		r.states[name] = st
	}
	st.status, st.lastError, st.lastRun = status, msg, now
	if status == StatusOK {
		st.backoff, st.nextLog = 0, time.Time{}
	} else if !now.Before(st.nextLog) {
		r.log.Println("collector", name, status+":", msg)
		st.backoff = min(max(st.backoff*2, minBackoff), maxBackoff)
		st.nextLog = now.Add(st.backoff)
	}
	if err := r.writeStatus(ctx); err != nil && ctx.Err() == nil {
		r.log.Println("collector_status write failed:", err)
	}
}

// writeStatus appends all collectors' statuses as a separate batch so each
// collector's own full-observation batches are unaffected. Caller holds r.mu.
func (r *Runner) writeStatus(ctx context.Context) error {
	names := make([]string, 0, len(r.states))
	for n := range r.states {
		names = append(names, n)
	}
	sort.Strings(names)
	b := graph.Batch{Collector: StatusCollector, ObservedAt: r.now()}
	for _, n := range names {
		st := r.states[n]
		if st.lastRun.IsZero() {
			continue
		}
		b.Entities = append(b.Entities, entity(n, st))
	}
	if len(b.Entities) == 0 && !r.forgot {
		return nil
	}
	r.forgot = false
	b = r.guard.Scrub(b)
	if r.guard.Leaks(b) {
		return redact.ErrSecretLeak
	}
	_, err := r.engine.Ingest().Apply(ctx, b)
	return err
}

func entity(name string, st *state) batch.Entity {
	return batch.Entity{
		Type:     "collector_status",
		Identity: map[string]string{"collector": name},
		Attributes: map[string]any{
			"status":     st.status,
			"last_error": st.lastError,
			"last_run":   st.lastRun.UTC().Format(time.RFC3339Nano),
		},
	}
}

// persistGaps hands the run's gaps to the gap sink. A sink failure is logged
// and does not change the run's status.
func (r *Runner) persistGaps(ctx context.Context, c Collector) {
	sr, ok := c.(StatusReporter)
	if !ok || r.gapSink == nil {
		return
	}
	if err := r.gapSink(ctx, c.Name(), sr.RunStatus().Gaps, r.now()); err != nil && ctx.Err() == nil {
		r.log.Println("collector_gap write failed:", err)
	}
}
