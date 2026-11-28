package lifecycle

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

const (
	// DefaultInterval is used when a connection has no interval.
	DefaultInterval = 15 * time.Minute
	// RefreshLead is how long before expiry a session credential is refreshed.
	RefreshLead = 300 * time.Second
	// ExpiresSoonWindow is the remaining validity below which expiresSoon is set.
	ExpiresSoonWindow = 7 * 24 * time.Hour
	// PermissionRecheckInterval is the period between permission checks.
	PermissionRecheckInterval = 24 * time.Hour
	// PermissionRetryInterval is the retry delay when a check cannot complete.
	PermissionRetryInterval = time.Hour

	minFailureBackoff = time.Minute
	maxFailureBackoff = 15 * time.Minute
	minRefreshSpacing = 30 * time.Second
	// ExpiryCheckInterval is the longest the supervisor sleeps while a
	// non-refreshable credential has an expiry, so EXPIRED is set and the
	// collector stops within 60 seconds of the expiry even if the clock jumps.
	ExpiryCheckInterval = 60 * time.Second

	// LastSync.Status values written by the supervisor.
	SyncOK      = "ok"
	SyncPartial = "partial"
	SyncError   = "error"
	SyncStale   = "stale"
)

// DefaultRetryDelays are the increasing delays of the three network and
// credential refresh retries.
var DefaultRetryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}

// FailureBackoff is min(1m·2^(n-1), 15m) for the n-th consecutive failure.
func FailureBackoff(n int) time.Duration {
	if n < 1 {
		return 0
	}
	if n > 5 {
		return maxFailureBackoff
	}
	return min(minFailureBackoff<<(n-1), maxFailureBackoff)
}

// ExpiresSoon is the derived flag set when fewer than 7 days of credential
// validity remain. It is derived, never stored.
func ExpiresSoon(c store.Connection, now time.Time) bool {
	return c.CredentialExpiresAt != nil && c.CredentialExpiresAt.Sub(now) < ExpiresSoonWindow
}

// RunStatus and RateLimitWait are the Run_Status a collector reports. They are
// defined in collectors so collectors can report them without importing this
// package.
type (
	RunStatus     = collectors.RunStatus
	RateLimitWait = collectors.RateLimitWait
)

// HTTP status codes collectors report through HTTPStatusError, so collectors
// need not import net/http.
const (
	StatusUnauthorized = 401
	StatusForbidden    = 403
	StatusNotFound     = 404
)

// HTTPStatusError lets a collector report the HTTP status that ended its run.
// 401 sets the connection EXPIRED and 403 sets it to ERROR, both without retry.
type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string { return "provider returned an HTTP error status" }

// HTTPStatus returns the status code.
func (e *HTTPStatusError) HTTPStatus() int { return e.Code }

// SessionDropper is optionally implemented by providers that keep session
// credentials in memory. It is called when a refresh fails for good.
type SessionDropper interface{ DropSession(connectionID string) }

// RunOnceRunner is the part of *collectors.Runner the supervisor uses.
type RunOnceRunner interface {
	RunOnce(ctx context.Context, c collectors.Collector) error
}

// Host is what the supervisor needs from the manager.
type Host interface {
	// Prepare resolves the provider and the broker-backed call of a connection.
	Prepare(conn store.Connection) (Provider, Call, error)
	// SetStatus moves a connection to a new status (audited).
	SetStatus(ctx context.Context, id string, to Status, reason string) error
	// Record appends an audit entry.
	Record(ctx context.Context, conn store.Connection, event, outcome string, detail map[string]string) error
}

// SupervisorConfig wires a CollectorSupervisor.
type SupervisorConfig struct {
	Store  *store.Store
	Runner RunOnceRunner
	Host   Host // may be set later with Attach, before the first Start
	// Now and After are the clock seams; defaults are time.Now and time.After.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
	// RetryDelays are the delays of the network and refresh retries
	// (default DefaultRetryDelays); its length is the retry count.
	RetryDelays []time.Duration
	Redactor    Redactor
}

// CollectorSupervisor implements Supervisor: one goroutine per ACTIVE connection.
type CollectorSupervisor struct {
	cfg SupervisorConfig
	now func() time.Time
	// after waits for d on the configured clock.
	after func(time.Duration) <-chan time.Time

	mu      sync.Mutex
	host    Host
	entries map[string]*entry
}

var _ Supervisor = (*CollectorSupervisor)(nil)

// NewCollectorSupervisor builds a supervisor with no running collectors.
func NewCollectorSupervisor(cfg SupervisorConfig) *CollectorSupervisor {
	s := &CollectorSupervisor{cfg: cfg, now: cfg.Now, after: cfg.After, host: cfg.Host, entries: map[string]*entry{}}
	if s.now == nil {
		s.now = time.Now
	}
	if s.after == nil {
		s.after = time.After
	}
	if len(s.cfg.RetryDelays) == 0 {
		s.cfg.RetryDelays = DefaultRetryDelays
	}
	return s
}

// Attach sets the host (normally Manager.Host()).
func (s *CollectorSupervisor) Attach(h Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.host = h
}

type entry struct {
	id     string
	conn   store.Connection
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	wake   chan struct{}

	running atomic.Bool
	col     atomic.Pointer[observed]
	prov    Provider // set by setup; read only by the run goroutine

	mu           sync.Mutex // guards the fields below
	collectDue   time.Time
	failures     int
	netTries     int
	lastRefresh  time.Time
	noRefreshFor *time.Time
}

// observed wraps a collector to learn partial failures and entity counts, and
// to apply the connector run timeout.
type observed struct {
	collectors.Collector
	mu       sync.Mutex
	partial  []string
	entities int
}

func (o *observed) Timeout() time.Duration {
	if t, ok := o.Collector.(collectors.Timeouter); ok && t.Timeout() > 0 {
		return t.Timeout()
	}
	return collectors.ConnectorTimeout
}

func (o *observed) Collect(ctx context.Context) (graph.Batch, error) {
	b, err := o.Collector.Collect(ctx)
	var pe collectors.PartialError
	o.mu.Lock()
	o.partial, o.entities = nil, len(b.Entities)
	if errors.As(err, &pe) {
		o.partial = pe.Types
	}
	o.mu.Unlock()
	return b, err
}

// runStatus returns what the collector reported for its last run.
func (o *observed) runStatus() RunStatus {
	if r, ok := o.Collector.(collectors.StatusReporter); ok {
		return r.RunStatus()
	}
	return RunStatus{}
}

func (o *observed) result() ([]string, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.partial, o.entities
}

// Start launches the collector goroutine of an ACTIVE connection. A running
// goroutine for the same id is cancelled first.
func (s *CollectorSupervisor) Start(conn store.Connection) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{id: conn.ID, conn: conn, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	s.mu.Lock()
	old := s.entries[conn.ID]
	s.entries[conn.ID] = e
	s.mu.Unlock()
	if old != nil {
		old.cancel()
	}
	go s.run(e)
}

// Stop cancels the collector and waits for it, bounded by ctx. Unknown ids are
// not an error.
func (s *CollectorSupervisor) Stop(ctx context.Context, id string) error {
	s.mu.Lock()
	e := s.entries[id]
	delete(s.entries, id)
	s.mu.Unlock()
	if e == nil {
		return nil
	}
	e.cancel()
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SyncNow runs one collection now. It returns ErrRunInProgress while a run is
// active for the connection.
func (s *CollectorSupervisor) SyncNow(ctx context.Context, id string) error {
	s.mu.Lock()
	e := s.entries[id]
	s.mu.Unlock()
	if e == nil || e.col.Load() == nil {
		return NewError(CodeValidationFailed, "connection is not collecting", s.cfg.Redactor)
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(e.ctx, cancel)
	defer stop()
	ran, err := s.collect(rctx, e)
	if !ran {
		return ErrRunInProgress
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
	if err == nil {
		return nil
	}
	return s.typed(err)
}

func (s *CollectorSupervisor) typed(err error) error {
	switch classifyRun(err) {
	case kindExpired:
		return NewError(CodeExpired, "provider rejected the credential", s.cfg.Redactor)
	case kindForbidden:
		return NewError(CodeInsufficientPermission, "provider denied access", s.cfg.Redactor)
	case kindDecrypt:
		return NewError(CodeDecryptFailed, "credential cannot be decrypted", s.cfg.Redactor)
	case kindNetwork:
		return NewError(CodeNetwork, "provider could not be reached", s.cfg.Redactor)
	}
	return NewError(CodeNetwork, "collection failed", s.cfg.Redactor)
}

func (s *CollectorSupervisor) hostOrNil() Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host
}

// run is the per-connection goroutine.
func (s *CollectorSupervisor) run(e *entry) {
	defer close(e.done)
	defer s.detach(e)
	if !s.setup(e) {
		return
	}
	now := s.now()
	e.mu.Lock()
	e.collectDue = now
	e.mu.Unlock()
	permDue := now
	if e.conn.LastPermissionCheck != nil {
		permDue = e.conn.LastPermissionCheck.Add(PermissionRecheckInterval)
	}
	for e.ctx.Err() == nil {
		conn, ok := s.cfg.Store.Connection(e.id)
		if !ok || conn.Removed || Status(conn.Status) != StatusActive {
			return
		}
		now = s.now()
		expiring := nonRefreshableExpiry(e.prov, conn)
		if expiring != nil && !now.Before(*expiring) {
			// No refresh exists for this credential: stop collection and
			// keep the last graph data. Reconnect replaces the token.
			s.finish(e, StatusExpired, "credential expired")
			return
		}
		refreshDue, hasRefresh := s.refreshDue(e, conn)
		if expiring != nil {
			hasRefresh = false
		}
		e.mu.Lock()
		collectDue := e.collectDue
		e.mu.Unlock()
		next := collectDue
		if permDue.Before(next) {
			next = permDue
		}
		if hasRefresh && refreshDue.Before(next) {
			next = refreshDue
		}
		if expiring != nil {
			next = minTime(next, minTime(*expiring, now.Add(ExpiryCheckInterval)))
		}
		if d := next.Sub(now); d > 0 {
			select {
			case <-e.ctx.Done():
				return
			case <-e.wake:
			case <-s.after(d):
			}
			continue
		}
		switch {
		case hasRefresh && !refreshDue.After(now):
			s.refresh(e, conn, now)
		case !permDue.After(now):
			permDue = s.recheck(e, conn, now)
		default:
			ran, _ := s.collect(e.ctx, e)
			if !ran { // a manual run holds the slot; it reschedules when done
				e.mu.Lock()
				e.collectDue = now.Add(s.interval(e))
				e.mu.Unlock()
			}
		}
	}
}

// nonRefreshableExpiry returns the credential expiry of a connection whose
// provider cannot renew it, else nil.
func nonRefreshableExpiry(p Provider, conn store.Connection) *time.Time {
	nr, ok := p.(NonRefreshable)
	if !ok || conn.CredentialExpiresAt == nil || nr.Refreshable(conn) {
		return nil
	}
	return conn.CredentialExpiresAt
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (s *CollectorSupervisor) setup(e *entry) bool {
	h := s.hostOrNil()
	if h == nil {
		return false
	}
	p, call, err := h.Prepare(e.conn)
	if err != nil {
		s.finish(e, StatusError, "connector is unavailable")
		return false
	}
	c := p.Collector(e.conn, call.Ref)
	if c == nil {
		s.finish(e, StatusError, "connector has no collector")
		return false
	}
	e.col.Store(&observed{Collector: c})
	e.prov = p
	return true
}

func (s *CollectorSupervisor) interval(e *entry) time.Duration {
	if e.conn.IntervalSec <= 0 {
		return DefaultInterval
	}
	return time.Duration(e.conn.IntervalSec) * time.Second
}

// collect runs the collector through the Runner. ran is false when another run
// of the same connection is active.
func (s *CollectorSupervisor) collect(ctx context.Context, e *entry) (ran bool, err error) {
	if !e.running.CompareAndSwap(false, true) {
		return false, nil
	}
	defer e.running.Store(false)
	err = s.cfg.Runner.RunOnce(ctx, e.col.Load())
	s.afterRun(e, err)
	return true, err
}

type runKind int

const (
	kindOther runKind = iota
	kindExpired
	kindForbidden
	kindDecrypt
	kindNetwork
)

func classifyRun(err error) runKind {
	var hs interface{ HTTPStatus() int }
	var te *Error
	var ne *broker.NetworkError
	switch {
	case errors.As(err, &hs) && hs.HTTPStatus() == 401:
		return kindExpired
	case errors.As(err, &hs) && hs.HTTPStatus() == 403:
		return kindForbidden
	case errors.As(err, &te) && (te.Code == CodeInvalidCredential || te.Code == CodeExpired):
		return kindExpired
	case errors.As(err, &te) && te.Code == CodeInsufficientPermission:
		return kindForbidden
	case errors.As(err, &te) && te.Code == CodeDecryptFailed, errors.Is(err, vault.ErrDecrypt):
		return kindDecrypt
	case errors.As(err, &te) && te.Code == CodeNetwork, errors.As(err, &ne), errors.Is(err, context.DeadlineExceeded):
		return kindNetwork
	}
	return kindOther
}

// afterRun applies the outcome of a run: schedule, counters, LastSync and the
// terminal transitions. It is called once per run (scheduled or manual).
func (s *CollectorSupervisor) afterRun(e *entry, err error) {
	if e.ctx.Err() != nil {
		return // stopping: not a failure
	}
	now := s.now()
	if err == nil {
		e.mu.Lock()
		e.failures, e.netTries = 0, 0
		e.collectDue = now.Add(s.interval(e))
		e.mu.Unlock()
		partial, n := e.col.Load().result()
		status := SyncOK
		if len(partial) > 0 {
			status = SyncPartial
		}
		t := now.UTC()
		rs := e.col.Load().runStatus()
		s.setSync(e.id, func(l *store.LastSync) {
			*l = store.LastSync{Status: status, EndedAt: &t, Entities: n, Partial: append([]string{}, partial...)}
			applyRunStatus(l, rs)
		})
		return
	}
	kind := classifyRun(err)
	// Written before the terminal transitions below, which return early.
	rs := e.col.Load().runStatus()
	s.setSync(e.id, func(l *store.LastSync) { applyRunStatus(l, rs) })
	switch kind {
	case kindExpired:
		s.finish(e, StatusExpired, "provider rejected the credential (HTTP 401)")
		return
	case kindForbidden:
		s.finish(e, StatusError, "provider denied access (HTTP 403)")
		return
	case kindDecrypt:
		s.finish(e, StatusError, "credential cannot be decrypted; reconnect")
		return
	}
	e.mu.Lock()
	stale := false
	switch {
	case kind == kindNetwork && e.netTries < len(s.cfg.RetryDelays):
		e.collectDue = now.Add(s.cfg.RetryDelays[e.netTries])
		e.netTries++
	default:
		stale = kind == kindNetwork
		e.netTries = 0
		e.failures++
		e.collectDue = now.Add(FailureBackoff(e.failures))
	}
	e.mu.Unlock()
	s.setSync(e.id, func(l *store.LastSync) {
		// EndedAt keeps the last successful sync time.
		l.Status = SyncError
		if stale {
			l.Status = SyncStale
		}
		if l.Partial == nil {
			l.Partial = []string{}
		}
	})
}

// applyRunStatus copies the collector-reported Run_Status into LastSync,
// replacing the values of the previous run.
func applyRunStatus(l *store.LastSync, rs RunStatus) {
	l.RateLimitWaits = rs.RateLimitWaits
	l.AuthError = rs.AuthError
	l.DeniedScopes = rs.DeniedScopes
	l.Truncations = rs.Truncations
	l.Gaps = rs.Gaps
}

func (s *CollectorSupervisor) setSync(id string, fn func(*store.LastSync)) {
	_ = s.cfg.Store.UpdateConnection(id, func(c *store.Connection) error {
		l := store.LastSync{}
		if c.LastSync != nil {
			l = *c.LastSync
		}
		fn(&l)
		c.LastSync = &l
		return nil
	})
}

// refreshDue is expiry − 300 s, never closer than minRefreshSpacing to the last
// refresh. It reports false when no refresh applies.
func (s *CollectorSupervisor) refreshDue(e *entry, conn store.Connection) (time.Time, bool) {
	exp := conn.CredentialExpiresAt
	if exp == nil {
		return time.Time{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.noRefreshFor != nil && e.noRefreshFor.Equal(*exp) {
		return time.Time{}, false
	}
	due := exp.Add(-RefreshLead)
	if !e.lastRefresh.IsZero() && due.Before(e.lastRefresh.Add(minRefreshSpacing)) {
		due = e.lastRefresh.Add(minRefreshSpacing)
	}
	return due, true
}

// refresh renews the session credential, retrying with increasing delay. When
// every attempt fails the connection becomes EXPIRED and in-memory credentials
// are dropped. A zero expiry with no error means the credential is not
// refreshable and is not asked again until its expiry changes.
func (s *CollectorSupervisor) refresh(e *entry, conn store.Connection, now time.Time) {
	p, call, err := s.hostOrNil().Prepare(conn)
	if err == nil {
		var exp time.Time
		for attempt := 0; ; attempt++ {
			exp, err = p.Refresh(e.ctx, call)
			if err == nil || e.ctx.Err() != nil || attempt >= len(s.cfg.RetryDelays) {
				break
			}
			select {
			case <-e.ctx.Done():
				return
			case <-s.after(s.cfg.RetryDelays[attempt]):
			}
		}
		if err == nil {
			e.mu.Lock()
			e.lastRefresh = now
			if exp.IsZero() {
				e.noRefreshFor = conn.CredentialExpiresAt
			}
			e.mu.Unlock()
			if !exp.IsZero() {
				u := exp.UTC()
				_ = s.cfg.Store.UpdateConnection(e.id, func(c *store.Connection) error {
					c.CredentialExpiresAt = &u
					return nil
				})
			}
			return
		}
	}
	if e.ctx.Err() != nil {
		return
	}
	if d, ok := p.(SessionDropper); ok {
		d.DropSession(e.id)
	}
	reason := "credential refresh failed"
	var te *Error
	if errors.As(err, &te) {
		reason += " (" + string(te.Code) + ")"
	}
	s.finish(e, StatusExpired, reason)
}

// recheck runs the periodic permission check and returns the next due time.
func (s *CollectorSupervisor) recheck(e *entry, conn store.Connection, now time.Time) time.Time {
	retry := now.Add(PermissionRetryInterval)
	h := s.hostOrNil()
	p, call, err := h.Prepare(conn)
	var rep PermissionReport
	if err == nil {
		rep, err = p.CheckPermissions(e.ctx, call)
	}
	if e.ctx.Err() != nil {
		return retry
	}
	actx := context.WithoutCancel(e.ctx)
	if err != nil { // retain state, audit, retry within 1 h
		code := string(CodeNetwork)
		var te *Error
		if errors.As(err, &te) {
			code = string(te.Code)
		}
		_ = h.Record(actx, conn, audit.EventTest, audit.OutcomeFailure,
			map[string]string{"step": "permission_recheck", "code": code})
		return retry
	}
	if len(rep.WriteOffenders) > 0 {
		_ = s.cfg.Store.UpdateConnection(e.id, func(c *store.Connection) error {
			c.PermissionCheck = store.PermissionExcess
			return nil
		})
		_ = h.Record(actx, conn, audit.EventPermissionChange, audit.OutcomeFailure,
			map[string]string{"write": strings.Join(rep.WriteOffenders, ",")})
		s.finish(e, StatusError, "write permissions found: "+strings.Join(rep.WriteOffenders, ", "))
		return retry
	}
	check := store.PermissionOK
	if rep.Unverifiable {
		check = store.PermissionUnverifiable
	}
	t := now.UTC()
	_ = s.cfg.Store.UpdateConnection(e.id, func(c *store.Connection) error {
		c.LastPermissionCheck, c.PermissionCheck = &t, check
		return nil
	})
	return now.Add(PermissionRecheckInterval)
}

// finish leaves the entry (so the manager's own Stop returns at once), moves the
// connection to a new status and stops the goroutine.
func (s *CollectorSupervisor) finish(e *entry, to Status, reason string) {
	s.detach(e)
	defer e.cancel()
	if h := s.hostOrNil(); h != nil {
		_ = h.SetStatus(context.WithoutCancel(e.ctx), e.id, to, reason)
	}
}

func (s *CollectorSupervisor) detach(e *entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries[e.id] == e {
		delete(s.entries, e.id)
	}
}

// Host returns the supervisor host backed by the manager.
func (m *Manager) Host() Host { return managerHost{m} }

type managerHost struct{ m *Manager }

func (h managerHost) Prepare(conn store.Connection) (Provider, Call, error) {
	p, ok := h.m.provider(conn.ConnectorID)
	if !ok {
		return nil, Call{}, errors.New("unknown connector")
	}
	ref, err := h.m.brokerRef(conn, p, credRef(conn.ID))
	if err != nil {
		return nil, Call{}, err
	}
	return p, Call{Connection: conn, Ref: ref, Client: h.m.cfg.Clients.HTTPClient(ref, "supervisor")}, nil
}

func (h managerHost) SetStatus(ctx context.Context, id string, to Status, reason string) error {
	_, err := h.m.transition(ctx, id, to, reason, false)
	return err
}

func (h managerHost) Record(ctx context.Context, conn store.Connection, event, outcome string, detail map[string]string) error {
	return h.m.cfg.Audit.Append(ctx, audit.Entry{
		TS: h.m.now().UTC(), ConnectionID: conn.ID, ConnectorID: conn.ConnectorID,
		Event: event, Outcome: outcome, Actor: audit.ActorSystem, Detail: detail,
	})
}
