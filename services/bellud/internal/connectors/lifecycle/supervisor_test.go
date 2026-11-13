package lifecycle

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

var svT0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// svClock is a fake clock: After timers fire only when Advance passes them.
type svClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*svTimer
}

type svTimer struct {
	when time.Time
	ch   chan time.Time
}

func (c *svClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *svClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &svTimer{when: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	return t.ch
}

func (c *svClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	rest := c.timers[:0]
	for _, t := range c.timers {
		if t.when.After(c.now) {
			rest = append(rest, t)
			continue
		}
		t.ch <- c.now
	}
	c.timers = rest
}

// next returns the time until the earliest pending timer.
func (c *svClock) next() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timers) == 0 {
		return 0, false
	}
	best := c.timers[0].when
	for _, t := range c.timers {
		if t.when.Before(best) {
			best = t.when
		}
	}
	return best.Sub(c.now), true
}

type svRunner struct{ runs atomic.Int32 }

// RunOnce mimics collectors.Runner: a PartialError is not a failure.
func (r *svRunner) RunOnce(ctx context.Context, c collectors.Collector) error {
	r.runs.Add(1)
	_, err := c.Collect(ctx)
	var pe collectors.PartialError
	if errors.As(err, &pe) {
		return nil
	}
	return err
}

type svCollector struct {
	fn func(ctx context.Context) (graph.Batch, error)
}

func (c svCollector) Name() string            { return "connector:ex:c1" }
func (c svCollector) Interval() time.Duration { return time.Hour }
func (c svCollector) Collect(ctx context.Context) (graph.Batch, error) {
	return c.fn(ctx)
}

type svProvider struct {
	collect func(ctx context.Context) (graph.Batch, error)
	perms   func() (PermissionReport, error)
	refresh func() (time.Time, error)

	permCalls    atomic.Int32
	refreshCalls atomic.Int32
	dropped      atomic.Int32
}

func (p *svProvider) Verify(context.Context, Call) (Identity, error) { return Identity{}, nil }
func (p *svProvider) CheckPermissions(context.Context, Call) (PermissionReport, error) {
	p.permCalls.Add(1)
	if p.perms == nil {
		return PermissionReport{}, nil
	}
	return p.perms()
}
func (p *svProvider) Refresh(context.Context, Call) (time.Time, error) {
	p.refreshCalls.Add(1)
	if p.refresh == nil {
		return time.Time{}, nil
	}
	return p.refresh()
}
func (p *svProvider) Collector(store.Connection, broker.ConnectionRef) collectors.Collector {
	return svCollector{fn: p.collect}
}
func (p *svProvider) Describe(store.Connection) Descriptor { return Descriptor{} }
func (p *svProvider) DropSession(string)                   { p.dropped.Add(1) }

type svStatusCall struct {
	to     Status
	reason string
}

type svHost struct {
	st *store.Store
	p  *svProvider
	a  *mgrAudit

	mu    sync.Mutex
	calls []svStatusCall
}

func (h *svHost) Prepare(c store.Connection) (Provider, Call, error) {
	return h.p, Call{Connection: c}, nil
}

func (h *svHost) SetStatus(_ context.Context, id string, to Status, reason string) error {
	h.mu.Lock()
	h.calls = append(h.calls, svStatusCall{to, reason})
	h.mu.Unlock()
	return h.st.UpdateConnection(id, func(c *store.Connection) error {
		c.Status, c.StatusReason = string(to), reason
		return nil
	})
}

func (h *svHost) Record(ctx context.Context, c store.Connection, event, outcome string, d map[string]string) error {
	return h.a.Append(ctx, audit.Entry{ConnectionID: c.ID, Event: event, Outcome: outcome, Detail: d})
}

func (h *svHost) statuses() []svStatusCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]svStatusCall(nil), h.calls...)
}

type svFix struct {
	clk  *svClock
	run  *svRunner
	host *svHost
	sup  *CollectorSupervisor
	conn store.Connection
}

func newSvFix(t *testing.T, p *svProvider, mod func(*store.Connection)) *svFix {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	conn := store.NewConnection("c1", "ex", "prod", st.Snapshot().Settings, svT0)
	conn.Status = string(StatusActive)
	conn.IntervalSec = 3600
	checked := svT0
	conn.LastPermissionCheck, conn.PermissionCheck = &checked, store.PermissionOK
	if mod != nil {
		mod(&conn)
	}
	if err := st.AddConnection(conn); err != nil {
		t.Fatal(err)
	}
	f := &svFix{clk: &svClock{now: svT0}, run: &svRunner{}}
	f.host = &svHost{st: st, p: p, a: &mgrAudit{}}
	f.sup = NewCollectorSupervisor(SupervisorConfig{
		Store: st, Runner: f.run, Host: f.host, Now: f.clk.Now, After: f.clk.After,
	})
	f.conn, _ = st.Connection("c1")
	t.Cleanup(func() { _ = f.sup.Stop(context.Background(), "c1") })
	return f
}

func (f *svFix) stored() store.Connection {
	c, _ := f.host.st.Connection("c1")
	return c
}

func svWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitTimer waits until the earliest pending timer is d away.
func (f *svFix) waitTimer(t *testing.T, d time.Duration) {
	t.Helper()
	svWait(t, "timer "+d.String(), func() bool {
		n, ok := f.clk.next()
		return ok && n == d
	})
}

func (f *svFix) waitRuns(t *testing.T, n int32) {
	t.Helper()
	svWait(t, "runs", func() bool { return f.run.runs.Load() >= n })
}

func svOK(context.Context) (graph.Batch, error) { return graph.Batch{}, nil }

func TestFailureBackoffAndExpiresSoon(t *testing.T) {
	want := []time.Duration{0, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for n, w := range want {
		if got := FailureBackoff(n); got != w {
			t.Fatalf("FailureBackoff(%d) = %v, want %v", n, got, w)
		}
	}
	soon, far := svT0.Add(6*24*time.Hour), svT0.Add(8*24*time.Hour)
	if !ExpiresSoon(store.Connection{CredentialExpiresAt: &soon}, svT0) ||
		ExpiresSoon(store.Connection{CredentialExpiresAt: &far}, svT0) ||
		ExpiresSoon(store.Connection{}, svT0) {
		t.Fatal("expiresSoon boundaries")
	}
}

func TestRunsAtIntervalAndRecordsSync(t *testing.T) {
	f := newSvFix(t, &svProvider{collect: svOK}, nil)
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	f.waitTimer(t, time.Hour)
	f.clk.Advance(time.Hour)
	f.waitRuns(t, 2)
	svWait(t, "last sync", func() bool { l := f.stored().LastSync; return l != nil && l.Status == SyncOK })
}

func TestRunUsesConnectorTimeoutAndReportsPartial(t *testing.T) {
	p := &svProvider{collect: func(context.Context) (graph.Batch, error) {
		return graph.Batch{}, collectors.PartialError{Types: []string{"ec2", "rds"}}
	}}
	f := newSvFix(t, p, nil)
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	svWait(t, "partial sync", func() bool {
		l := f.stored().LastSync
		return l != nil && l.Status == SyncPartial && len(l.Partial) == 2
	})
	if f.stored().Status != string(StatusActive) {
		t.Fatal("partial failure must keep the connection ACTIVE")
	}
	var c collectors.Collector = &observed{Collector: svCollector{}}
	if c.(collectors.Timeouter).Timeout() != collectors.ConnectorTimeout {
		t.Fatal("connector runs must use the 120 s timeout")
	}
}

func TestFailureBackoffGrowsAndResetsOnSuccess(t *testing.T) {
	var n atomic.Int32
	p := &svProvider{collect: func(context.Context) (graph.Batch, error) {
		if n.Add(1) <= 2 {
			return graph.Batch{}, errors.New("boom")
		}
		return graph.Batch{}, nil
	}}
	f := newSvFix(t, p, nil)
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	f.waitTimer(t, time.Minute)
	f.clk.Advance(time.Minute)
	f.waitRuns(t, 2)
	f.waitTimer(t, 2*time.Minute)
	f.clk.Advance(2 * time.Minute)
	f.waitRuns(t, 3)
	f.waitTimer(t, time.Hour) // success: back to the interval
	if f.stored().Status != string(StatusActive) {
		t.Fatal("generic failures keep the connection ACTIVE")
	}
}

func TestAuthFailuresStopWithoutRetry(t *testing.T) {
	for code, want := range map[int]Status{401: StatusExpired, 403: StatusError} {
		p := &svProvider{collect: func(context.Context) (graph.Batch, error) {
			return graph.Batch{}, &HTTPStatusError{Code: code}
		}}
		f := newSvFix(t, p, nil)
		f.sup.Start(f.conn)
		svWait(t, "status change", func() bool { return len(f.host.statuses()) == 1 })
		if got := f.host.statuses()[0].to; got != want {
			t.Fatalf("HTTP %d -> %s, want %s", code, got, want)
		}
		if f.run.runs.Load() != 1 {
			t.Fatalf("HTTP %d must not be retried", code)
		}
	}
}

func TestNetworkErrorsRetryThreeTimesThenStale(t *testing.T) {
	p := &svProvider{collect: func(context.Context) (graph.Batch, error) { return graph.Batch{}, &broker.NetworkError{} }}
	f := newSvFix(t, p, nil)
	f.sup.Start(f.conn)
	for i, d := range DefaultRetryDelays {
		f.waitRuns(t, int32(i+1))
		f.waitTimer(t, d)
		f.clk.Advance(d)
	}
	f.waitRuns(t, 4)
	svWait(t, "stale", func() bool { l := f.stored().LastSync; return l != nil && l.Status == SyncStale })
	f.waitTimer(t, time.Minute)
	if f.stored().Status != string(StatusActive) {
		t.Fatal("network errors keep the connection ACTIVE")
	}
}

func TestSyncNowRejectsConcurrentRun(t *testing.T) {
	release := make(chan struct{})
	var first atomic.Bool
	p := &svProvider{collect: func(ctx context.Context) (graph.Batch, error) {
		if first.CompareAndSwap(false, true) {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return graph.Batch{}, nil
	}}
	f := newSvFix(t, p, nil)
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	svWait(t, "collector ready", func() bool {
		f.sup.mu.Lock()
		defer f.sup.mu.Unlock()
		e := f.sup.entries["c1"]
		return e != nil && e.col.Load() != nil
	})
	if err := f.sup.SyncNow(context.Background(), "c1"); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("want ErrRunInProgress, got %v", err)
	}
	close(release)
	f.waitTimer(t, time.Hour)
	if err := f.sup.SyncNow(context.Background(), "c1"); err != nil {
		t.Fatalf("manual sync: %v", err)
	}
	if f.run.runs.Load() != 2 {
		t.Fatalf("runs = %d", f.run.runs.Load())
	}
	if err := f.sup.SyncNow(context.Background(), "nope"); err == nil {
		t.Fatal("unknown id must fail")
	}
}

func TestStopCancelsRunningCollector(t *testing.T) {
	cancelled := make(chan struct{})
	p := &svProvider{collect: func(ctx context.Context) (graph.Batch, error) {
		<-ctx.Done()
		close(cancelled)
		return graph.Batch{}, ctx.Err()
	}}
	f := newSvFix(t, p, nil)
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.sup.Stop(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("collector context not cancelled")
	}
	if len(f.host.statuses()) != 0 {
		t.Fatal("a stop is not a failure")
	}
	if err := f.sup.Stop(ctx, "unknown"); err != nil {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestPermissionRecheckWriteSuspendsAndSetsError(t *testing.T) {
	p := &svProvider{collect: svOK, perms: func() (PermissionReport, error) {
		return PermissionReport{WriteOffenders: []string{"s3:PutObject"}}, nil
	}}
	f := newSvFix(t, p, nil)
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	f.waitTimer(t, time.Hour)
	f.clk.Advance(PermissionRecheckInterval)
	svWait(t, "error status", func() bool { return len(f.host.statuses()) == 1 })
	if f.host.statuses()[0].to != StatusError || f.stored().PermissionCheck != store.PermissionExcess {
		t.Fatalf("unexpected state %+v / %s", f.host.statuses(), f.stored().PermissionCheck)
	}
	if f.host.a.count(audit.EventPermissionChange) != 1 {
		t.Fatal("write permission must be audited")
	}
}

func TestPermissionRecheckUnreachableRetainsStateAndRetriesInAnHour(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	p := &svProvider{collect: svOK, perms: func() (PermissionReport, error) {
		if fail.Load() {
			return PermissionReport{}, &broker.NetworkError{}
		}
		return PermissionReport{}, nil
	}}
	f := newSvFix(t, p, nil)
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	f.waitTimer(t, time.Hour)
	f.clk.Advance(PermissionRecheckInterval)
	svWait(t, "first check", func() bool { return p.permCalls.Load() == 1 })
	svWait(t, "audit", func() bool { return f.host.a.count(audit.EventTest) == 1 })
	f.waitTimer(t, PermissionRetryInterval)
	if f.stored().Status != string(StatusActive) || len(f.host.statuses()) != 0 {
		t.Fatal("state must be retained")
	}
	fail.Store(false)
	f.clk.Advance(PermissionRetryInterval)
	svWait(t, "retry", func() bool { return p.permCalls.Load() == 2 })
	svWait(t, "check time", func() bool {
		c := f.stored()
		return c.LastPermissionCheck != nil && c.LastPermissionCheck.After(svT0.Add(PermissionRecheckInterval))
	})
}

func TestRefreshBeforeExpiryAndImmediateWhenClose(t *testing.T) {
	newExp := svT0.Add(2 * time.Hour)
	p := &svProvider{collect: svOK, refresh: func() (time.Time, error) { return newExp, nil }}
	f := newSvFix(t, p, func(c *store.Connection) {
		e := svT0.Add(10 * time.Minute)
		c.CredentialExpiresAt = &e
	})
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	f.waitTimer(t, 5*time.Minute) // expiry − 300 s
	if p.refreshCalls.Load() != 0 {
		t.Fatal("refreshed too early")
	}
	f.clk.Advance(5 * time.Minute)
	svWait(t, "refresh", func() bool { return p.refreshCalls.Load() == 1 })
	svWait(t, "new expiry", func() bool {
		e := f.stored().CredentialExpiresAt
		return e != nil && e.Equal(newExp)
	})

	// Less than 300 s remaining: refresh starts at once.
	p2 := &svProvider{collect: svOK}
	f2 := newSvFix(t, p2, func(c *store.Connection) {
		e := svT0.Add(100 * time.Second)
		c.CredentialExpiresAt = &e
	})
	f2.sup.Start(f2.conn)
	svWait(t, "immediate refresh", func() bool { return p2.refreshCalls.Load() == 1 })
}

func TestRefreshFailureRetriesThenExpires(t *testing.T) {
	p := &svProvider{collect: svOK, refresh: func() (time.Time, error) { return time.Time{}, errors.New("sts down") }}
	f := newSvFix(t, p, func(c *store.Connection) {
		e := svT0.Add(100 * time.Second)
		c.CredentialExpiresAt = &e
	})
	f.sup.Start(f.conn)
	for i, d := range DefaultRetryDelays {
		svWait(t, "attempt", func() bool { return p.refreshCalls.Load() == int32(i+1) })
		f.waitTimer(t, d)
		f.clk.Advance(d)
	}
	svWait(t, "expired", func() bool { return len(f.host.statuses()) == 1 })
	if p.refreshCalls.Load() != 4 {
		t.Fatalf("attempts = %d, want 1 + 3 retries", p.refreshCalls.Load())
	}
	if got := f.host.statuses()[0]; got.to != StatusExpired {
		t.Fatalf("status %+v", got)
	}
	if p.dropped.Load() != 1 {
		t.Fatal("in-memory credentials not dropped")
	}
}
