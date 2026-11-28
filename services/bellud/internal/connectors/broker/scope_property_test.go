package broker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/scope"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Feature: cloud-connectors, Property 19: Scope decision (policy.CheckAgent).
// An agent caller is allowed iff the inputs say in scope AND live reads; nil or
// zero inputs deny; a non-agent caller is never gated.
// **Validates: Requirements 16.5, 17.1, 17.2, 17.3, 17.4**
func TestPropertyCheckAgentDefaultDeny(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		caller := rapid.SampledFrom([]string{"agent:agent", "agent:", "agent:x", policy.CallerCollector, policy.CallerLifecycle}).Draw(t, "caller")
		in := policy.AgentInputs{InScope: rapid.Bool().Draw(t, "scope"), LiveReads: rapid.Bool().Draw(t, "live")}
		useNil := rapid.Bool().Draw(t, "nil")
		var p *policy.AgentInputs
		if !useNil {
			p = &in
		}
		d := policy.CheckAgent(caller, p)
		want := !policy.IsAgentCaller(caller) || (!useNil && in.InScope && in.LiveReads)
		if d.Allow != want {
			t.Fatalf("caller=%s nil=%v in=%+v allow=%v want %v", caller, useNil, in, d.Allow, want)
		}
		if !d.Allow && d.Reason != policy.ReasonScope {
			t.Fatalf("denial reason %q", d.Reason)
		}
	})
}

// Feature: cloud-connectors, Property 19: Scope decision (broker + scope).
// Through the real scope service and broker, an agent call is sent iff the
// connection and operation are in scope, the operation is on the read
// allowlist and live reads are on. Every denial sends zero requests and
// appends one audit entry (before any send) naming principal, connection,
// operation and reason. A rejected scope leaves the previous one in force.
// **Validates: Requirements 16.5, 17.1, 17.2, 17.3, 17.4**
func TestPropertyAgentCallsDefaultDeny(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	if err := reg.Register(ghManifest()); err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0)
	var clock atomic.Pointer[time.Time]
	clock.Store(&start)
	svc := scope.New(st, reg, func() time.Time { return *clock.Load() })
	baseRef := newRef(t, AuthGitHubToken)
	conns := []string{"c1", "c2"}
	for _, id := range conns {
		if err := st.AddConnection(store.NewConnection(id, "github", id, store.Settings{}, start)); err != nil {
			t.Fatal(err)
		}
	}
	const opRepo, opBig, opAuth = "GET /repos/{o}/{r}", "GET /big", "sts:GetCallerIdentity"
	ops := []string{opRepo, opBig, opAuth, "DELETE /x"}
	subset := func(t *rapid.T, name string, from []string) []string {
		return rapid.SliceOfNDistinct(rapid.SampledFrom(from), 0, len(from), rapid.ID[string]).Draw(t, name)
	}
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}

	rapid.Check(t, func(t *rapid.T) {
		// Optionally start from the default (empty) scope.
		if rapid.Bool().Draw(t, "reset") {
			if err := svc.Put(scope.Principal, store.Scope{}); err != nil {
				t.Fatal(err)
			}
		}
		next := store.Scope{Principal: scope.Principal, Connections: subset(t, "connections", conns),
			Operations: map[string][]string{"github": subset(t, "ops", ops)}}
		if rapid.Bool().Draw(t, "connector") {
			next.Connectors = []string{"github"}
		}
		live := map[string]bool{}
		for _, id := range conns {
			live[id] = rapid.Bool().Draw(t, "live-"+id)
			on := live[id]
			if err := st.UpdateConnection(id, func(c *store.Connection) error { c.AllowAgentLiveReads = on; return nil }); err != nil {
				t.Fatal(err)
			}
		}
		prev := svc.Get(scope.Principal)
		err := svc.Put(scope.Principal, next)
		bad := has(next.Operations["github"], opAuth) || has(next.Operations["github"], "DELETE /x")
		var ve *scope.ValidationError
		switch {
		case bad && !errors.As(err, &ve):
			t.Fatalf("scope with non-allowlisted op accepted: %v", err)
		case !bad && err != nil:
			t.Fatalf("valid scope rejected: %v", err)
		case bad:
			if !has([]string{opAuth, "DELETE /x"}, ve.Operation) {
				t.Fatalf("error names %q", ve.Operation)
			}
			if got := svc.Get(scope.Principal); len(got.Connections) != len(prev.Connections) ||
				len(got.Operations["github"]) != len(prev.Operations["github"]) || len(got.Connectors) != len(prev.Connectors) {
				t.Fatalf("previous scope changed: %+v -> %+v", prev, got)
			}
		}
		eff := svc.Get(scope.Principal)
		later := clock.Load().Add(scope.MaxAge)
		clock.Store(&later)

		conn := rapid.SampledFrom(conns).Draw(t, "conn")
		op := rapid.SampledFrom(ops).Draw(t, "op")
		want := has(eff.Connectors, "github") && has(eff.Connections, conn) &&
			has(eff.Operations["github"], op) && (op == opRepo || op == opBig) && live[conn]

		rt := &countingRT{fn: respond(200, `{}`)}
		a := &denyAudit{rt: rt}
		b := New(Config{Opener: fakeOpener{secret: token}, Audit: a, Redactor: redactor.New(), Inner: rt,
			RatePerSecond: 10000, AgentGate: svc})
		ref := baseRef
		ref.ID = conn
		_, err = b.Do(context.Background(), Call{Connection: ref, Caller: policy.CallerAgentPrefix + scope.Principal,
			Operation: op, Params: map[string]any{"o": "a", "r": "b"}})

		if want {
			if err != nil || rt.n.Load() != 1 || len(a.es) != 0 {
				t.Fatalf("expected one send: err=%v n=%d audit=%d scope=%+v", err, rt.n.Load(), len(a.es), eff)
			}
			return
		}
		var be *BlockedError
		if !errors.As(err, &be) {
			t.Fatalf("want BlockedError, got %v (scope=%+v conn=%s op=%s live=%v)", err, eff, conn, op, live)
		}
		if rt.n.Load() != 0 {
			t.Fatalf("denied agent call sent %d requests", rt.n.Load())
		}
		if len(a.es) != 1 || a.sentAt[0] != 0 {
			t.Fatalf("audit entries: %+v", a.es)
		}
		e := a.es[0]
		if e.Outcome != audit.OutcomeBlocked || e.ConnectionID != conn || e.Detail["operation"] != op ||
			e.Detail["caller"] != policy.CallerAgentPrefix+scope.Principal || e.Detail["reason"] == "" {
			t.Fatalf("audit entry: %+v", e)
		}
	})
}
