package scope

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

const (
	opRepo = "GET /repos/{o}/{r}"
	opBig  = "GET /big"
	opAuth = "sts:GetCallerIdentity"
)

func testManifest() manifest.Manifest {
	return manifest.Manifest{
		ID: "github", Version: "1.0.0", Name: "GitHub",
		AuthMethods: []manifest.AuthMethod{{ID: "pat", Name: "PAT", Enabled: true}},
		Entities:    []string{"github_repo"},
		Egress:      []string{"api.github.com", "sts.{region}.amazonaws.com"},
		Operations: []manifest.Operation{
			{Name: opRepo, Class: manifest.ClassRead, Method: "GET", Host: "api.github.com", Path: "/repos/{o}/{r}"},
			{Name: opBig, Class: manifest.ClassRead, Method: "GET", Host: "api.github.com", Path: "/big"},
			{Name: opAuth, Class: manifest.ClassAuth, Host: "sts.{region}.amazonaws.com"},
		},
	}
}

type env struct {
	svc *Service
	st  *store.Store
	now atomic.Pointer[time.Time]
}

func (e *env) advance(d time.Duration) { t := e.now.Load().Add(d); e.now.Store(&t) }

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	if err := reg.Register(testManifest()); err != nil {
		t.Fatal(err)
	}
	e := &env{st: st}
	start := time.Unix(1_700_000_000, 0)
	e.now.Store(&start)
	e.svc = New(st, reg, func() time.Time { return *e.now.Load() })
	for _, id := range []string{"c1", "c2"} {
		if err := st.AddConnection(store.NewConnection(id, "github", id, store.Settings{}, start)); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) setLive(t interface {
	Helper()
	Fatal(...any)
}, id string, on bool) {
	t.Helper()
	err := e.st.UpdateConnection(id, func(c *store.Connection) error { c.AllowAgentLiveReads = on; return nil })
	if err != nil {
		t.Fatal(err)
	}
}

func fullScope() store.Scope {
	return store.Scope{Principal: Principal, Connectors: []string{"github"}, Connections: []string{"c1"},
		Operations: map[string][]string{"github": {opRepo}}}
}

func TestDefaultScopeDeniesEverything(t *testing.T) {
	e := newEnv(t)
	e.setLive(t, "c1", true)
	in := e.svc.AgentInputs(Principal, "c1", "github", opRepo)
	if in.InScope || in.LiveReads {
		t.Fatalf("empty scope allowed: %+v", in)
	}
	if in := e.svc.AgentInputs("other", "c1", "github", opRepo); in.InScope || in.LiveReads {
		t.Fatalf("unknown principal allowed: %+v", in)
	}
}

func TestPutRejectsOperationOutsideAllowlistAndKeepsPrevious(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Put(Principal, fullScope()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{opAuth, "DELETE /repos/{o}/{r}", ""} {
		next := fullScope()
		next.Operations["github"] = []string{opBig, bad}
		err := e.svc.Put(Principal, next)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Operation != bad {
			t.Fatalf("op %q: err=%v", bad, err)
		}
		got := e.svc.Get(Principal)
		if len(got.Operations["github"]) != 1 || got.Operations["github"][0] != opRepo {
			t.Fatalf("previous scope lost: %+v", got)
		}
	}
	if err := e.svc.Put(Principal, store.Scope{Connections: []string{"nope"}}); err == nil {
		t.Fatal("unknown connection accepted")
	}
	if err := e.svc.Put("other", fullScope()); err == nil {
		t.Fatal("unknown principal accepted")
	}
}

func TestDecisionIsScopeAndLiveReadsAndAllowlist(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Put(Principal, fullScope()); err != nil {
		t.Fatal(err)
	}
	// In scope but live reads default to off.
	in := e.svc.AgentInputs(Principal, "c1", "github", opRepo)
	if !in.InScope || in.LiveReads {
		t.Fatalf("live reads must default off: %+v", in)
	}
	e.setLive(t, "c1", true)
	e.advance(MaxAge)
	if in := e.svc.AgentInputs(Principal, "c1", "github", opRepo); !in.InScope || !in.LiveReads {
		t.Fatalf("want allow: %+v", in)
	}
	for name, got := range map[string]struct{ conn, connector, op string }{
		"other connection": {"c2", "github", opRepo},
		"other operation":  {"c1", "github", opBig},
		"auth operation":   {"c1", "github", opAuth},
		"wrong connector":  {"c1", "other", opRepo},
		"unknown conn":     {"zz", "github", opRepo},
	} {
		if in := e.svc.AgentInputs(Principal, got.conn, got.connector, got.op); in.InScope || in.LiveReads {
			t.Fatalf("%s allowed: %+v", name, in)
		}
	}
}

func TestChangesApplyWithinFiveSeconds(t *testing.T) {
	e := newEnv(t)
	e.setLive(t, "c1", true)
	if err := e.svc.Put(Principal, fullScope()); err != nil {
		t.Fatal(err)
	}
	if in := e.svc.AgentInputs(Principal, "c1", "github", opRepo); !in.LiveReads {
		t.Fatal("expected allow")
	}
	// The live-read flag changes through the store, not through Put.
	e.setLive(t, "c1", false)
	e.advance(MaxAge)
	if in := e.svc.AgentInputs(Principal, "c1", "github", opRepo); in.LiveReads {
		t.Fatalf("live-read disable not seen within %v", MaxAge)
	}
	if MaxAge >= 5*time.Second {
		t.Fatal("MaxAge must be below 5 s")
	}
	// A scope change through Put is visible immediately.
	e.setLive(t, "c1", true)
	e.advance(MaxAge)
	if err := e.svc.Put(Principal, store.Scope{}); err != nil {
		t.Fatal(err)
	}
	if in := e.svc.AgentInputs(Principal, "c1", "github", opRepo); in.InScope {
		t.Fatalf("cleared scope still allows: %+v", in)
	}
	// A removed connection is denied after the next rebuild.
	if err := e.svc.Put(Principal, fullScope()); err != nil {
		t.Fatal(err)
	}
	err := e.st.UpdateConnection("c1", func(c *store.Connection) error { c.Removed = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	e.advance(MaxAge)
	if in := e.svc.AgentInputs(Principal, "c1", "github", opRepo); in.InScope {
		t.Fatalf("removed connection allowed: %+v", in)
	}
}

// Feature: cloud-connectors, Property 19: Scope decision.
// **Validates: Requirements 16.5, 17.2, 17.3, 17.4**
func TestPropertyScopeDecision(t *testing.T) {
	e := newEnv(t)
	ops := []string{opRepo, opBig, opAuth, "x"}
	conns := []string{"c1", "c2"}
	subset := func(t *rapid.T, name string, from []string) []string {
		return rapid.SliceOfNDistinct(rapid.SampledFrom(from), 0, len(from), rapid.ID[string]).Draw(t, name)
	}
	rapid.Check(t, func(t *rapid.T) {
		sc := store.Scope{Principal: Principal, Connections: subset(t, "connections", conns),
			Operations: map[string][]string{}}
		if rapid.Bool().Draw(t, "connectorInScope") {
			sc.Connectors = []string{"github"}
		}
		sc.Operations["github"] = subset(t, "ops", ops)
		live := map[string]bool{"c1": rapid.Bool().Draw(t, "live1"), "c2": rapid.Bool().Draw(t, "live2")}
		for id, on := range live {
			e.setLive(t, id, on)
		}
		hasBad := false
		for _, op := range sc.Operations["github"] {
			hasBad = hasBad || op == opAuth || op == "x"
		}
		err := e.svc.Put(Principal, sc)
		if hasBad != (err != nil) {
			t.Fatalf("put err=%v hasBad=%v", err, hasBad)
		}
		if hasBad {
			sc = e.svc.Get(Principal) // the previous scope must still decide
		}
		inSet := func(list []string, v string) bool {
			for _, x := range list {
				if x == v {
					return true
				}
			}
			return false
		}
		e.advance(MaxAge)
		conn := rapid.SampledFrom(append(conns, "zz")).Draw(t, "conn")
		op := rapid.SampledFrom(ops).Draw(t, "op")
		want := inSet(sc.Connectors, "github") && inSet(sc.Connections, conn) &&
			inSet(sc.Operations["github"], op) && (op == opRepo || op == opBig)
		got := e.svc.AgentInputs(Principal, conn, "github", op)
		if got.InScope != want {
			t.Fatalf("InScope=%v want %v (%+v conn=%s op=%s)", got.InScope, want, sc, conn, op)
		}
		if got.LiveReads != (want && live[conn]) {
			t.Fatalf("LiveReads=%v want %v", got.LiveReads, want && live[conn])
		}
		if !got.InScope && got.Why == "" {
			t.Fatal("denial without reason")
		}
	})
}
