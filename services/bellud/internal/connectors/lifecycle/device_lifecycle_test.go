package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

func (f *mgrFix) createMethod(t *testing.T, alias, secret, method string) (store.Connection, error) {
	t.Helper()
	return f.m.Create(context.Background(), CreateInput{
		ConnectorID: "ex", Alias: alias, Method: method,
		Credential: CredentialInput{Secret: []byte(secret)},
	})
}

func TestDeviceVerificationFailureDropsToken(t *testing.T) {
	for _, tc := range []struct {
		method   string
		wantKept bool
	}{{"device", false}, {"token", true}} {
		f := newMgrFix(t)
		f.p.verify = func(string) (Identity, error) { return Identity{}, NewError(CodeInvalidCredential, "bad", nil) }
		c, err := f.createMethod(t, "a", "secret-token-0001", tc.method)
		if codeOf(t, err) != CodeInvalidCredential || c.Status != string(StatusError) {
			t.Fatalf("%s: status=%s err=%v", tc.method, c.Status, err)
		}
		if _, ok := f.v.get(credRef(c.ID)); ok != tc.wantKept {
			t.Fatalf("%s: credential kept = %v, want %v", tc.method, ok, tc.wantKept)
		}
	}
}

func TestReconnectVerifiedReplacesTokenAndKeepsIdentity(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "keep", "secret-token-old3")
	if _, err := f.m.transition(context.Background(), c.ID, StatusExpired, "401", false); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(48 * time.Hour).UTC()
	if err := f.m.ReconnectVerified(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-new4"), ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.Connection(c.ID)
	if got.ID != c.ID || got.Alias != "keep" || got.ConnectorID != "ex" || got.Method != MethodDevice ||
		got.Status != string(StatusActive) || got.CredentialExpiresAt == nil || !got.CredentialExpiresAt.Equal(exp) {
		t.Fatalf("connection %+v", got)
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-new4" {
		t.Fatal("credential not replaced")
	}
	if _, ok := f.v.get(candRef(c.ID)); ok {
		t.Fatal("candidate left behind")
	}
}

func TestReconnectVerifiedFailureChangesNothing(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "keep", "secret-token-old3")
	if _, err := f.m.transition(context.Background(), c.ID, StatusExpired, "401", false); err != nil {
		t.Fatal(err)
	}
	before, _ := f.st.Connection(c.ID)
	f.p.verify = func(string) (Identity, error) { return Identity{}, NewError(CodeInvalidCredential, "bad", nil) }
	err := f.m.ReconnectVerified(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-bad2")})
	if codeOf(t, err) != CodeInvalidCredential {
		t.Fatalf("err = %v", err)
	}
	after, _ := f.st.Connection(c.ID)
	if after.Status != string(StatusExpired) || after.Method != before.Method || after.Alias != before.Alias {
		t.Fatalf("connection changed: %+v", after)
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-old3" {
		t.Fatal("stored credential changed")
	}
	if _, ok := f.v.get(candRef(c.ID)); ok {
		t.Fatal("candidate left behind")
	}
}

func TestReconnectVerifiedRejectsActiveConnection(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-0001")
	err := f.m.ReconnectVerified(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-new4")})
	if codeOf(t, err) != CodeTransitionRejected {
		t.Fatalf("err = %v", err)
	}
}

// svNonRefreshable is a provider whose credentials cannot be renewed.
type svNonRefreshable struct{ *svProvider }

func (svNonRefreshable) Refreshable(store.Connection) bool { return false }

func TestNonRefreshableExpiresWithoutRefreshWithin60s(t *testing.T) {
	p := &svProvider{collect: func(context.Context) (graph.Batch, error) { return graph.Batch{}, nil }}
	exp := svT0.Add(90 * time.Second)
	f := newSvFix(t, p, func(c *store.Connection) { c.CredentialExpiresAt = &exp })
	f.host.over = svNonRefreshable{p}
	f.sup.Start(f.conn)
	f.waitRuns(t, 1)
	f.waitTimer(t, ExpiryCheckInterval) // never sleeps longer than 60 s
	f.clk.Advance(ExpiryCheckInterval)
	f.waitTimer(t, 30*time.Second) // woken for the expiry itself
	f.clk.Advance(30 * time.Second)
	svWait(t, "EXPIRED", func() bool { return len(f.host.statuses()) == 1 })
	if got := f.host.statuses()[0].to; got != StatusExpired {
		t.Fatalf("status = %s", got)
	}
	if p.refreshCalls.Load() != 0 {
		t.Fatal("Refresh must not be called")
	}
	if f.run.runs.Load() != 1 {
		t.Fatal("no collection after expiry")
	}
}
