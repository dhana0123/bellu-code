package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

type mgrVault struct {
	mu        sync.Mutex
	data      map[vault.Ref]string
	putErr    error
	deleteErr error
}

func (v *mgrVault) Put(_ context.Context, ref vault.Ref, _ string, secret []byte, _ time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.putErr != nil {
		return v.putErr
	}
	v.data[ref] = string(secret)
	clear(secret)
	return nil
}

func (v *mgrVault) Delete(_ context.Context, ref vault.Ref) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleteErr != nil {
		return v.deleteErr
	}
	delete(v.data, ref)
	return nil
}

func (v *mgrVault) Use(_ context.Context, ref vault.Ref, fn func(secret []byte) error) error {
	v.mu.Lock()
	s, ok := v.data[ref]
	v.mu.Unlock()
	if !ok {
		return vault.ErrNotFound
	}
	b := []byte(s)
	defer clear(b)
	return fn(b)
}
func (v *mgrVault) get(ref vault.Ref) (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.data[ref]
	return s, ok
}

type mgrAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    bool
}

func (a *mgrAudit) Append(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("disk full")
	}
	a.entries = append(a.entries, e)
	return nil
}
func (a *mgrAudit) List(string, string, int) (audit.Page, error) { return audit.Page{}, nil }
func (a *mgrAudit) Prune(time.Time, int) error                   { return nil }

func (a *mgrAudit) count(event string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Event == event {
			n++
		}
	}
	return n
}

// mgrProvider decides by the secret held in the vault slot it is asked about.
type mgrProvider struct {
	v        *mgrVault
	verify   func(secret string) (Identity, error)
	perms    func(secret string) (PermissionReport, error)
	verified int
}

func (p *mgrProvider) secret(c Call) string { s, _ := p.v.get(c.Ref.Credential); return s }
func (p *mgrProvider) Verify(_ context.Context, c Call) (Identity, error) {
	p.verified++
	return p.verify(p.secret(c))
}
func (p *mgrProvider) CheckPermissions(_ context.Context, c Call) (PermissionReport, error) {
	return p.perms(p.secret(c))
}
func (p *mgrProvider) Refresh(context.Context, Call) (time.Time, error) { return time.Time{}, nil }
func (p *mgrProvider) Collector(store.Connection, broker.ConnectionRef) collectors.Collector {
	return nil
}
func (p *mgrProvider) Describe(store.Connection) Descriptor {
	return Descriptor{Auth: broker.AuthGitHubToken, APIHost: "api.example.com"}
}

type mgrSup struct {
	mu      sync.Mutex
	started []string
	stopped []string
	syncErr error
}

func (s *mgrSup) Start(c store.Connection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = append(s.started, c.ID)
}
func (s *mgrSup) Stop(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = append(s.stopped, id)
	return nil
}
func (s *mgrSup) SyncNow(context.Context, string) error { return s.syncErr }

type mgrEngine struct {
	graph.Engine
	ing *mgrIngest
}

func (e mgrEngine) Ingest() graph.Ingest { return e.ing }

type mgrIngest struct {
	applied []string
	err     error
}

func (i *mgrIngest) Apply(_ context.Context, b graph.Batch) (graph.Receipt, error) {
	if i.err != nil {
		return graph.Receipt{}, i.err
	}
	if len(b.Entities) == 0 {
		i.applied = append(i.applied, b.Collector)
	}
	return graph.Receipt{}, nil
}

type mgrClients struct{}

func (mgrClients) HTTPClient(broker.ConnectionRef, string) *http.Client { return &http.Client{} }

type mgrForget struct{ names []string }

func (f *mgrForget) Forget(n string) { f.names = append(f.names, n) }

type mgrFix struct {
	m      *Manager
	st     *store.Store
	v      *mgrVault
	a      *mgrAudit
	p      *mgrProvider
	sup    *mgrSup
	ing    *mgrIngest
	forget *mgrForget
}

func newMgrFix(t *testing.T) *mgrFix {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	if err := reg.Register(manifest.Manifest{
		ID: "ex", Version: "1.0.0", Name: "ex", Icon: "ex",
		AuthMethods: []manifest.AuthMethod{{ID: "token", Name: "Token", Enabled: true}},
		Permissions: []manifest.Permission{{Name: "read", ReadOnly: true}},
		Operations:  []manifest.Operation{{Name: "GET /x", Class: manifest.ClassRead, Method: "GET", Host: "api.example.com", Path: "/x"}},
		Egress:      []string{"api.example.com"},
		Entities:    []string{"thing"},
	}); err != nil {
		t.Fatal(err)
	}
	f := &mgrFix{st: st, v: &mgrVault{data: map[vault.Ref]string{}}, a: &mgrAudit{}, sup: &mgrSup{}, ing: &mgrIngest{}, forget: &mgrForget{}}
	f.p = &mgrProvider{
		v:      f.v,
		verify: func(string) (Identity, error) { return Identity{AccountLabel: "acct-1"}, nil },
		perms:  func(string) (PermissionReport, error) { return PermissionReport{}, nil },
	}
	n := 0
	f.m = NewManager(Config{
		Store: st, Vault: f.v, Audit: f.a, Registry: reg, Clients: mgrClients{},
		Engine: mgrEngine{ing: f.ing}, Runner: f.forget, Supervisor: f.sup,
		NewID: func() string { n++; return "c" + string(rune('0'+n)) },
	})
	f.m.RegisterProvider("ex", f.p)
	return f
}

func (f *mgrFix) create(t *testing.T, alias, secret string) store.Connection {
	t.Helper()
	c, err := f.m.Create(context.Background(), CreateInput{
		ConnectorID: "ex", Alias: alias, Method: "token",
		Credential: CredentialInput{Secret: []byte(secret)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return c
}

func codeOf(t *testing.T, err error) Code {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %T %v", err, err)
	}
	return e.Code
}

func TestCreateActive(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "prod", "secret-token-0001")
	if c.Status != string(StatusActive) || c.AccountLabel != "acct-1" || c.PermissionCheck != store.PermissionOK {
		t.Fatalf("unexpected connection %+v", c)
	}
	if s, ok := f.v.get(credRef(c.ID)); !ok || s != "secret-token-0001" {
		t.Fatal("credential not stored")
	}
	if len(f.sup.started) != 1 {
		t.Fatalf("collector starts: %v", f.sup.started)
	}
	// INITIATED, VERIFYING and ACTIVE are each audited.
	if n := f.a.count(audit.EventStatusChange); n != 2 {
		t.Fatalf("status_change entries = %d", n)
	}
	if f.a.count(audit.EventConnect) != 1 {
		t.Fatal("missing connect entry")
	}
}

func TestCreateExcessPermissionNamesOffendersAndDropsCredential(t *testing.T) {
	f := newMgrFix(t)
	f.p.perms = func(string) (PermissionReport, error) {
		return PermissionReport{WriteOffenders: []string{"s3:PutObject", "iam:CreateUser"}}, nil
	}
	c, err := f.m.Create(context.Background(), CreateInput{
		ConnectorID: "ex", Alias: "a", Credential: CredentialInput{Secret: []byte("secret-token-0002")},
	})
	var te *Error
	if !errors.As(err, &te) || te.Code != CodeExcessPermission {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(te.Offenders, ",") != "s3:PutObject,iam:CreateUser" {
		t.Fatalf("offenders = %v", te.Offenders)
	}
	if c.Status != string(StatusError) || c.PermissionCheck != store.PermissionExcess {
		t.Fatalf("connection %+v", c)
	}
	if _, ok := f.v.get(credRef(c.ID)); ok {
		t.Fatal("credential must be deleted")
	}
	if len(f.sup.started) != 0 {
		t.Fatal("collector must not start")
	}
}

func TestCreateVerifyFailureIsOneTypedError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want Code
	}{
		"typed":    {NewError(CodeInvalidCredential, "bad", nil), CodeInvalidCredential},
		"network":  {&broker.NetworkError{}, CodeNetwork},
		"rate":     {&broker.RateLimitedError{}, CodeRateLimited},
		"deadline": {context.DeadlineExceeded, CodeNetwork},
		"expired":  {NewError(CodeExpired, "expired", nil), CodeExpired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newMgrFix(t)
			f.p.verify = func(string) (Identity, error) { return Identity{}, tc.err }
			c, err := f.m.Create(context.Background(), CreateInput{
				ConnectorID: "ex", Alias: "a", Credential: CredentialInput{Secret: []byte("secret-token-0003")},
			})
			if got := codeOf(t, err); got != tc.want {
				t.Fatalf("code = %s", got)
			}
			if c.Status != string(StatusError) {
				t.Fatalf("status = %s", c.Status)
			}
			if _, ok := f.v.get(credRef(c.ID)); !ok {
				t.Fatal("credential must be kept for reconnect")
			}
		})
	}
}

func TestCreateAuditFailureLeavesNothing(t *testing.T) {
	f := newMgrFix(t)
	f.a.fail = true
	_, err := f.m.Create(context.Background(), CreateInput{
		ConnectorID: "ex", Alias: "a", Credential: CredentialInput{Secret: []byte("secret-token-0004")},
	})
	if codeOf(t, err) != CodeAuditFailed {
		t.Fatalf("err = %v", err)
	}
	if len(f.st.Snapshot().Connections) != 0 || len(f.v.data) != 0 {
		t.Fatal("connection or credential left behind")
	}
}

func TestCreateVaultFailureTombstones(t *testing.T) {
	f := newMgrFix(t)
	f.v.putErr = errors.New("io")
	_, err := f.m.Create(context.Background(), CreateInput{
		ConnectorID: "ex", Alias: "a", Credential: CredentialInput{Secret: []byte("secret-token-0005")},
	})
	if codeOf(t, err) != CodeNetwork && codeOf(t, err) != CodeVaultUnavailable {
		t.Fatalf("err = %v", err)
	}
	for _, c := range f.st.Snapshot().Connections {
		if !c.Removed {
			t.Fatal("connection must not stay live")
		}
	}
	f.v.putErr = nil
	f.create(t, "a", "secret-token-0005") // alias is free again
}

func TestCreateAliasErrors(t *testing.T) {
	f := newMgrFix(t)
	f.create(t, "prod", "secret-token-0006")
	in := func(alias string) CreateInput {
		return CreateInput{ConnectorID: "ex", Alias: alias, Credential: CredentialInput{Secret: []byte("secret-token-0007")}}
	}
	if _, err := f.m.Create(context.Background(), in("prod")); codeOf(t, err) != CodeAliasTaken {
		t.Fatalf("dup: %v", err)
	}
	if _, err := f.m.Create(context.Background(), in("")); codeOf(t, err) != CodeAliasInvalid {
		t.Fatalf("empty: %v", err)
	}
}

func TestProviderErrorIsRedacted(t *testing.T) {
	f := newMgrFix(t)
	secret := "secret-token-0008"
	f.p.verify = func(string) (Identity, error) {
		return Identity{}, NewError(CodeInvalidCredential, "rejected "+secret, nil)
	}
	_, err := f.m.Create(context.Background(), CreateInput{
		ConnectorID: "ex", Alias: "a", Credential: CredentialInput{Secret: []byte(secret)},
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("leaked: %v", err)
	}
	for _, c := range f.st.Snapshot().Connections {
		if strings.Contains(c.StatusReason, secret) {
			t.Fatal("status reason leaked")
		}
	}
}

func TestTestLeavesStateAndCredentialUnchanged(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-0009")
	before, _ := f.st.Connection(c.ID)
	f.p.perms = func(string) (PermissionReport, error) {
		return PermissionReport{WriteOffenders: []string{"x:Write"}}, nil
	}
	if _, err := f.m.Test(context.Background(), c.ID); codeOf(t, err) != CodeExcessPermission {
		t.Fatalf("err = %v", err)
	}
	f.p.verify = func(string) (Identity, error) { return Identity{}, &broker.NetworkError{} }
	if _, err := f.m.Test(context.Background(), c.ID); codeOf(t, err) != CodeNetwork {
		t.Fatalf("err = %v", err)
	}
	after, _ := f.st.Connection(c.ID)
	if after.Status != before.Status || after.StatusReason != before.StatusReason {
		t.Fatal("state changed")
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-0009" {
		t.Fatal("credential changed")
	}
	f.p.verify = func(string) (Identity, error) { return Identity{AccountLabel: "z"}, nil }
	f.p.perms = func(string) (PermissionReport, error) { return PermissionReport{}, nil }
	r, err := f.m.Test(context.Background(), c.ID)
	if err != nil || r.AccountLabel != "z" {
		t.Fatalf("report %+v %v", r, err)
	}
}

func TestRotateVerifiesCandidateBeforeSwap(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-old1")
	f.p.verify = func(s string) (Identity, error) {
		if s == "secret-token-bad1" {
			return Identity{}, NewError(CodeInvalidCredential, "no", nil)
		}
		return Identity{AccountLabel: "acct-1"}, nil
	}
	err := f.m.Rotate(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-bad1")})
	if codeOf(t, err) != CodeInvalidCredential {
		t.Fatalf("err = %v", err)
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-old1" {
		t.Fatal("stored credential changed on failed rotate")
	}
	if _, ok := f.v.get(candRef(c.ID)); ok {
		t.Fatal("candidate left behind")
	}
	// Excess permission in the candidate is rejected too.
	f.p.perms = func(s string) (PermissionReport, error) {
		if s == "secret-token-new1" {
			return PermissionReport{WriteOffenders: []string{"w"}}, nil
		}
		return PermissionReport{}, nil
	}
	if err := f.m.Rotate(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-new1")}); codeOf(t, err) != CodeExcessPermission {
		t.Fatalf("err = %v", err)
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-old1" {
		t.Fatal("stored credential changed")
	}
	f.p.perms = func(string) (PermissionReport, error) { return PermissionReport{}, nil }
	if err := f.m.Rotate(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-new2")}); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-new2" {
		t.Fatal("credential not swapped")
	}
	if got, _ := f.st.Connection(c.ID); got.Status != string(StatusActive) {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestRotateAuditFailureKeepsCredential(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-old2")
	f.a.fail = true
	err := f.m.Rotate(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-new3")})
	if codeOf(t, err) != CodeAuditFailed {
		t.Fatalf("err = %v", err)
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-old2" {
		t.Fatal("credential changed")
	}
	if _, ok := f.v.get(candRef(c.ID)); ok {
		t.Fatal("candidate left behind")
	}
}

func TestReconnectKeepsIdentityOfConnection(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "keep", "secret-token-old3")
	f.p.verify = func(s string) (Identity, error) {
		if s == "secret-token-bad2" {
			return Identity{}, NewError(CodeExpired, "expired", nil)
		}
		return Identity{AccountLabel: "acct-1"}, nil
	}
	if _, err := f.m.transition(context.Background(), c.ID, StatusExpired, "401", false); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Reconnect(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-bad2")}); codeOf(t, err) != CodeExpired {
		t.Fatalf("err = %v", err)
	}
	if got, _ := f.st.Connection(c.ID); got.Status != string(StatusError) {
		t.Fatalf("status = %s", got.Status)
	}
	if err := f.m.Reconnect(context.Background(), c.ID, CredentialInput{Secret: []byte("secret-token-new4")}); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.Connection(c.ID)
	if got.ID != c.ID || got.Alias != "keep" || got.ConnectorID != "ex" || got.Status != string(StatusActive) {
		t.Fatalf("connection %+v", got)
	}
	if s, _ := f.v.get(credRef(c.ID)); s != "secret-token-new4" {
		t.Fatal("credential not replaced")
	}
	if len(f.sup.started) != 2 {
		t.Fatalf("collector restarts: %v", f.sup.started)
	}
}

func TestPauseResumeAndRejectedTransition(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-0010")
	ctx := context.Background()
	if err := f.m.Pause(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.sup.stopped) != 1 {
		t.Fatal("collector not stopped on pause")
	}
	if err := f.m.Pause(ctx, c.ID); codeOf(t, err) != CodeTransitionRejected {
		t.Fatalf("err = %v", err)
	}
	if f.a.count(audit.EventRejectedTransition) != 1 {
		t.Fatal("rejection not audited")
	}
	if err := f.m.Resume(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.st.Connection(c.ID); got.Status != string(StatusActive) || len(f.sup.started) != 2 {
		t.Fatalf("status %s starts %d", got.Status, len(f.sup.started))
	}
}

func TestSyncNow(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-0011")
	if err := f.m.SyncNow(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	f.sup.syncErr = ErrRunInProgress
	if err := f.m.SyncNow(context.Background(), c.ID); codeOf(t, err) != CodeRunInProgress {
		t.Fatalf("err = %v", err)
	}
	_ = f.m.Pause(context.Background(), c.ID)
	if err := f.m.SyncNow(context.Background(), c.ID); codeOf(t, err) != CodeTransitionRejected {
		t.Fatalf("err = %v", err)
	}
}

func TestUpdate(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-0012")
	f.create(t, "b", "secret-token-0013")
	ctx := context.Background()
	alias, iv, live := "renamed", 600, true
	if err := f.m.Update(ctx, c.ID, ConnectionPatch{Alias: &alias, IntervalSec: &iv, AllowAgentLiveReads: &live}); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.Connection(c.ID)
	if got.Alias != "renamed" || got.IntervalSec != 600 || !got.AllowAgentLiveReads {
		t.Fatalf("%+v", got)
	}
	taken := "b"
	if err := f.m.Update(ctx, c.ID, ConnectionPatch{Alias: &taken}); codeOf(t, err) != CodeAliasTaken {
		t.Fatalf("err = %v", err)
	}
	bad := 30
	if err := f.m.Update(ctx, c.ID, ConnectionPatch{IntervalSec: &bad}); codeOf(t, err) != CodeValidationFailed {
		t.Fatalf("err = %v", err)
	}
	if again, _ := f.st.Connection(c.ID); again.IntervalSec != 600 || again.Alias != "renamed" {
		t.Fatal("rejected update changed values")
	}
}

func TestDisconnect(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-0014")
	if err := f.m.Disconnect(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.Connection(c.ID)
	if !got.Removed {
		t.Fatal("not removed")
	}
	if _, ok := f.v.get(credRef(c.ID)); ok {
		t.Fatal("credential not deleted")
	}
	name := CollectorName("ex", c.ID)
	if len(f.ing.applied) != 1 || f.ing.applied[0] != name {
		t.Fatalf("empty observation: %v", f.ing.applied)
	}
	if len(f.forget.names) != 1 || f.forget.names[0] != name {
		t.Fatalf("forget: %v", f.forget.names)
	}
	if len(f.sup.stopped) == 0 {
		t.Fatal("collector not stopped")
	}
}

func TestDisconnectVaultFailureKeepsStateAndStopsCollectors(t *testing.T) {
	f := newMgrFix(t)
	c := f.create(t, "a", "secret-token-0015")
	f.v.deleteErr = errors.New("io")
	if err := f.m.Disconnect(context.Background(), c.ID); err == nil {
		t.Fatal("expected error")
	}
	got, _ := f.st.Connection(c.ID)
	if got.Removed || got.Status != string(StatusActive) {
		t.Fatalf("state changed: %+v", got)
	}
	if len(f.sup.stopped) == 0 || len(f.ing.applied) != 0 || len(f.forget.names) != 0 {
		t.Fatal("collectors must stay stopped and graph untouched")
	}
}
