package connectors

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

type memSource struct {
	mu    sync.Mutex
	slots map[string][]byte
}

func (m *memSource) Name() string                   { return "mem" }
func (m *memSource) Available(context.Context) bool { return true }
func (m *memSource) Load(ctx context.Context) ([]byte, error) {
	return m.LoadSlot(ctx, keysource.SlotCurrent)
}
func (m *memSource) LoadSlot(_ context.Context, slot string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.slots[slot]
	if !ok {
		return nil, keysource.ErrNoKey
	}
	return append([]byte(nil), k...), nil
}
func (m *memSource) Store(_ context.Context, key []byte, slot string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots[slot] = append([]byte(nil), key...)
	return nil
}
func (m *memSource) Promote(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots[keysource.SlotCurrent] = m.slots[keysource.SlotNext]
	delete(m.slots, keysource.SlotNext)
	return nil
}

// ghTransport answers the GitHub verification calls and everything else with an empty list.
type ghTransport struct{}

func (ghTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `[]`
	if r.URL.Path == "/user" {
		body = `{"login":"octo"}`
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
}

func testEngine(t *testing.T) graph.Engine {
	t.Helper()
	ctx := context.Background()
	e, err := graph.Open(ctx, graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(ctx) })
	return e
}

func newSvc(t *testing.T, dir string, src keysource.Source, eng graph.Engine, rt http.RoundTripper) *Service {
	t.Helper()
	s, err := New(context.Background(), Options{
		Dir: dir, Engine: eng, Order: []keysource.Source{src}, Transport: rt,
		Getenv: func(k string) string {
			if k == "BELLUCODE_FLAGS" {
				return "connectors"
			}
			return ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDisabledConstructsNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c")
	s, err := New(context.Background(), Options{Dir: dir, Getenv: func(string) string { return "-connectors" }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled() || s.Status().Enabled || len(s.Catalog()) != 0 {
		t.Fatal("service must be disabled")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("data directory created: %v", err)
	}
	if _, err := s.Create(context.Background(), CreateInput{}); err != ErrDisabled {
		t.Fatalf("err=%v", err)
	}
	if s.Start(context.Background()) != nil || s.Close(context.Background()) != nil {
		t.Fatal("start/close must be no-ops")
	}
}

func TestGitHubLifecycleAndRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := &memSource{slots: map[string][]byte{}}
	eng := testEngine(t)
	s := newSvc(t, dir, src, eng, ghTransport{})
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); !st.Enabled || !st.Persistent || st.KeySource != "mem" {
		t.Fatalf("status %+v", st)
	}
	if len(s.Catalog()) != 8 {
		t.Fatalf("catalog %d", len(s.Catalog()))
	}
	if acs, err := s.AuthConfigs("github"); err != nil || len(acs) == 0 {
		t.Fatalf("auth configs %v %v", acs, err)
	}

	token := "github_pat_" + strings.Repeat("a", 30)
	conn, err := s.Create(ctx, CreateInput{
		ConnectorID: "github", Alias: "main", Method: "pat",
		Params: map[string]string{"repos": "octo/hello"}, Credential: map[string]string{"token": token},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn.Status != "ACTIVE" || conn.AccountLabel != "octo" {
		t.Fatalf("conn %+v", conn)
	}
	if _, err := s.Test(ctx, conn.ID); err != nil {
		t.Fatal(err)
	}
	pg, err := s.ListAudit(conn.ID, "", 500)
	if err != nil || len(pg.Entries) == 0 || len(pg.Entries) > DefaultPageSize {
		t.Fatalf("audit %v %d", err, len(pg.Entries))
	}
	assertNoSecret(t, dir, token)
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// Restart: the persisted ACTIVE connection is picked up and its credential
	// is still usable.
	s2 := newSvc(t, dir, src, eng, ghTransport{})
	if err := s2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Connection(conn.ID)
	if !ok || got.Status != "ACTIVE" {
		t.Fatalf("after restart: %+v %v", got, ok)
	}
	if _, err := s2.Test(ctx, conn.ID); err != nil {
		t.Fatal(err)
	}
	if err := s2.Disconnect(ctx, conn.ID); err != nil {
		t.Fatal(err)
	}
	if len(s2.Connections()) != 0 {
		t.Fatal("connection still listed")
	}
	if err := s2.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCreateValidation(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t, t.TempDir(), &memSource{slots: map[string][]byte{}}, testEngine(t), ghTransport{})
	defer s.Close(ctx)
	cases := map[string]CreateInput{
		"unknown connector": {ConnectorID: "nope", Alias: "a", Method: "pat"},
		"bad host":          {ConnectorID: "github", Alias: "a", Method: "pat", Params: map[string]string{"host": "10.0.0.1"}, Credential: map[string]string{"token": "github_pat_x"}},
		"missing token":     {ConnectorID: "github", Alias: "a", Method: "pat"},
		"bad role":          {ConnectorID: "aws", Alias: "a", Method: "assume_role", Params: map[string]string{"roleArn": "x"}},
		"bad source":        {ConnectorID: "aws", Alias: "a", Method: "assume_role", Params: map[string]string{"roleArn": "arn:aws:iam::123456789012:role/r", "source": "env"}},
		"missing keys":      {ConnectorID: "aws", Alias: "a", Method: "static_keys"},
	}
	for name, in := range cases {
		_, err := s.Create(ctx, in)
		var le *lifecycle.Error
		if !asErr(err, &le) || le.Code != lifecycle.CodeValidationFailed {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	if len(s.Connections()) != 0 {
		t.Fatal("validation failures must leave no connection")
	}
}

func TestAWSFailedVerificationKeepsExternalID(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := newSvc(t, dir, &memSource{slots: map[string][]byte{}}, testEngine(t), failTransport{})
	defer s.Close(ctx)
	ext := "BELLU-" + strings.Repeat("ABCDEFGH", 6)
	conn, err := s.Create(ctx, CreateInput{
		ConnectorID: "aws", Alias: "prod", Method: "assume_role",
		Params: map[string]string{"roleArn": "arn:aws:iam::123456789012:role/bellu", "externalId": ext, "regions": "eu-west-1"},
	})
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if conn.ID == "" || conn.ExternalIDRef != "vault:"+conn.ID+"/external-id" {
		t.Fatalf("conn %+v", conn)
	}
	stored, ok := s.Connection(conn.ID)
	if !ok || stored.Status == "ACTIVE" {
		t.Fatalf("stored %+v", stored)
	}
	p, err := s.paramsOf(ctx, stored)
	if err != nil || p.ExternalID != ext || p.Source != "ambient" || p.RoleARN == "" {
		t.Fatalf("params %+v %v", p, err)
	}
	if !s.Redactor().Contains(ext) {
		t.Error("external id not registered with the redactor")
	}
	assertNoSecret(t, dir, ext)
	if err := s.Disconnect(ctx, conn.ID); err != nil {
		t.Fatal(err)
	}
	if s.Redactor().Contains(ext) {
		t.Error("external id still registered after disconnect")
	}
}

func asErr(err error, target **lifecycle.Error) bool {
	for err != nil {
		if e, ok := err.(*lifecycle.Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// assertNoSecret fails if secret appears in any file under dir.
func assertNoSecret(t *testing.T, dir, secret string) {
	t.Helper()
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(secret)) {
			t.Errorf("secret found in %s", p)
		}
		return nil
	})
}

func TestStartupReconcileExpiresCredentialLess(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := &memSource{slots: map[string][]byte{}}
	eng := testEngine(t)
	s := newSvc(t, dir, src, eng, ghTransport{})
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	mk := func(alias string) string {
		c, err := s.Create(ctx, CreateInput{
			ConnectorID: "github", Alias: alias, Method: "pat",
			Params:     map[string]string{"repos": "octo/hello"},
			Credential: map[string]string{"token": "github_pat_" + strings.Repeat("a", 30)},
		})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	lost, paused := mk("lost"), mk("paused")
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate vault loss for two connections; one of them is PAUSED.
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateConnection(paused, func(c *store.Connection) error { c.Status = "PAUSED"; return nil }); err != nil {
		t.Fatal(err)
	}
	// Losing vault.json empties every slot.
	if err := os.Remove(filepath.Join(dir, "vault", "vault.json")); err != nil {
		t.Fatal(err)
	}

	s2 := newSvc(t, dir, src, eng, ghTransport{})
	if err := s2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s2.Close(ctx)
	for id, want := range map[string]string{lost: "EXPIRED", paused: "EXPIRED"} {
		if got, _ := s2.Connection(id); got.Status != want {
			t.Fatalf("%s: status %s want %s", id, got.Status, want)
		}
	}
}

func TestStatusConnectionCollection(t *testing.T) {
	s := newSvc(t, t.TempDir(), &memSource{slots: map[string][]byte{}}, testEngine(t), failTransport{})
	gap := store.Gap{ResourceType: "compute.googleapis.com/Firewall", Scope: "p1", Reason: "missing_permission"}
	for id, cid := range map[string]string{"c1": "gitlab", "c2": "gcp"} {
		if err := s.store.AddConnection(store.Connection{ID: id, Alias: id, IntervalSec: 900, RotationIntervalDays: 90, ConnectorID: cid, Status: "ACTIVE", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.UpdateConnection("c2", func(c *store.Connection) error {
		c.LastSync = &store.LastSync{Gaps: []store.Gap{gap}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := map[string]ConnectionStatus{}
	for _, c := range s.Status().Connections {
		got[c.ID] = c
	}
	if got["c1"].Collection != CollectionNotAvailable || len(got["c1"].Gaps) != 0 {
		t.Fatalf("gitlab: %+v", got["c1"])
	}
	if got["c2"].Collection != CollectionAvailable || len(got["c2"].Gaps) != 1 || got["c2"].Gaps[0] != gap {
		t.Fatalf("gcp: %+v", got["c2"])
	}
}
