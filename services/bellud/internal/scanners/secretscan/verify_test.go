package secretscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type memAudit struct{ rows []VerifyAudit }

func (m *memAudit) RecordVerify(_ context.Context, a VerifyAudit) error {
	m.rows = append(m.rows, a)
	return nil
}

func newVerifier(srv *httptest.Server, on bool, a *memAudit) *Verifier {
	return &Verifier{
		WorkspaceID: "ws1",
		Enabled:     func(p string) bool { return on && p == "github" },
		HTTP:        srv.Client(),
		Audit:       a,
		Endpoints: map[string]Endpoint{"github": {URL: srv.URL, Header: func(s []byte) (string, string) {
			return "Authorization", "Bearer " + string(s)
		}}},
		Timeout: 100 * time.Millisecond,
	}
}

func TestVerifyResultsAndAudit(t *testing.T) {
	const secret = "ghp_supersecretvalue"
	var hits atomic.Int32
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	for _, c := range []struct {
		status int
		want   string
	}{{200, VerifyLive}, {401, VerifyNotLive}, {500, VerifyUnverified}} {
		status = c.status
		a := &memAudit{}
		buf := []byte(secret)
		got, err := newVerifier(srv, true, a).Verify(context.Background(), "github", "fp1", buf)
		if err != nil || got != c.want {
			t.Fatalf("status %d: got %q %v want %q", c.status, got, err, c.want)
		}
		if strings.Trim(string(buf), "\x00") != "" {
			t.Fatal("secret buffer not zeroed")
		}
		if len(a.rows) != 1 || a.rows[0].Result != c.want || a.rows[0].Fingerprint != "fp1" ||
			a.rows[0].Provider != "github" || a.rows[0].At.IsZero() {
			t.Fatalf("bad audit rows %+v", a.rows)
		}
		if strings.Contains(strings.ToLower(strings.Join([]string{a.rows[0].Provider, a.rows[0].Fingerprint, a.rows[0].Result, a.rows[0].WorkspaceID}, "|")), "supersecret") {
			t.Fatal("audit row holds the secret")
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("want exactly one request per credential, got %d", hits.Load())
	}
}

func TestVerifyDefaultOffMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	a := &memAudit{}
	for _, v := range []*Verifier{newVerifier(srv, false, a), {HTTP: srv.Client(), Audit: a}} {
		got, err := v.Verify(context.Background(), "github", "fp", []byte("x"))
		if got != "" || err != nil {
			t.Fatalf("got %q %v", got, err)
		}
	}
	if hits.Load() != 0 || len(a.rows) != 0 {
		t.Fatalf("hits=%d rows=%d", hits.Load(), len(a.rows))
	}
}

func TestVerifyTimeoutIsUnverifiedWithoutRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-r.Context().Done()
	}))
	defer srv.Close()
	a := &memAudit{}
	got, err := newVerifier(srv, true, a).Verify(context.Background(), "github", "fp", []byte("s"))
	if err != nil || got != VerifyUnverified {
		t.Fatalf("got %q %v", got, err)
	}
	if hits.Load() != 1 || len(a.rows) != 1 || a.rows[0].Result != VerifyUnverified {
		t.Fatalf("hits=%d rows=%+v", hits.Load(), a.rows)
	}
}
