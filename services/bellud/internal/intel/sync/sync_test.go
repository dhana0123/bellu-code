package sync

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
)

func makeBundle(t *testing.T, priv ed25519.PrivateKey, tamper bool) []byte {
	t.Helper()
	data := []byte(`{"ID":"CVE-2024-0001"}` + "\n" + `{"ID":"CVE-2024-0002"}` + "\n")
	sum := sha256.Sum256(data)
	manifest, _ := json.Marshal(map[string]any{
		"version":    1,
		"created_at": "2024-05-01T00:00:00Z",
		"files":      []map[string]any{{"name": "intel.jsonl", "size": len(data), "sha256": hex.EncodeToString(sum[:])}},
	})
	if tamper {
		data = append(data[:len(data)-2], 'x', '\n')
	}
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range []struct {
		n string
		b []byte
	}{{"intel.jsonl", data}, {"manifest.json", manifest}, {"manifest.json.sig", ed25519.Sign(priv, manifest)}} {
		if err := tw.WriteHeader(&tar.Header{Name: m.n, Mode: 0o644, Size: int64(len(m.b))}); err != nil {
			t.Fatal(err)
		}
		tw.Write(m.b)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

type fixture struct {
	st      *store.Store
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	bundle  []byte
	pointer func(b []byte) []byte
	srv     *httptest.Server
	mu      gosync.Mutex
	reqs    []*http.Request
	ptrHits atomic.Int32
	ptrCode int
	dlBody  func(b []byte) []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{st: st, pub: pub, priv: priv, bundle: makeBundle(t, priv, false)}
	f.dlBody = func(b []byte) []byte { return b }
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r)
		f.mu.Unlock()
		if r.URL.Path == "/latest.json" {
			f.ptrHits.Add(1)
			if f.ptrCode != 0 {
				w.WriteHeader(f.ptrCode)
				return
			}
			if r.Header.Get("If-None-Match") == `"e1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			sum := sha256.Sum256(f.bundle)
			w.Header().Set("ETag", `"e1"`)
			json.NewEncoder(w).Encode(map[string]any{
				"schema": 1, "version": "v1", "created_at": "2024-05-01T00:00:00Z",
				"bundle_url": "b/v1.tar.zst", "bundle_sha256": hex.EncodeToString(sum[:]), "bundle_size": len(f.bundle),
			})
			return
		}
		w.Write(f.dlBody(f.bundle))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) syncer(onImported func()) *Syncer {
	return New(Config{URL: f.srv.URL + "/latest.json", Key: f.pub, Version: "9.9"}, f.st, onImported)
}

func TestGoodBundleImportsAndRequestsAreMinimal(t *testing.T) {
	f := newFixture(t)
	var called int
	s := f.syncer(func() { called++ })
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("onImported called %d times", called)
	}
	st := s.Status()
	if st.State != StateOK || st.Version != "v1" || st.Records != 2 {
		t.Fatalf("status %+v", st)
	}
	// Second run: 304, no import, no callback.
	if err := s.RunOnce(context.Background()); err != nil || called != 1 {
		t.Fatalf("second run err=%v called=%d", err, called)
	}
	for _, r := range f.reqs {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.Cookies()) != 0 {
			t.Fatalf("bad request %v", r)
		}
		for k := range r.Header {
			switch k {
			case "User-Agent", "Accept", "If-None-Match", "Accept-Encoding":
			default:
				t.Fatalf("unexpected header %s", k)
			}
		}
		if r.Header.Get("User-Agent") != "bellud/9.9" {
			t.Fatalf("ua %q", r.Header.Get("User-Agent"))
		}
	}
	last := f.reqs[len(f.reqs)-1]
	if last.Header.Get("If-None-Match") != `"e1"` {
		t.Fatal("missing conditional header")
	}
}

func TestFailuresKeepCorpusAndRecordKind(t *testing.T) {
	cases := []struct {
		name string
		mut  func(f *fixture)
		want string
	}{
		{"pointer 500", func(f *fixture) { f.ptrCode = 500 }, ErrPointerUnreachable},
		{"truncated", func(f *fixture) { f.dlBody = func(b []byte) []byte { return b[:len(b)/2] } }, ErrDownloadFailed},
		{"bad sha", func(f *fixture) {
			f.dlBody = func(b []byte) []byte { c := append([]byte(nil), b...); c[3] ^= 1; return c }
		}, ErrDownloadCorrupt},
		{"tampered", func(f *fixture) {
			f.bundle = makeBundle(t, f.priv, true)
		}, ErrVerificationFailed},
		{"wrong key", func(f *fixture) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			f.pub = pub
		}, ErrVerificationFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c.mut(f)
			s := f.syncer(func() { t.Fatal("onImported must not run") })
			err := s.RunOnce(context.Background())
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Fatalf("err = %v, want prefix %s", err, c.want)
			}
			m, _ := f.st.Meta()
			if m.Active() || !strings.HasPrefix(m.LastError, c.want) {
				t.Fatalf("meta %+v", m)
			}
			if s.Status().State != StateError {
				t.Fatalf("state %s", s.Status().State)
			}
		})
	}
}

func TestFailureKeepsPreviousCorpus(t *testing.T) {
	f := newFixture(t)
	s := f.syncer(nil)
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.ptrCode = 503
	if err := s.RunOnce(context.Background()); err == nil {
		t.Fatal("want error")
	}
	m, _ := f.st.Meta()
	if !m.Active() || m.Version != "v1" || m.Records != 2 || m.LastError == "" {
		t.Fatalf("meta %+v", m)
	}
}

func TestInvalidPointerNoDownload(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"schema":2}`))
	}))
	defer srv.Close()
	s := New(Config{URL: srv.URL, Key: f.pub}, f.st, nil)
	err := s.RunOnce(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), ErrPointerInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestLocalBundleNeverDials(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "b.tar.zst")
	if err := os.WriteFile(path, f.bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	client := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no network")
	}}}
	var called int
	s := New(Config{URL: f.srv.URL + "/latest.json", LocalBundle: path, Key: f.pub, HTTPClient: client}, f.st, func() { called++ })
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.RunOnce(context.Background()); err != nil { // unchanged file: skipped
		t.Fatal(err)
	}
	if dials.Load() != 0 || f.ptrHits.Load() != 0 {
		t.Fatalf("network used: dials=%d hits=%d", dials.Load(), f.ptrHits.Load())
	}
	if called != 1 || s.Status().Records != 2 {
		t.Fatalf("called=%d status=%+v", called, s.Status())
	}
}

func TestStatusNotConfiguredAndDisabled(t *testing.T) {
	f := newFixture(t)
	if st := New(Config{Key: f.pub}, f.st, nil).Status(); st.State != StateNotConfigured {
		t.Fatalf("state %s", st.State)
	}
	s := New(Config{URL: f.srv.URL + "/latest.json"}, f.st, nil)
	if st := s.Status(); st.State != StateDisabled || !strings.Contains(st.LastError, "no pinned key") {
		t.Fatalf("status %+v", st)
	}
}

func TestRunFirstDelayThenImport(t *testing.T) {
	f := newFixture(t)
	done := make(chan struct{})
	var once gosync.Once
	s := New(Config{URL: f.srv.URL + "/latest.json", Key: f.pub, FirstDelay: 10 * time.Millisecond}, f.st, func() { once.Do(func() { close(done) }) })
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no import")
	}
	cancel()
}
