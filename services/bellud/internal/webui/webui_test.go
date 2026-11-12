package webui

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func do(h http.Handler, method, p string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, p, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const script = `window.x=1`

func setup(t *testing.T, index string) http.Handler {
	d := t.TempDir()
	if index != "" {
		write(t, d, "index.html", index)
	}
	write(t, d, "_assets/a.js", "A")
	write(t, d, "_assets/a.js.br", "BR")
	write(t, d, "sw.js", "sw")
	write(t, d, "icons/dev/favicon.ico", "ico")
	h, err := New(Options{Dir: d})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestServing(t *testing.T) {
	sum := sha256.Sum256([]byte(script))
	hash := base64.StdEncoding.EncodeToString(sum[:])
	h := setup(t, `<html><script id="oc-theme-preload-script">`+script+`</script></html>`)

	w := do(h, "GET", "/some/route")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<html>") {
		t.Fatalf("spa fallback: %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "'sha256-"+hash+"'") {
		t.Fatal("csp hash missing")
	}
	if w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("html headers")
	}
	if do(h, "GET", "/sw.js").Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("sw cache")
	}
	// Unhashed files keep their URL across releases, so they must revalidate.
	if do(h, "GET", "/icons/dev/favicon.ico").Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("icon cache")
	}
	w = do(h, "GET", "/_assets/a.js")
	if w.Body.String() != "A" || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" ||
		w.Header().Get("Vary") != "Accept-Encoding" || w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("asset plain: %v", w.Header())
	}
	w = do(h, "GET", "/_assets/a.js", "Accept-Encoding", "gzip, br;q=0.5")
	if w.Body.String() != "BR" || w.Header().Get("Content-Encoding") != "br" {
		t.Fatal("brotli")
	}
	w = do(h, "GET", "/_assets/a.js", "Accept-Encoding", "br;q=0")
	if w.Body.String() != "A" {
		t.Fatal("q=0 must not use brotli")
	}
	w = do(h, "GET", "/index.html", "Accept-Encoding", "br")
	if w.Header().Get("Content-Encoding") != "" || w.Header().Get("Vary") != "" {
		t.Fatal("index never brotli")
	}
	w = do(h, "GET", "/_assets/missing.js")
	if w.Code != 404 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing asset")
	}
	if w = do(h, "GET", "/icons/x.png"); w.Code != 404 {
		t.Fatal("missing icon")
	}
	if w = do(h, "HEAD", "/"); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("head")
	}
	if do(h, "POST", "/").Code != 405 {
		t.Fatal("405")
	}
}

func TestNoThemeScriptOmitsHash(t *testing.T) {
	h := setup(t, `<html></html>`)
	if strings.Contains(do(h, "GET", "/").Header().Get("Content-Security-Policy"), "sha256") {
		t.Fatal("unexpected hash")
	}
}

func TestMissingIndex(t *testing.T) {
	h := setup(t, "")
	if do(h, "GET", "/nope").Code != 404 {
		t.Fatal("want 404")
	}
	if do(h, "GET", "/sw.js").Code != 200 {
		t.Fatal("existing file still served")
	}
}

func TestUnreadableDir(t *testing.T) {
	if _, err := New(Options{Dir: filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("want error")
	}
}

func TestEmbeddedDefaultEmpty(t *testing.T) {
	h, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if do(h, "GET", "/").Code != 404 {
		t.Fatal("want 404")
	}
}
