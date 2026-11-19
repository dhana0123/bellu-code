package debugui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

const base = "/api/experimental/graph"

func setup(t *testing.T) (*Handler, *engine.Core) {
	t.Helper()
	c, err := engine.Open(t.TempDir(), engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	b := batch.Batch{Collector: "test", Entities: []batch.Entity{
		{Type: "host", Identity: map[string]string{"hostname": "a"}, Attributes: map[string]any{"os": "<script>alert(1)</script>"}},
		{Type: "host", Identity: map[string]string{"hostname": "b"}},
	}}
	if _, err := c.Apply(context.Background(), b, engine.ModeFull); err != nil {
		t.Fatal(err)
	}
	return New(c, base), c
}

func get(h http.Handler, method, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
	return w
}

func TestHeadersAndMethods(t *testing.T) {
	h, _ := setup(t)
	w := get(h, http.MethodGet, base+"/debug")
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	} {
		if w.Header().Get(k) != v {
			t.Errorf("%s = %q", k, w.Header().Get(k))
		}
	}
	if w := get(h, http.MethodPost, base+"/debug"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST code %d", w.Code)
	}
	if w := get(h, http.MethodGet, base+"/debug/style.css"); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Errorf("css %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w := get(h, http.MethodGet, base+"/nope"); w.Code != 404 {
		t.Errorf("404 expected, got %d", w.Code)
	}
}

func TestEntityPageEscapes(t *testing.T) {
	h, c := setup(t)
	f, err := c.Find(context.Background(), engine.FindQuery{Kind: "host"}, nil)
	if err != nil || len(f.Items) == 0 {
		t.Fatalf("find: %v %d", err, len(f.Items))
	}
	var id string
	for _, e := range f.Items {
		if e.Attributes["hostname"] == "a" {
			id = e.ID
		}
	}
	w := get(h, http.MethodGet, base+"/debug?ref="+url.QueryEscape(id))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("code %d body %s", w.Code, body)
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "http://") && strings.Contains(body, "src=") {
		t.Fatal("unescaped content")
	}
	if !strings.Contains(body, "<h3>History</h3>") || !strings.Contains(body, "added") {
		t.Fatal("history missing")
	}
}

func TestRefEchoEscaped(t *testing.T) {
	h, _ := setup(t)
	w := get(h, http.MethodGet, base+"/debug?ref="+url.QueryEscape(`"><script>x</script>`))
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("ref echoed unescaped")
	}
}

func TestFindAndErrors(t *testing.T) {
	h, _ := setup(t)
	w := get(h, http.MethodGet, base+"/debug?kind=host&q=")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Find results (2)") || !strings.Contains(w.Body.String(), "debug?ref=%40") {
		t.Fatalf("find: %d %s", w.Code, w.Body.String())
	}
	if w := get(h, http.MethodGet, base+"/debug?kind=host&q=bad"); w.Code != 400 {
		t.Errorf("bad q %d", w.Code)
	}
	if w := get(h, http.MethodGet, base+"/debug?ref=@zzzzzz"); w.Code != 404 {
		t.Errorf("unknown ref %d", w.Code)
	}
	if w := get(h, http.MethodGet, base+"/debug?ref=x&depth=4"); w.Code != 400 {
		t.Errorf("depth %d", w.Code)
	}
	if w := get(h, http.MethodGet, base+"/debug?ref=x&as_of=yesterday"); w.Code != 400 {
		t.Errorf("as_of %d", w.Code)
	}
}

func TestNeighborAttributesShownAndEscaped(t *testing.T) {
	h, c := setup(t)
	id := func(n string) string {
		f, err := c.Find(context.Background(), engine.FindQuery{Kind: "host", Attributes: map[string]string{"hostname": n}}, nil)
		if err != nil || len(f.Items) != 1 {
			t.Fatalf("find %s: %v %d", n, err, len(f.Items))
		}
		return f.Items[0].ID
	}
	a, b := id("a"), id("b")
	cc, _ := ident.Hash("host", map[string]string{"hostname": "c"})
	if _, err := c.Apply(context.Background(), batch.Batch{Collector: "test", Entities: []batch.Entity{
		{Type: "host", Identity: map[string]string{"hostname": "a"}, Attributes: map[string]any{"os": "<script>alert(1)</script>"}},
		{Type: "host", Identity: map[string]string{"hostname": "b"}},
		{Type: "host", Identity: map[string]string{"hostname": "c"}},
	}, Relations: []batch.Relation{
		{Type: "depends_on", From: a, To: b, Attributes: map[string]any{
			"evidence": "<img src=x onerror=1>", "confidence": "inferred", "observed_at": "2025-01-01T00:00:00Z"}},
		{Type: "depends_on", From: a, To: cc},
	}}, engine.ModeFull); err != nil {
		t.Fatal(err)
	}
	body := get(h, http.MethodGet, base+"/debug?ref="+url.QueryEscape(a)).Body.String()
	if !strings.Contains(body, "<td>&lt;img src=x onerror=1&gt;</td><td>inferred</td><td>2025-01-01T00:00:00Z</td>") {
		t.Fatalf("attribute cells missing or unescaped:\n%s", body)
	}
	if strings.Contains(body, "<img") {
		t.Fatal("evidence rendered unescaped")
	}
	if !strings.Contains(body, "<td></td><td></td><td></td></tr>") {
		t.Fatal("relation without attributes should render empty cells")
	}
}
