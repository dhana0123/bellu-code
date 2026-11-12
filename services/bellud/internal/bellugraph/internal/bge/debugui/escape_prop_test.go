package debugui

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// allowedTags are the elements the embedded templates emit; any other
// element in a rendered page came from a value.
var allowedTags = map[string]bool{
	"a": true, "body": true, "br": true, "button": true, "code": true, "form": true, "h1": true, "h2": true,
	"h3": true, "head": true, "html": true, "input": true, "label": true, "link": true, "meta": true, "p": true,
	"table": true, "td": true, "th": true, "title": true, "tr": true,
}

var markup = regexp.MustCompile(`<[a-zA-Z]`)

// assertEscaped fails when the page holds an element the templates do not
// emit, an event-handler attribute, or a value containing markup verbatim.
func assertEscaped(t *rapid.T, body string, values []string) {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			tok := z.Token()
			if !allowedTags[tok.Data] {
				t.Fatalf("unexpected element <%s> in page", tok.Data)
			}
			for _, a := range tok.Attr {
				if strings.HasPrefix(a.Key, "on") {
					t.Fatalf("event handler attribute %q", a.Key)
				}
			}
		}
	}
	if strings.Contains(body, "<script") {
		t.Fatal("page contains <script")
	}
	for _, v := range values {
		if markup.MatchString(v) && strings.Contains(body, v) {
			t.Fatalf("value %q appears unescaped", v)
		}
	}
}

// Feature: bellu-graph-native, Property 29: Debug UI escapes every value
// **Validates: Requirements 17.1, 17.5**
func TestPropDebugUIEscapesEveryValue(t *testing.T) {
	c, err := engine.Open(t.TempDir(), engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	h := New(c, base)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		host := gen.HTML().Draw(rt, "hostname")
		attr := gen.HTML().Draw(rt, "attr")
		note := gen.HTML().Draw(rt, "annotation")
		ref := gen.HTML().Draw(rt, "ref")
		_, err := c.Apply(ctx, batch.Batch{Collector: "t", Entities: []batch.Entity{
			{Type: "host", Identity: map[string]string{"hostname": host}, Attributes: map[string]any{"os": attr}},
		}}, engine.ModeFull)
		if err != nil {
			rt.Skip("batch rejected: ", err)
		}
		f, err := c.Find(ctx, engine.FindQuery{Kind: "host"}, nil)
		if err != nil {
			rt.Fatal(err)
		}
		var id string
		for _, e := range f.Items {
			if e.Attributes["hostname"] == host {
				id = e.ID
			}
		}
		if id == "" {
			rt.Fatal("entity not found")
		}
		if _, err := c.Annotate(ctx, id, map[string]string{"note": note}, nil, "t"); err != nil {
			rt.Skip("annotation rejected: ", err)
		}
		values := []string{host, attr, note, ref}
		for _, target := range []string{
			base + "/debug?ref=" + url.QueryEscape(id),
			base + "/debug?kind=host&q=",
			base + "/debug?ref=" + url.QueryEscape(ref),
		} {
			w := get(h, http.MethodGet, target)
			assertEscaped(rt, w.Body.String(), values)
		}
	})
}
