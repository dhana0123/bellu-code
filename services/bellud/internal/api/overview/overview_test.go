package overview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
	ov "github.com/bellu/bellucode/services/bellud/internal/overview"
	"github.com/bellu/bellucode/services/bellud/internal/server"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

const password = "pw"

type env struct {
	svc   *ov.Service
	eng   facade.Engine
	front http.Handler
}

func newEnv(t *testing.T, start, enabled bool) *env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	eng, err := facade.Open(ctx, facade.Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "g")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); eng.Close(context.Background()) })
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := findings.New(db)
	t.Cleanup(fs.Close)
	reg, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	svc := ov.New(eng, reg, fs, db.DB(), "ws1")
	if start {
		if err := svc.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	table, err := routes.NewTable([]routes.Route{{Method: "GET", Pattern: CategoriesPath, Group: "overview", Owner: routes.OwnerGo}})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, eng: eng, front: &server.Server{Table: table, Auth: auth.New(password), Go: New(svc, enabled)}}
}

func (e *env) get(authed bool, inm string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", CategoriesPath, nil)
	if authed {
		r.SetBasicAuth(auth.Username, password)
	}
	if inm != "" {
		r.Header.Set("If-None-Match", inm)
	}
	w := httptest.NewRecorder()
	e.front.ServeHTTP(w, r)
	return w
}

func TestCategoriesReturnsNineWithETag(t *testing.T) {
	e := newEnv(t, true, true)
	w := e.get(true, "")
	if w.Code != 200 || w.Header().Get("ETag") == "" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	var body wireSummaries
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Categories) != 9 || body.Revision == 0 || w.Header().Get("ETag") != ETag(body.Revision) {
		t.Fatalf("%d cards rev %d etag %s", len(body.Categories), body.Revision, w.Header().Get("ETag"))
	}
	c := body.Categories[0]
	if c.Category != "cloud_infrastructure" || len(c.Severity) != 5 || c.TopIssues == nil || c.EmptyState == nil || c.EmptyState.SetupLink != "/security/connectors" {
		t.Fatalf("%+v", c)
	}
	var raw map[string][]map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	for _, k := range []string{"category", "entityCount", "topIssues", "emptyState", "kinds"} {
		if _, ok := raw["categories"][0][k]; !ok {
			t.Errorf("missing field %s", k)
		}
	}
}

func TestIfNoneMatchGives304ThenNewETagAfterChange(t *testing.T) {
	e := newEnv(t, true, true)
	first := e.get(true, "")
	tag := first.Header().Get("ETag")

	for _, inm := range []string{tag, `"x", ` + tag, "*", tag[2:]} {
		w := e.get(true, inm)
		if w.Code != 304 || w.Body.Len() != 0 || w.Header().Get("ETag") != tag {
			t.Fatalf("%q: %d %q %v", inm, w.Code, w.Body, w.Header())
		}
	}
	if w := e.get(true, `W/"rev-999"`); w.Code != 200 {
		t.Fatalf("stale tag: %d", w.Code)
	}

	b := batch.Batch{Collector: "aws", ObservedAt: time.Now().UTC(), Entities: []batch.Entity{{Type: "aws_resource",
		Identity:   map[string]string{"connection": "c1", "arn": "arn1"},
		Attributes: map[string]any{"resource_type": "ec2:instance"}}}}
	if _, err := e.eng.Ingest().Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	e.svc.Refresh()
	deadline := time.Now().Add(5 * time.Second)
	for {
		w := e.get(true, tag)
		if w.Code == 200 {
			if w.Header().Get("ETag") == tag {
				t.Fatal("ETag unchanged after change")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no new ETag after change")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNotStartedIs503WithRetryHint(t *testing.T) {
	e := newEnv(t, false, true)
	w := e.get(true, "")
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 503 || w.Header().Get("Retry-After") == "" || body["_tag"] != "ServiceUnavailableError" || w.Header().Get("ETag") != "" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestDisabledFlagAnswersNotFound(t *testing.T) {
	e := newEnv(t, true, false)
	if w := e.get(true, ""); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
	mux := http.NewServeMux()
	Mount(mux, nil, true) // no service behaves like disabled
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", CategoriesPath, nil))
	if w.Code != 404 {
		t.Fatalf("nil service: %d", w.Code)
	}
}

func TestUnauthenticatedRejectedBeforeHandler(t *testing.T) {
	e := newEnv(t, true, true)
	if w := e.get(false, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("%d", w.Code)
	}
}
