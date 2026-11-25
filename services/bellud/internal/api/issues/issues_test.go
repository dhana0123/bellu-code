package issues

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/issues"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func setup(t *testing.T) (*issues.Store, *findings.Store) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := findings.New(db)
	t.Cleanup(fs.Close)
	st := issues.New(db)
	mk := func(id string, score float64) issues.Issue {
		return issues.Issue{ID: id, Title: "t " + id, RuleID: "r", Severity: findings.SevHigh, RiskScore: score, Category: "code_and_dependencies",
			FindingIDs: []string{"f1"}, IncludesInferred: id == "i2",
			Path: []issues.Hop{{EntityID: "a", Relation: "reaches", Evidence: []string{"e1"}, Inferred: id == "i2"}, {EntityID: "b"}}}
	}
	for _, i := range []issues.Issue{mk("i1", 50), mk("i2", 80), mk("i3", 50)} {
		if err := st.Upsert(context.Background(), i); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Millisecond)
	}
	return st, fs
}

func do(h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, target, strings.NewReader(body)))
	return w
}

func TestListOrderAndPaging(t *testing.T) {
	st, fs := setup(t)
	h := New(st, fs, true)
	var p struct {
		Items      []wireIssue `json:"items"`
		NextCursor string      `json:"nextCursor"`
	}
	w := do(h, "GET", Prefix+"?limit=2", "")
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(p.Items) != 2 || p.Items[0].ID != "i2" || p.Items[1].ID != "i3" || p.NextCursor == "" {
		t.Fatalf("page1 %+v", p)
	}
	next := p.NextCursor
	p.NextCursor = ""
	w = do(h, "GET", Prefix+"?limit=2&cursor="+next, "")
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || len(p.Items) != 1 || p.Items[0].ID != "i1" || p.NextCursor != "" {
		t.Fatalf("page2 %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", Prefix+"?status=bogus", ""); w.Code != 400 || !strings.Contains(w.Body.String(), `"field":"status"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestGetWithPathAndSetStatus(t *testing.T) {
	st, fs := setup(t)
	h := New(st, fs, true)
	var d wireDetail
	w := do(h, "GET", Prefix+"/i2", "")
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(d.Path) != 2 || d.Path[0].EntityID != "a" || !d.Path[0].Inferred || d.Path[0].Evidence[0] != "e1" || !d.IncludesInferred || len(d.Findings) != 1 || d.Findings[0].ID != "f1" {
		t.Fatalf("%+v", d)
	}
	w = do(h, "POST", Prefix+"/i2/status", `{"status":"resolved"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"resolved"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(h, "POST", Prefix+"/i2/status", `{"status":"nope"}`); w.Code != 400 {
		t.Fatalf("%d", w.Code)
	}
	if w := do(h, "POST", Prefix+"/zz/status", `{"status":"open"}`); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}

func TestFlagOffIs404(t *testing.T) {
	st, fs := setup(t)
	h := New(st, fs, false)
	for _, c := range [][2]string{{"GET", Prefix}, {"GET", Prefix + "/i1"}, {"POST", Prefix + "/i1/status"}} {
		if w := do(h, c[0], c[1], `{}`); w.Code != 404 {
			t.Errorf("%v: %d", c, w.Code)
		}
	}
}
