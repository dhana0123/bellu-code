package findings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/server"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

const password = "pw"

type env struct {
	store *findings.Store
	db    *sqlite.Store
	front http.Handler // front door with auth, as served in production
	now   time.Time
}

func newEnv(t *testing.T, enabled bool) *env {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{db: db, now: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)}
	e.store = findings.New(db, findings.WithClock(func() time.Time { return e.now }))
	t.Cleanup(e.store.Close)
	table, err := routes.NewTable([]routes.Route{
		{Method: "GET", Pattern: Prefix, Group: "findings", Owner: routes.OwnerGo},
		{Method: "GET", Pattern: Prefix + "/{id}", Group: "findings", Owner: routes.OwnerGo},
		{Method: "POST", Pattern: Prefix + "/{id}/status", Group: "findings", Owner: routes.OwnerGo},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.front = &server.Server{Table: table, Auth: auth.New(password), Go: New(e.store, enabled)}
	return e
}

func (e *env) report(t *testing.T, id, asset, source string, sev findings.Severity, risk *float64, day int) {
	t.Helper()
	e.now = time.Date(2025, 3, day, 0, 0, 0, 0, time.UTC)
	_, err := e.store.Report(context.Background(), findings.ScanRef{}, []findings.Finding{{
		ID: id, RuleID: "r1", Title: "t " + id, Category: "code_and_dependencies", Type: findings.TypeVulnerability,
		Severity: sev, AssetID: asset, Source: source, RiskScore: risk,
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) do(method, target, body string, authed bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if authed {
		r.SetBasicAuth(auth.Username, password)
	}
	w := httptest.NewRecorder()
	e.front.ServeHTTP(w, r)
	return w
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	return v
}

type listBody struct {
	Items      []wireFinding `json:"items"`
	NextCursor string        `json:"nextCursor"`
	Truncated  bool          `json:"truncated"`
}

func ids(l listBody) []string {
	out := []string{}
	for _, f := range l.Items {
		out = append(out, f.ID)
	}
	return out
}

func seed(t *testing.T, e *env) {
	r := func(v float64) *float64 { return &v }
	e.report(t, "f1", "a1", "grype", findings.SevLow, r(10), 1)
	e.report(t, "f2", "a2", "trivy", findings.SevCritical, nil, 2)
	e.report(t, "f3", "a1", "trivy", findings.SevHigh, r(55.5), 3)
	e.report(t, "f4", "a3", "grype", findings.SevHigh, r(70), 4)
}

func TestUnauthenticatedRejectedBeforeHandler(t *testing.T) {
	e := newEnv(t, true)
	seed(t, e)
	for _, c := range []struct{ method, path, body string }{
		{"GET", Prefix, ""}, {"GET", Prefix + "/f1", ""}, {"POST", Prefix + "/f1/status", `{"status":"in_progress"}`},
	} {
		if w := e.do(c.method, c.path, c.body, false); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
	// The rejected POST changed nothing.
	f, _, _ := e.store.Get(context.Background(), "f1")
	if f.Status != findings.StatusOpen {
		t.Fatalf("status %s", f.Status)
	}
}

func TestListFiltersSortAndPaging(t *testing.T) {
	e := newEnv(t, true)
	seed(t, e)
	get := func(q string) listBody {
		t.Helper()
		w := e.do("GET", Prefix+"?"+q, "", true)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
		return decode[listBody](t, w)
	}
	if got := ids(get("")); strings.Join(got, ",") != "f4,f3,f2,f1" {
		t.Fatalf("default %v", got)
	}
	if got := ids(get("asset=a1&asset=a3&sort=severity")); strings.Join(got, ",") != "f1,f3,f4" {
		t.Fatalf("assets %v", got)
	}
	if got := ids(get("source=trivy&sort=-risk_score")); strings.Join(got, ",") != "f3,f2" {
		t.Fatalf("source %v", got)
	}
	from := url.QueryEscape("2025-03-02T00:00:00Z")
	to := url.QueryEscape("2025-03-03T00:00:00Z")
	if got := ids(get("from=" + from + "&to=" + to)); strings.Join(got, ",") != "f3,f2" {
		t.Fatalf("range %v", got)
	}
	if got := ids(get("severity=critical&severity=low&status=open")); strings.Join(got, ",") != "f2,f1" {
		t.Fatalf("enums %v", got)
	}

	// Page through a severity sort two at a time.
	var all []string
	q := "sort=-severity&limit=2"
	for range 5 {
		p := get(q)
		all = append(all, ids(p)...)
		if p.NextCursor == "" {
			break
		}
		q = "sort=-severity&limit=2&cursor=" + url.QueryEscape(p.NextCursor)
	}
	if strings.Join(all, ",") != "f2,f3,f4,f1" && strings.Join(all, ",") != "f2,f4,f3,f1" {
		t.Fatalf("paged %v", all)
	}
	if strings.Join(all, ",") != "f2,f3,f4,f1" { // high ties break on id ascending
		t.Fatalf("tie order %v", all)
	}
	first := get("limit=1")
	if first.NextCursor == "" || len(first.Items) != 1 || first.Truncated {
		t.Fatalf("%+v", first)
	}
	// A cursor does not carry over to a different sort.
	if w := e.do("GET", Prefix+"?sort=severity&cursor="+url.QueryEscape(first.NextCursor), "", true); w.Code != 400 {
		t.Fatalf("cursor reuse: %d", w.Code)
	}
}

func TestListBadParameterNamesItAndRunsNoQuery(t *testing.T) {
	e := newEnv(t, true)
	seed(t, e)
	for param, q := range map[string]string{
		"severity": "severity=urgent", "status": "status=done", "limit": "limit=0", "sort": "sort=title",
		"from": "from=yesterday", "cursor": "cursor=abc", "bogus": "bogus=1", "asset": "asset=",
	} {
		w := e.do("GET", Prefix+"?"+q, "", true)
		body := decode[map[string]string](t, w)
		if w.Code != 400 || body["field"] != param || body["code"] != "invalid_request" {
			t.Errorf("%s: %d %s", q, w.Code, w.Body)
		}
	}
	// A closed database fails any query with 500; a bad parameter must still give 400,
	// which shows the store was never called.
	e.db.Close()
	if w := e.do("GET", Prefix+"?severity=urgent", "", true); w.Code != 400 {
		t.Fatalf("query ran: %d", w.Code)
	}
}

func TestGet(t *testing.T) {
	e := newEnv(t, true)
	seed(t, e)
	w := e.do("GET", Prefix+"/f3", "", true)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	d := decode[wireDetail](t, w)
	if d.ID != "f3" || d.AssetID != "a1" || d.RiskScore == nil || *d.RiskScore != 55.5 || len(d.Events) != 1 || d.Events[0].New != "open" {
		t.Fatalf("%+v", d)
	}
	if w := e.do("GET", Prefix+"/nope", "", true); w.Code != 404 {
		t.Fatalf("missing: %d", w.Code)
	}
	if w := e.do("GET", Prefix+"/"+strings.Repeat("x", 200), "", true); w.Code != 400 || decode[map[string]string](t, w)["field"] != "id" {
		t.Fatalf("long id: %d %s", w.Code, w.Body)
	}
}

func TestSetStatus(t *testing.T) {
	e := newEnv(t, true)
	seed(t, e)
	post := func(id, body string) *httptest.ResponseRecorder {
		return e.do("POST", Prefix+"/"+id+"/status", body, true)
	}
	w := post("f1", `{"status":"in_progress"}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	d := decode[wireDetail](t, w)
	if d.Status != "in_progress" || len(d.Events) != 2 || d.Events[1].Actor != LocalActor {
		t.Fatalf("%+v", d)
	}
	until := e.now.Add(48 * time.Hour).Format(time.RFC3339)
	if w := post("f2", `{"status":"ignored","reason":"vendor fix pending","until":"`+until+`"}`); w.Code != 200 {
		t.Fatalf("snooze: %d %s", w.Code, w.Body)
	}

	for name, c := range map[string]struct {
		id, body, field string
		code            int
	}{
		"empty body":       {"f3", ``, "body", 400},
		"unknown key":      {"f3", `{"status":"open","x":1}`, "body", 400},
		"missing status":   {"f3", `{}`, "status", 400},
		"unknown status":   {"f3", `{"status":"closed"}`, "status", 400},
		"reason required":  {"f3", `{"status":"ignored"}`, "reason", 400},
		"reason too long":  {"f3", `{"status":"ignored","reason":"` + strings.Repeat("x", 1025) + `"}`, "reason", 400},
		"bad until":        {"f3", `{"status":"ignored","reason":"r","until":"soon"}`, "until", 400},
		"past until":       {"f3", `{"status":"ignored","reason":"r","until":"2020-01-01T00:00:00Z"}`, "until", 400},
		"until on open":    {"f3", `{"status":"in_progress","until":"` + until + `"}`, "until", 400},
		"not found":        {"nope", `{"status":"in_progress"}`, "", 404},
		"same status":      {"f1", `{"status":"in_progress"}`, "", 409},
		"resolved by user": {"f3", `{"status":"resolved"}`, "", 409},
		"leave snooze":     {"f2", `{"status":"in_progress"}`, "", 409},
	} {
		w := post(c.id, c.body)
		if w.Code != c.code {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
			continue
		}
		if c.field != "" && decode[map[string]string](t, w)["field"] != c.field {
			t.Errorf("%s: field %s", name, w.Body)
		}
	}
	// f3 was never changed by a rejected request.
	if f, ev, _ := e.store.Get(context.Background(), "f3"); f.Status != findings.StatusOpen || len(ev) != 1 {
		t.Fatalf("f3 changed: %s %d", f.Status, len(ev))
	}
}

func TestSetStatusAuditFailureIs500(t *testing.T) {
	e := newEnv(t, true)
	seed(t, e)
	if _, err := e.db.DB().Exec(`CREATE TRIGGER audit_block BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	w := e.do("POST", Prefix+"/f1/status", `{"status":"in_progress"}`, true)
	if w.Code != 500 || decode[map[string]string](t, w)["code"] != "audit_write_failed" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if f, _, _ := e.store.Get(context.Background(), "f1"); f.Status != findings.StatusOpen {
		t.Fatalf("status %s", f.Status)
	}
}

func TestActorComesFromCallerIdentity(t *testing.T) {
	e := newEnv(t, true)
	seed(t, e)
	mux := http.NewServeMux()
	Mount(mux, e.store, true)
	r := httptest.NewRequest("POST", Prefix+"/f1/status", strings.NewReader(`{"status":"in_progress"}`))
	r = r.WithContext(graph.WithCaller(r.Context(), graph.Caller{Role: graph.RoleWrite, Identity: "alice"}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || decode[wireDetail](t, w).Events[1].Actor != "alice" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestDisabledFlagAnswersNotFound(t *testing.T) {
	e := newEnv(t, false)
	for _, c := range []struct{ method, path string }{
		{"GET", Prefix}, {"GET", Prefix + "/f1"}, {"POST", Prefix + "/f1/status"},
	} {
		if w := e.do(c.method, c.path, `{"status":"open"}`, true); w.Code != 404 {
			t.Errorf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
	mux := http.NewServeMux()
	Mount(mux, nil, true) // no store behaves like disabled
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", Prefix, nil))
	if w.Code != 404 {
		t.Fatalf("nil store: %d", w.Code)
	}
}

func TestFailMapsStoreErrors(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{
		{&findings.InvalidError{Field: "cursor", Msg: "malformed"}, 400},
		{findings.ErrNotFound, 404},
		{findings.ErrTransition, 409},
		{findings.ErrAuditWriteFailed, 500},
		{errors.New("boom"), 500},
	} {
		w := httptest.NewRecorder()
		fail(w, c.err)
		if w.Code != c.code {
			t.Errorf("%v: %d", c.err, w.Code)
		}
	}
}
