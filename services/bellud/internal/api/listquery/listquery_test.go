package listquery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var spec = Spec{
	Filters:     AllFilters,
	Sorts:       []string{"updated_at", "score"},
	DefaultSort: "-score",
}

func parse(t *testing.T, raw string) (Query, error) {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return spec.Parse(v)
}

func TestParseValid(t *testing.T) {
	q, err := parse(t, "severity=high&severity=critical&severity=high&category=secrets&asset=a1&from=2025-01-01T00:00:00Z&to=2025-02-01T00:00:00Z&sort=updated_at&limit=500")
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Severities) != 2 || q.Severities[0] != "high" || q.Categories[0] != "secrets" || q.Assets[0] != "a1" {
		t.Fatalf("filters: %+v", q)
	}
	if q.SortField != "updated_at" || q.Desc || q.Limit != 500 || q.From == nil || q.To == nil {
		t.Fatalf("query: %+v", q)
	}
}

func TestDefaults(t *testing.T) {
	q, err := parse(t, "")
	if err != nil || q.Limit != 50 || q.SortField != "score" || !q.Desc {
		t.Fatalf("%+v %v", q, err)
	}
	q, _ = parse(t, "sort=-updated_at")
	if q.SortField != "updated_at" || !q.Desc {
		t.Fatalf("%+v", q)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"bogus=1":                    "bogus",
		"limit=0":                    "limit",
		"limit=501":                  "limit",
		"limit=abc":                  "limit",
		"limit=1.5":                  "limit",
		"limit=-3":                   "limit",
		"limit=1&limit=2":            "limit",
		"severity=urgent":            "severity",
		"status=open&status=nope":    "status",
		"type=x":                     "type",
		"category=cloud":             "category",
		"severity=":                  "severity",
		"from=yesterday":             "from",
		"to=2025-01-01":              "to",
		"sort=nope":                  "sort",
		"sort=-nope":                 "sort",
		"sort=score&sort=updated_at": "sort",
		"cursor=garbage":             "cursor",
		"cursor=a.b":                 "cursor",
		"from=2025-02-01T00:00:00Z&to=2025-01-01T00:00:00Z": "from",
	}
	for raw, param := range cases {
		_, err := parse(t, raw)
		e, ok := err.(*Error)
		if !ok || e.Param != param {
			t.Errorf("%q: got %v, want error on %q", raw, err, param)
		}
	}
}

func TestSpecRestrictsFilters(t *testing.T) {
	narrow := Spec{Filters: []string{Severity}}
	if _, err := narrow.Parse(url.Values{"asset": {"a"}}); err == nil || err.(*Error).Param != "asset" {
		t.Fatalf("got %v", err)
	}
	if _, err := narrow.Parse(url.Values{"sort": {"x"}}); err == nil {
		t.Fatal("sort without sortable fields must fail")
	}
	custom := Spec{Filters: []string{Status}, Domains: map[string][]string{Status: {"queued", "done"}}}
	if _, err := custom.Parse(url.Values{"status": {"queued"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := custom.Parse(url.Values{"status": {"open"}}); err == nil {
		t.Fatal("default domain must be overridden")
	}
}

func TestCursorRoundTripExpiryAndBinding(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewCodec().WithClock(func() time.Time { return now })
	q, _ := spec.ParseWith(c, url.Values{"severity": {"high"}})
	cur := q.NextCursorWith(c, "2025|id9")

	got, err := spec.ParseWith(c, url.Values{"severity": {"high"}, "cursor": {cur}})
	if err != nil || got.Position != "2025|id9" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := spec.ParseWith(c, url.Values{"severity": {"low"}, "cursor": {cur}}); err == nil || err.(*Error).Param != "cursor" {
		t.Fatalf("filter change must invalidate cursor: %v", err)
	}
	late := c.WithClock(func() time.Time { return now.Add(CursorTTL) })
	if _, err := spec.ParseWith(late, url.Values{"severity": {"high"}, "cursor": {cur}}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired cursor: %v", err)
	}
	other := NewCodec().WithClock(c.now)
	if _, err := spec.ParseWith(other, url.Values{"severity": {"high"}, "cursor": {cur}}); err == nil {
		t.Fatal("cursor from another key must fail")
	}
	// Tamper with the body.
	body, sig, _ := strings.Cut(cur, ".")
	if _, err := spec.ParseWith(c, url.Values{"severity": {"high"}, "cursor": {body + "A." + sig}}); err == nil {
		t.Fatal("tampered cursor must fail")
	}
}

func TestWriteError(t *testing.T) {
	_, err := parse(t, "limit=0")
	rec := httptest.NewRecorder()
	if !WriteIfInvalid(rec, err) {
		t.Fatal("not written")
	}
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	var body map[string]string
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["_tag"] != "InvalidRequestError" || body["code"] != "invalid_request" || body["field"] != "limit" || body["kind"] != "validation" {
		t.Fatalf("%v", body)
	}
	if WriteIfInvalid(httptest.NewRecorder(), context.Canceled) {
		t.Fatal("non-query error written")
	}
}

func TestBudgetAndTruncated(t *testing.T) {
	ctx, cancel := Budget(context.Background())
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) > DefaultBudget || time.Until(dl) < 9*time.Second {
		t.Fatalf("deadline %v", dl)
	}
	short, cancel2 := BudgetFor(context.Background(), time.Millisecond)
	defer cancel2()
	<-short.Done()
	if !Truncated(short, short.Err()) {
		t.Fatal("deadline must truncate")
	}
	c3, cancel3 := context.WithCancel(context.Background())
	cancel3()
	if Truncated(c3, c3.Err()) {
		t.Fatal("cancel is not truncation")
	}
	b, _ := json.Marshal(Page[int]{Items: []int{1}, Truncated: true})
	if string(b) != `{"items":[1],"truncated":true}` {
		t.Fatal(string(b))
	}
}

func TestToFindings(t *testing.T) {
	q, err := Spec{Filters: AllFilters, Sorts: []string{"risk_score"}}.Parse(url.Values{
		"severity": {"high", "low"}, "status": {"open"}, "type": {"secret"}, "category": {"secrets"},
		"asset": {"a", "b"}, "source": {"s", "t"}, "from": {"2025-01-01T00:00:00Z"}, "to": {"2025-02-01T00:00:00Z"},
		"sort": {"-risk_score"}, "limit": {"7"}})
	if err != nil {
		t.Fatal(err)
	}
	lq, err := ToFindings(q)
	if err != nil || len(lq.Severities) != 2 || lq.Statuses[0] != "open" || lq.Types[0] != "secret" || lq.Categories[0] != "secrets" ||
		len(lq.AssetIDs) != 2 || len(lq.Sources) != 2 || lq.Limit != 7 || lq.Sort != "risk_score" || !lq.Desc ||
		lq.From == nil || lq.To == nil {
		t.Fatalf("%+v %v", lq, err)
	}
}
