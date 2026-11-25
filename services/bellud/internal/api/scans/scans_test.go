package scans

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

type adapter struct{}

func (adapter) Kind() scanners.Kind { return scanners.KindSecret }
func (adapter) Info() scanners.Info {
	return scanners.Info{Name: "fake", Version: "1.0", License: "MIT"}
}
func (adapter) Applies(t scanners.TargetType) bool                        { return t == scanners.TargetRepository }
func (adapter) Digest(context.Context, scanners.Target) (string, error)   { return "", nil }
func (adapter) Run(context.Context, scanners.Target, scanners.Sink) error { return nil }

// newHandler builds a real Manager that is never started, so jobs stay queued.
func newHandler(t *testing.T, enabled bool) http.Handler {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := findings.New(db)
	t.Cleanup(fs.Close)
	m, err := scanners.New(scanners.Config{
		Store: db, Settings: config.DefaultScanners(), Adapters: []scanners.Adapter{adapter{}},
		Resolve: func(_ context.Context, typ scanners.TargetType, id string) (scanners.Target, bool, error) {
			return scanners.Target{Type: typ, ID: id}, id == "repo1", nil
		},
		SinkFor: func(j scanners.Job) scanners.JobSink {
			return scanners.FindingsSink{JobSink: fs.JobSink(context.Background(), findings.ScanRef{JobID: j.ID})}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(Deps{Orch: m, Adapters: func() []scanners.Adapter { return []scanners.Adapter{adapter{}} }}, enabled)
}

func do(h http.Handler, method, path, body string) (int, map[string]any) {
	r := httptest.NewRequest(method, Prefix+path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestScansLifecycle(t *testing.T) {
	h := newHandler(t, true)
	code, job := do(h, "POST", "", `{"kind":"secret","targetType":"repository","targetId":"repo1"}`)
	id, _ := job["id"].(string)
	if code != http.StatusAccepted || id == "" || job["status"] != "queued" {
		t.Fatalf("enqueue = %d %v", code, job)
	}
	if code, got := do(h, "GET", "/"+id, ""); code != 200 || got["id"] != id {
		t.Fatalf("get = %d %v", code, got)
	}
	if code, got := do(h, "GET", "", ""); code != 200 || len(got["items"].([]any)) != 1 {
		t.Fatalf("list = %d %v", code, got)
	}
	code, sc := do(h, "GET", "/scanners", "")
	items, _ := sc["items"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["name"] != "fake" || items[0].(map[string]any)["lastRun"] == nil {
		t.Fatalf("scanners = %d %v", code, sc)
	}
	if code, got := do(h, "POST", "/"+id+"/cancel", ""); code != 200 || got["status"] != "cancelled" {
		t.Fatalf("cancel = %d %v", code, got)
	}
	if code, got := do(h, "POST", "/"+id+"/cancel", ""); code != 409 {
		t.Fatalf("second cancel = %d %v", code, got)
	}
	if code, _ := do(h, "GET", "/sj_missing", ""); code != 404 {
		t.Fatalf("missing job = %d", code)
	}
	if code, got := do(h, "PUT", "/schedules/repo1", `{"kind":"secret","targetType":"repository","intervalSeconds":3600,"enabled":true}`); code != 200 || got["intervalSeconds"] != float64(3600) {
		t.Fatalf("schedule = %d %v", code, got)
	}
	if code, _ := do(h, "PUT", "/schedules/repo1", `{"kind":"secret","targetType":"repository","intervalSeconds":60,"enabled":true}`); code != 400 {
		t.Fatalf("short interval = %d", code)
	}
}

func TestScansRejections(t *testing.T) {
	h := newHandler(t, true)
	if code, got := do(h, "POST", "", `{"kind":"bogus","targetType":"repository","targetId":"repo1"}`); code != 400 || got["field"] != "kind" {
		t.Fatalf("bad kind = %d %v", code, got)
	}
	if code, got := do(h, "POST", "", `{"kind":"secret","targetType":"host","targetId":"repo1"}`); code != 400 || !strings.Contains(got["message"].(string), "kind_not_applicable") {
		t.Fatalf("not applicable = %d %v", code, got)
	}
	if code, got := do(h, "POST", "", `{"kind":"secret","targetType":"repository","targetId":"nope"}`); code != 400 || !strings.Contains(got["message"].(string), "target_not_found") {
		t.Fatalf("no target = %d %v", code, got)
	}
}

func TestScansFlagOff(t *testing.T) {
	h := newHandler(t, false)
	for _, c := range [][2]string{{"POST", ""}, {"GET", ""}, {"GET", "/scanners"}, {"GET", "/x"}, {"POST", "/x/cancel"}, {"PUT", "/schedules/x"}} {
		if code, _ := do(h, c[0], c[1], "{}"); code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c[0], c[1], code)
		}
	}
}
