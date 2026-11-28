package cvesource

import (
	"context"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/bskg/bskgtest"
)

const fakeID = "CVE-2021-44228"

func newGraphSource(t *testing.T, mode Mode, o bskgtest.Options, timeout time.Duration, ttl time.Duration, clock *time.Time) (*DB, *bskgtest.Server) {
	t.Helper()
	srv := bskgtest.New(o)
	t.Cleanup(srv.Close)
	d, err := New(Options{
		Store: newStore(t, now), Mode: mode, GraphCacheTTL: ttl,
		BSKG: bskg.New(bskg.Config{URL: srv.URL, Key: "test-key", Timeout: timeout}),
		Now:  func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, srv
}

func TestGraphModeDetailFromBSKG(t *testing.T) {
	clock := now
	d, srv := newGraphSource(t, ModeGraph, bskgtest.Options{}, 0, 0, &clock)
	det, err := d.Detail(context.Background(), fakeID, "")
	if err != nil || len(det.Gaps) != 0 {
		t.Fatalf("%+v %v", det, err)
	}
	v := det.Data.Vuln
	if v.Origin != OriginBSKG || v.CVSSScore != 10 || v.Summary == "db log4j" || !v.KEV {
		t.Fatalf("not BSKG data: %+v", v)
	}
	if len(det.Data.CWEs) != 2 || len(det.Data.Exploits) != 1 || len(det.Data.Affected) != 2 || det.Data.Related == nil {
		t.Fatalf("enrichment: %+v", det.Data)
	}
	if det.FieldFrom["detail"] != ModeGraph || !d.Status().BSKGReachable {
		t.Fatalf("%v %+v", det.FieldFrom, d.Status())
	}
	if len(srv.Recorder.Requests()) != 4 {
		t.Fatalf("want 4 requests, got %d", len(srv.Recorder.Requests()))
	}
}

func TestBothModeEnrichesDBRecord(t *testing.T) {
	clock := now
	d, _ := newGraphSource(t, ModeBoth, bskgtest.Options{}, 0, 0, &clock)
	det, err := d.Detail(context.Background(), fakeID, "")
	if err != nil || len(det.Gaps) != 0 {
		t.Fatalf("%+v %v", det, err)
	}
	if det.Data.Vuln.Summary != "db log4j" || det.Data.Vuln.Origin != OriginIntelStore {
		t.Fatalf("db record replaced: %+v", det.Data.Vuln)
	}
	for f, want := range map[string]Mode{"detail": ModeDB, "cwe": ModeGraph, "exploits": ModeGraph, "affected": ModeGraph, "related": ModeGraph} {
		if det.FieldFrom[f] != want {
			t.Errorf("FieldFrom[%s] = %q want %q", f, det.FieldFrom[f], want)
		}
	}
	if len(det.Data.CWEs) != 2 || len(det.Data.Exploits) != 1 {
		t.Fatalf("%+v", det.Data)
	}
	// Lookup never touches BSKG (17.4).
	if lr, err := d.Lookup(context.Background(), LookupQuery{ID: fakeID}); err != nil || len(lr.Data) != 1 || lr.Data[0].Origin != OriginIntelStore {
		t.Fatalf("%+v %v", lr, err)
	}
}

func TestGapCausesFallBackToDBData(t *testing.T) {
	cases := []struct {
		name  string
		opts  bskgtest.Options
		to    time.Duration
		cause string
	}{
		{"unauthorized", bskgtest.Options{Mode: bskgtest.Mode401}, 0, CauseUnauthorized},
		{"unreachable", bskgtest.Options{Mode: bskgtest.Mode503}, 0, CauseUnreachable},
		{"timeout", bskgtest.Options{Mode: bskgtest.ModeSlow, Delay: 2 * time.Second}, 50 * time.Millisecond, CauseTimeout},
	}
	for _, c := range cases {
		for _, m := range []Mode{ModeGraph, ModeBoth} {
			clock := now
			d, _ := newGraphSource(t, m, c.opts, c.to, 0, &clock)
			det, err := d.Detail(context.Background(), fakeID, "")
			if err != nil || len(det.Gaps) != 1 || det.Gaps[0] != (Gap{GapGraphUnavailable, c.cause}) {
				t.Fatalf("%s/%s: %+v %v", c.name, m, det, err)
			}
			if det.Data.Vuln.Summary != "db log4j" || det.FieldFrom["detail"] != ModeDB {
				t.Fatalf("%s/%s: db data lost: %+v", c.name, m, det)
			}
			if st := d.Status(); st.LastGap == nil || st.LastGap.Cause != c.cause || st.BSKGReachable {
				t.Fatalf("%s/%s: %+v", c.name, m, st)
			}
		}
	}
	d, _ := New(Options{Store: newStore(t, now), Mode: ModeBoth, Now: func() time.Time { return now }})
	det, _ := d.Detail(context.Background(), fakeID, "")
	if len(det.Gaps) != 1 || det.Gaps[0].Cause != CauseNotConfigured || det.Data.Vuln.ID != fakeID {
		t.Fatalf("nil client: %+v", det)
	}
}

func TestGraphSliceShapeAndCache(t *testing.T) {
	clock := now
	d, srv := newGraphSource(t, ModeGraph, bskgtest.Options{}, 0, time.Minute, &clock)
	ctx := context.Background()
	q := GraphQuery{ID: fakeID, NodeTypes: []string{"Exploit", "Weakness"}}
	g, err := d.Graph(ctx, q)
	if err != nil || len(g.Gaps) != 0 || len(g.Data.Nodes) != 4 || len(g.Data.Edges) != 3 {
		t.Fatalf("%+v %v", g, err)
	}
	if n := g.Data.Nodes[0]; n.ID != "Vulnerability:"+fakeID || n.Type != "Vulnerability" {
		t.Fatalf("start node %+v", n)
	}
	if e := g.Data.Edges[0]; e.Source == "" || e.Target == "" || e.ID == "" {
		t.Fatalf("edge %+v", e)
	}
	if _, err := d.Graph(ctx, q); err != nil || len(srv.Recorder.Requests()) != 1 {
		t.Fatalf("second call must hit the cache: %d requests", len(srv.Recorder.Requests()))
	}
	clock = clock.Add(59 * time.Second)
	_, _ = d.Graph(ctx, q)
	if len(srv.Recorder.Requests()) != 1 {
		t.Fatal("entry inside the TTL must be served")
	}
	clock = clock.Add(2 * time.Second)
	_, _ = d.Graph(ctx, q)
	if len(srv.Recorder.Requests()) != 2 {
		t.Fatal("entry older than the TTL was served")
	}
	g, _ = d.Graph(ctx, GraphQuery{ID: fakeID, Limit: 2})
	if len(g.Data.Nodes) != 2 || !g.Truncated {
		t.Fatalf("limit: %+v", g)
	}
	if _, err := d.Graph(ctx, GraphQuery{ID: "not-an-id"}); err == nil {
		t.Fatal("invalid id accepted")
	}
}

func TestCacheDropsEntriesOnRevisionChange(t *testing.T) {
	c := newLRU(8, time.Hour)
	c.put("/p", "a=1", bskg.Result{Revision: "r1"}, now)
	if _, ok := c.get("/p", "a=1", now); !ok {
		t.Fatal("miss")
	}
	c.put("/p", "a=2", bskg.Result{Revision: "r2"}, now)
	if _, ok := c.get("/p", "a=1", now); ok {
		t.Fatal("entry from the old revision survived")
	}
	if _, ok := c.get("/p", "a=2", now); !ok {
		t.Fatal("new entry missing")
	}
}

func TestStaleAndSampleWarningsPropagate(t *testing.T) {
	for mode, code := range map[bskgtest.Mode]string{bskgtest.ModeStale: WarnBSKGStale, bskgtest.ModeSample: WarnBSKGSample} {
		clock := now
		d, _ := newGraphSource(t, ModeBoth, bskgtest.Options{Mode: mode}, 0, 0, &clock)
		det, err := d.Detail(context.Background(), fakeID, "")
		g, err2 := d.Graph(context.Background(), GraphQuery{ID: fakeID})
		if err != nil || err2 != nil || !hasWarn(det.Warnings, code) || !hasWarn(g.Warnings, code) {
			t.Fatalf("%s: detail=%+v graph=%+v %v %v", mode, det.Warnings, g.Warnings, err, err2)
		}
	}
}

func hasWarn(ws []Warning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

func TestRequestsStayInsideAllowList(t *testing.T) {
	clock := now
	d, srv := newGraphSource(t, ModeBoth, bskgtest.Options{}, 0, 0, &clock)
	ctx := context.Background()
	_, _ = d.Detail(ctx, fakeID, "")
	_, _ = d.Graph(ctx, GraphQuery{ID: fakeID, Depth: 2, NodeTypes: []string{"Exploit"}})
	_, _ = d.Lookup(ctx, LookupQuery{Purl: "pkg:npm/lodash@4.17.20"})
	reqs := srv.Recorder.Requests()
	if len(reqs) == 0 {
		t.Fatal("no requests recorded")
	}
	srv.Recorder.AssertAllowed(t, bskgtest.AllowList{Rules: []bskgtest.Rule{
		{Method: "GET", Path: "/v1/vulnerabilities/{id}"},
		{Method: "GET", Path: "/v1/graph/neighborhood", Params: []string{"id", "type", "depth", "relTypes", "nodeTypes"}},
	}})
}

func TestMergeBothTieBreak(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	later := t0.Add(time.Hour)
	var zero time.Time
	for _, c := range []struct {
		name    string
		db, g   time.Time
		want    Mode
		wantSev string
	}{
		{"graph newer", t0, later, ModeGraph, "critical"},
		{"db newer", later, t0, ModeDB, "high"},
		{"equal", t0, t0, ModeDB, "high"},
		{"graph missing", t0, zero, ModeDB, "high"},
		{"db missing", zero, t0, ModeDB, "high"},
		{"both missing", zero, zero, ModeDB, "high"},
	} {
		db := Vuln{Summary: "a", Severity: "high", CVSSScore: 7, EPSS: 0.1, Modified: c.db}
		g := Vuln{Summary: "b", Severity: "critical", CVSSScore: 9, KEV: true, EPSS: 0.5, Modified: c.g}
		from := map[string]Mode{}
		out, conf := mergeBoth(db, g, from)
		if out.Severity != c.wantSev || from["severity"] != c.want || from["kev"] != c.want || from["summary"] != ModeDB || out.Summary != "a" {
			t.Errorf("%s: %+v %v", c.name, out, from)
		}
		if conf["severity"] != (Conflict{DB: "high", Graph: "critical"}) || conf["cvssScore"].Graph != 9.0 || conf["summary"].DB != "a" || len(conf) != 5 {
			t.Errorf("%s: conflicts %+v", c.name, conf)
		}
	}
	if _, conf := mergeBoth(Vuln{Severity: "high"}, Vuln{Severity: "high"}, map[string]Mode{}); conf != nil {
		t.Errorf("no conflict expected: %+v", conf)
	}
}

func TestLookupSameInDBAndBothMode(t *testing.T) {
	clock := now
	db, _ := newGraphSource(t, ModeDB, bskgtest.Options{}, 0, 0, &clock)
	both, _ := newGraphSource(t, ModeBoth, bskgtest.Options{}, 0, 0, &clock)
	for _, q := range []LookupQuery{{Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"}, {ID: fakeID}} {
		a, e1 := db.Lookup(context.Background(), q)
		b, e2 := both.Lookup(context.Background(), q)
		if e1 != nil || e2 != nil || len(a.Data) != len(b.Data) {
			t.Fatalf("%v %v %+v %+v", e1, e2, a, b)
		}
		for i := range a.Data {
			if a.Data[i].AffectedState != b.Data[i].AffectedState || a.Data[i].ID != b.Data[i].ID {
				t.Errorf("state differs: %+v vs %+v", a.Data[i], b.Data[i])
			}
		}
	}
}
