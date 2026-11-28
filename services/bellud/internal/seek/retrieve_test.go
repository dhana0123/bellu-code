package seek_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/seek"
	"github.com/bellu/bellucode/services/bellud/internal/seek/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
)

// These tests run the real Retriever with the real bskg client against the
// fake BSKG in seektest. Fixtures live in ../testdata.

const rtKey = "bskg-SECRET-key-4f9a1c7e22b0"

// rtXSS shares words with the descriptions of CVE-2021-0001, -0002 and
// CVE-2022-0003 so each of them passes the default relevance cutoff.
const rtXSS = "Cross-site scripting comment renderer title parameter stored profile bio field reflected script tag injection search results page"

type rtLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *rtLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *rtLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func rtConfig(request, total time.Duration) seek.Config {
	return seek.Config{
		RequestTimeout: request,
		TotalTimeout:   total,
		MinRelevance:   seek.DefaultMinRelevance,
		PerCWEFetch:    seek.MaxScope,
		MaxDetailFetch: 120,
		Concurrency:    8,
	}
}

// rtRetriever builds a Retriever on the real client for baseURL. The returned
// logs capture everything the Retriever logs, at debug level.
func rtRetriever(t *testing.T, baseURL string, cfg seek.Config) (*seek.Retriever, *rtLogs) {
	t.Helper()
	client, err := bskg.New(bskg.Config{BaseURL: baseURL, Key: bskg.Secret(rtKey), Timeout: cfg.RequestTimeout})
	if err != nil {
		t.Fatal(err)
	}
	logs := &rtLogs{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return seek.NewRetriever(client, cfg, logger), logs
}

func rtPlan(units ...seek.Unit) seek.Plan {
	return seek.Plan{Language: "go", Reasoning: "test", Weaknesses: units}
}

func rtUnit(cwe, text string) seek.Unit {
	return seek.Unit{CWEID: cwe, RootCause: text, Snippet: text}
}

func rtIDs(cs []seek.Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.CVEID
	}
	return out
}

func rtCount(reqs []seektest.Request, match func(seektest.Request) bool) int {
	n := 0
	for _, r := range reqs {
		if match(r) {
			n++
		}
	}
	return n
}

func rtPathCount(s *seektest.Server, path string) int {
	return rtCount(s.Requests(), func(r seektest.Request) bool { return r.Path == path })
}

func rtDepth2(s *seektest.Server) int {
	return rtCount(s.Requests(), func(r seektest.Request) bool {
		q, _ := url.ParseQuery(r.RawQuery)
		return r.Path == "/v1/graph/neighborhood" && q.Get("depth") == "2"
	})
}

// rtNoKey asserts the known key is in none of the places a caller can see.
func rtNoKey(t *testing.T, res seek.Result, logs *rtLogs) {
	t.Helper()
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	all := []string{string(body), logs.String(), fmt.Sprintf("%v|%+v|%#v", res, res, res)}
	collect := func(e *seek.ErrInfo) {
		if e != nil {
			all = append(all, e.Category, e.Message)
		}
	}
	collect(res.Error)
	for _, u := range res.Units {
		collect(u.Error)
	}
	for _, s := range all {
		if strings.Contains(s, rtKey) {
			t.Fatalf("key leaked in %q", s)
		}
	}
}

func TestRetrieveOKRanksAndNamesCandidates(t *testing.T) {
	fake := seektest.New(t)
	r, logs := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
	res := r.Run(context.Background(), rtPlan(rtUnit("CWE-79", rtXSS)), 4)

	if res.Status != "ok" || res.TopK != 4 || len(res.Units) != 1 {
		t.Fatalf("result = %+v", res)
	}
	u := res.Units[0]
	if u.Status != "ok" || u.Expanded || strings.Join(u.Scope, ",") != "CWE-79,CWE-80" {
		t.Fatalf("unit = %+v", u)
	}
	ids := rtIDs(u.Candidates)
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	if strings.Join(sorted, ",") != "CVE-2021-0001,CVE-2021-0002,CVE-2022-0003" || ids[0] != "CVE-2021-0002" {
		t.Fatalf("candidates = %v", ids)
	}
	for i := 1; i < len(u.Candidates); i++ {
		a, b := u.Candidates[i-1], u.Candidates[i]
		if a.Score < b.Score || (a.Score == b.Score && a.CVEID > b.CVEID) {
			t.Fatalf("not ordered: %v", ids)
		}
	}
	top := u.Candidates[0]
	if top.CWEID != "CWE-79" || !strings.Contains(top.CWEName, "Cross-site Scripting") || !top.KEV {
		t.Fatalf("top = %+v", top)
	}
	if top.FixCommit != "0123456789abcdef0123456789abcdef01234567" || top.Repository != "https://github.com/acme/widget" {
		t.Fatalf("fix/repository = %q %q", top.FixCommit, top.Repository)
	}
	for _, c := range u.Candidates {
		if c.CVEID == "CVE-2022-0003" && (c.CWEID != "CWE-80" || !strings.Contains(c.CWEName, "Script-Related")) {
			t.Fatalf("child candidate = %+v", c)
		}
	}
	rtNoKey(t, res, logs)
}

func TestRetrieveUnitStatuses(t *testing.T) {
	t.Run("no candidates attached", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-720", rtXSS)), 4)
		u := res.Units[0]
		if res.Status != "ok" || u.Status != "no_candidates" || len(u.Candidates) != 0 || u.Error != nil {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("all candidates below the cutoff", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-89", "zebra giraffe quokka")), 4)
		u := res.Units[0]
		if res.Status != "ok" || u.Status != "no_candidates" || len(u.Candidates) != 0 {
			t.Fatalf("result = %+v", res)
		}
		// A candidate was attached (then dropped by the cutoff), so no expansion.
		if n := rtDepth2(fake); n != 0 || u.Expanded {
			t.Fatalf("expanded: %d depth=2 requests, Expanded=%v", n, u.Expanded)
		}
	})
	t.Run("unknown cwe", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-999", rtXSS), rtUnit("CWE-79", rtXSS)), 4)
		bad, good := res.Units[0], res.Units[1]
		if res.Status != "ok" || bad.CWEID != "CWE-999" || bad.Status != "unknown_cwe" ||
			len(bad.Scope) != 0 || len(bad.Candidates) != 0 || good.Status != "ok" {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("only unknown cwes is still ok", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-999", rtXSS)), 4)
		if res.Status != "ok" || res.Units[0].Status != "unknown_cwe" {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("one unit fails while another returns", func(t *testing.T) {
		fake := seektest.New(t)
		fake.Inject("/v1/weaknesses/CWE-89", seektest.Rule{Status: 500})
		fake.Inject("/v1/weaknesses/CWE-89/vulnerabilities", seektest.Rule{Status: 500})
		r, logs := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-89", "SQL injection username"), rtUnit("CWE-79", rtXSS)), 4)
		bad, good := res.Units[0], res.Units[1]
		if res.Status != "ok" || bad.Status != "unavailable" || len(bad.Candidates) != 0 ||
			bad.Error == nil || bad.Error.Category != "unreachable" || good.Status != "ok" || len(good.Candidates) == 0 {
			t.Fatalf("result = %+v", res)
		}
		rtNoKey(t, res, logs)
	})
}

func TestRetrieveGrandchildExpansion(t *testing.T) {
	text := "Integer wraparound in the allocator sizing routine"
	t.Run("not when a direct scope CWE has a candidate", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-79", rtXSS)), 4)
		if res.Units[0].Expanded || rtDepth2(fake) != 0 {
			t.Fatalf("expanded=%v depth2=%d", res.Units[0].Expanded, rtDepth2(fake))
		}
	})
	t.Run("once when no depth 0 or 1 CWE has a candidate", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-700", text)), 4)
		u := res.Units[0]
		if u.Status != "ok" || !u.Expanded || strings.Join(u.Scope, ",") != "CWE-700,CWE-701,CWE-702" {
			t.Fatalf("unit = %+v", u)
		}
		if len(u.Candidates) != 1 || u.Candidates[0].CVEID != "CVE-2023-0702" || u.Candidates[0].CWEID != "CWE-702" {
			t.Fatalf("candidates = %+v", u.Candidates)
		}
		if n := rtDepth2(fake); n != 1 {
			t.Fatalf("depth=2 requests = %d, want 1", n)
		}
	})
	t.Run("once and reported when the grandchildren have none either", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-710", text)), 4)
		u := res.Units[0]
		if u.Status != "no_candidates" || !u.Expanded || strings.Join(u.Scope, ",") != "CWE-710,CWE-711,CWE-712" {
			t.Fatalf("unit = %+v", u)
		}
		if n := rtDepth2(fake); n != 1 {
			t.Fatalf("depth=2 requests = %d, want 1", n)
		}
	})
}

func TestRetrieveCrossUnitDedupeKeepsEarliestUnit(t *testing.T) {
	// CVE-2022-0003 is attached to CWE-80, which is in the scope of CWE-79.
	t.Run("parent first", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-79", rtXSS), rtUnit("CWE-80", rtXSS)), 4)
		first, second := res.Units[0], res.Units[1]
		if !strings.Contains(strings.Join(rtIDs(first.Candidates), ","), "CVE-2022-0003") {
			t.Fatalf("first = %v", rtIDs(first.Candidates))
		}
		if second.Status != "no_candidates" || len(second.Candidates) != 0 {
			t.Fatalf("second = %+v", second)
		}
	})
	t.Run("child first", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-80", rtXSS), rtUnit("CWE-79", rtXSS)), 4)
		first, second := res.Units[0], res.Units[1]
		if strings.Join(rtIDs(first.Candidates), ",") != "CVE-2022-0003" {
			t.Fatalf("first = %v", rtIDs(first.Candidates))
		}
		got := rtIDs(second.Candidates)
		sort.Strings(got)
		if strings.Join(got, ",") != "CVE-2021-0001,CVE-2021-0002" {
			t.Fatalf("second = %v", got)
		}
	})
}

func TestRetrieveDetailFetchCap(t *testing.T) {
	// CWE-800 has children 801-803 with 50 references each (150 in total).
	// Reference i has CVE-2024-(1000+i) and v3 score (99-(7i mod 20))/10, so
	// scores repeat and the CVE id breaks ties.
	type ref struct {
		id    string
		tenth int
	}
	var refs []ref
	for i := 0; i < 150; i++ {
		refs = append(refs, ref{fmt.Sprintf("/v1/vulnerabilities/CVE-2024-%d", 1000+i), 99 - (i*7)%20})
	}
	sort.Slice(refs, func(a, b int) bool {
		if refs[a].tenth != refs[b].tenth {
			return refs[a].tenth > refs[b].tenth
		}
		return refs[a].id < refs[b].id
	})
	want := map[string]bool{}
	for _, x := range refs[:120] {
		want[x.id] = true
	}

	fake := seektest.New(t)
	r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 10*time.Second))
	res := r.Run(context.Background(), rtPlan(rtUnit("CWE-800", "Overflow candidate number")), 10)

	got := map[string]int{}
	for _, req := range fake.Requests() {
		if strings.HasPrefix(req.Path, "/v1/vulnerabilities/") {
			got[req.Path]++
		}
	}
	if len(got) != 120 {
		t.Fatalf("distinct detail fetches = %d, want 120", len(got))
	}
	for p, n := range got {
		if !want[p] || n != 1 {
			t.Fatalf("unexpected detail fetch %s x%d", p, n)
		}
	}
	if len(res.Units[0].Candidates) != 10 {
		t.Fatalf("candidates = %d, want 10", len(res.Units[0].Candidates))
	}
	for _, c := range res.Units[0].Candidates {
		if !want["/v1/vulnerabilities/"+c.CVEID] {
			t.Fatalf("candidate %s was not among the first 120", c.CVEID)
		}
	}
}

func TestRetrieveCWENamesOnlyForAllocatedCandidates(t *testing.T) {
	t.Run("dropped candidate gets no lookup", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		res := r.Run(context.Background(), rtPlan(rtUnit("CWE-79", rtXSS)), 1)
		if ids := rtIDs(res.Units[0].Candidates); len(ids) != 1 || ids[0] != "CVE-2021-0002" {
			t.Fatalf("candidates = %v", ids)
		}
		if n := rtPathCount(fake, "/v1/weaknesses/CWE-80"); n != 0 {
			t.Fatalf("CWE-80 looked up %d times", n)
		}
	})
	t.Run("allocated candidate is looked up once", func(t *testing.T) {
		fake := seektest.New(t)
		r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		r.Run(context.Background(), rtPlan(rtUnit("CWE-79", rtXSS)), 4)
		if n := rtPathCount(fake, "/v1/weaknesses/CWE-80"); n != 1 {
			t.Fatalf("CWE-80 looked up %d times, want 1", n)
		}
	})
}

func TestRetrieveFixCommitAndRepositoryTogetherOrOmitted(t *testing.T) {
	fake := seektest.New(t)
	r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
	// CVE-2023-0801 has a fix commit and no repository; CVE-2023-0802 has a
	// repository and no fix commit.
	res := r.Run(context.Background(), rtPlan(rtUnit("CWE-730", "Heap overflow parser buffer length handling")), 4)
	cs := res.Units[0].Candidates
	if len(cs) != 2 {
		t.Fatalf("candidates = %+v", cs)
	}
	for _, c := range cs {
		if c.FixCommit != "" || c.Repository != "" {
			t.Fatalf("%s: fix=%q repository=%q, want both omitted", c.CVEID, c.FixCommit, c.Repository)
		}
	}
	body, _ := json.Marshal(cs)
	if strings.Contains(string(body), "fix_commit") || strings.Contains(string(body), "repository") {
		t.Fatalf("fields not omitted: %s", body)
	}
}

func TestRetrieveCVEUnavailable(t *testing.T) {
	plan := rtPlan(rtUnit("CWE-79", rtXSS), rtUnit("CWE-89", "SQL injection username"))
	all79 := []string{"/v1/graph/neighborhood", "/v1/weaknesses/CWE-79", "/v1/weaknesses/CWE-79/vulnerabilities"}
	all89 := []string{"/v1/weaknesses/CWE-89", "/v1/weaknesses/CWE-89/vulnerabilities"}
	injectAll := func(s *seektest.Server, rule seektest.Rule) {
		for _, p := range append(append([]string{}, all79...), all89...) {
			s.Inject(p, rule)
		}
	}
	cases := []struct {
		name     string
		category string
		units    bool // every unit is reported unavailable
		retr     func(t *testing.T) (*seek.Retriever, *rtLogs)
	}{
		{"unconfigured", "unconfigured", false, func(t *testing.T) (*seek.Retriever, *rtLogs) {
			logs := &rtLogs{}
			return seek.NewRetriever(nil, rtConfig(time.Second, 2*time.Second), slog.New(slog.NewTextHandler(logs, nil))), logs
		}},
		{"unreachable", "unreachable", true, func(t *testing.T) (*seek.Retriever, *rtLogs) {
			return rtRetriever(t, "http://127.0.0.1:1", rtConfig(time.Second, 3*time.Second))
		}},
		{"delay beyond the request timeout", "timeout", true, func(t *testing.T) (*seek.Retriever, *rtLogs) {
			fake := seektest.New(t)
			injectAll(fake, seektest.Rule{Delay: 5 * time.Second})
			return rtRetriever(t, fake.URL, rtConfig(150*time.Millisecond, 10*time.Second))
		}},
		{"401", "authentication", true, func(t *testing.T) (*seek.Retriever, *rtLogs) {
			fake := seektest.New(t)
			injectAll(fake, seektest.Rule{Status: 401})
			return rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		}},
		{"body echoing the key", "unreachable", true, func(t *testing.T) (*seek.Retriever, *rtLogs) {
			fake := seektest.New(t)
			injectAll(fake, seektest.Rule{EchoKey: true})
			return rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		}},
		{"redirect to another host", "unreachable", true, func(t *testing.T) (*seek.Retriever, *rtLogs) {
			fake := seektest.New(t)
			injectAll(fake, seektest.Rule{RedirectTo: fake.Foreign().URL})
			t.Cleanup(func() {
				if n := len(fake.ForeignRequests()); n != 0 {
					t.Errorf("foreign host received %d requests", n)
				}
			})
			return rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, logs := tc.retr(t)
			start := time.Now()
			res := r.Run(context.Background(), plan, 4)
			if time.Since(start) > 4*time.Second {
				t.Fatalf("took %v", time.Since(start))
			}
			if res.Status != "cve_unavailable" || res.Error == nil || res.Error.Category != tc.category {
				t.Fatalf("result = %+v error=%+v", res, res.Error)
			}
			for _, u := range res.Units {
				if len(u.Candidates) != 0 || (tc.units && u.Status != "unavailable") {
					t.Fatalf("unit = %+v", u)
				}
			}
			if tc.units && len(res.Units) != 2 {
				t.Fatalf("units = %d, want 2", len(res.Units))
			}
			rtNoKey(t, res, logs)
		})
	}
}

func TestRetrieveTotalDeadline(t *testing.T) {
	fake := seektest.New(t)
	fake.Inject("/v1/weaknesses/CWE-89", seektest.Rule{Delay: 10 * time.Second})
	r, logs := rtRetriever(t, fake.URL, rtConfig(8*time.Second, 400*time.Millisecond))
	start := time.Now()
	res := r.Run(context.Background(), rtPlan(rtUnit("CWE-89", "SQL injection username"), rtUnit("CWE-79", rtXSS)), 4)
	if time.Since(start) > 4*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	late, done := res.Units[0], res.Units[1]
	if res.Status != "ok" || done.Status != "ok" || len(done.Candidates) == 0 {
		t.Fatalf("result = %+v", res)
	}
	if late.Status != "unavailable" || len(late.Candidates) != 0 || late.Error == nil || late.Error.Category != "timeout" {
		t.Fatalf("late unit = %+v", late)
	}
	rtNoKey(t, res, logs)
}

func TestRetrieveEmptyAndInvalidPlansMakeNoRequests(t *testing.T) {
	long := strings.Repeat("x", 1001)
	fake := seektest.New(t)
	r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))

	empty := r.Run(context.Background(), seek.Plan{Language: "go"}, 4)
	if empty.Status != "ok" || len(empty.Units) != 0 {
		t.Fatalf("empty = %+v", empty)
	}

	nine := make([]seek.Unit, seek.MaxWeaknesses+1)
	for i := range nine {
		nine[i] = rtUnit(fmt.Sprintf("CWE-%d", 79+i), rtXSS)
	}
	invalid := map[string]struct {
		plan seek.Plan
		topK int
		path string
	}{
		"top_k zero":            {rtPlan(rtUnit("CWE-79", rtXSS)), 0, "top_k"},
		"top_k eleven":          {rtPlan(rtUnit("CWE-79", rtXSS)), 11, "top_k"},
		"bad cwe id":            {rtPlan(rtUnit("CWE-79/../../v1/status", rtXSS)), 4, "weaknesses[0].cwe_id"},
		"long root cause":       {rtPlan(seek.Unit{CWEID: "CWE-79", RootCause: long, Snippet: "x"}), 4, "weaknesses[0].root_cause"},
		"over the weakness cap": {rtPlan(nine...), 4, "weaknesses"},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			res := r.Run(context.Background(), tc.plan, tc.topK)
			found := false
			for _, is := range res.Issues {
				found = found || is.Path == tc.path
			}
			if res.Status != "invalid_plan" || !found || len(res.Units) != 0 {
				t.Fatalf("result = %+v", res)
			}
		})
	}

	// A raw plan that fails ParsePlan never reaches Run.
	raw, _ := json.Marshal(map[string]any{"language": "go", "reasoning": "r", "weaknesses": nine, "extra": 1})
	if _, _, issues := seek.ParsePlan(raw); len(issues) == 0 {
		t.Fatal("ParsePlan accepted an invalid plan")
	}
	if n := len(fake.Requests()); n != 0 {
		t.Fatalf("%d BSKG requests, want 0", n)
	}
}
