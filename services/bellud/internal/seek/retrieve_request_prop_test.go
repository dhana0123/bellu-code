package seek_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/seek"
	"github.com/bellu/bellucode/services/bellud/internal/seek/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
)

func rtRunes(t *rapid.T, label string, min, max int) string {
	return rapid.StringOfN(rapid.Rune(), min, max, -1).Draw(t, label)
}

// rtLong returns a string of n..n+20 code points, so it is one past a limit at least.
func rtLong(t *rapid.T, label string, n int) string {
	r := rapid.Rune().Draw(t, label+"_rune")
	return strings.Repeat(string(r), rapid.IntRange(n, n+20).Draw(t, label+"_len"))
}

func rtGenUnit(t *rapid.T, label string, cwe int) seek.Unit {
	return seek.Unit{
		CWEID:     fmt.Sprintf("CWE-%d", cwe),
		RootCause: rtRunes(t, label+"_root_cause", 1, 40),
		Snippet:   rtRunes(t, label+"_snippet", 1, 40),
	}
}

// rtGenValidPlan draws a valid plan with minUnits..maxUnits distinct units.
func rtGenValidPlan(t *rapid.T, minUnits, maxUnits int) seek.Plan {
	ids := rapid.SliceOfNDistinct(rapid.IntRange(0, 99999), minUnits, maxUnits, func(i int) int { return i }).Draw(t, "cwe_nums")
	units := make([]seek.Unit, len(ids))
	for i, id := range ids {
		units[i] = rtGenUnit(t, fmt.Sprintf("unit%d", i), id)
	}
	return seek.Plan{
		Language:   rtRunes(t, "language", 1, 20),
		Reasoning:  rtRunes(t, "reasoning", 0, 40),
		Weaknesses: units,
	}
}

// Feature: bellu-seek-planner, Property 2: Validation rejects out-of-bound input without BSKG calls
// **Validates: Requirements 3.1, 3.2, 3.3, 3.7, 4.2, 4.5, 4.6, 9.3, 9.5, 9.8**
func TestRetrieveValidationRejectsOutOfBoundInputProperty(t *testing.T) {
	fake := seektest.New(t)
	r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))

	t.Run("typed plan", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			plan := rtGenValidPlan(t, 1, seek.MaxWeaknesses)
			topK := rapid.IntRange(seek.MinTopK, seek.MaxTopK).Draw(t, "top_k")
			path := ""
			switch rapid.IntRange(0, 7).Draw(t, "violation") {
			case 0:
				plan.Language, path = rtLong(t, "language", seek.MaxLanguage+1), "language"
			case 1:
				plan.Language, path = "", "language"
			case 2:
				plan.Reasoning, path = rtLong(t, "reasoning", seek.MaxReasoning+1), "reasoning"
			case 3:
				i := rapid.IntRange(0, len(plan.Weaknesses)-1).Draw(t, "index")
				plan.Weaknesses[i].RootCause = rtLong(t, "root_cause", seek.MaxRootCause+1)
				path = fmt.Sprintf("weaknesses[%d].root_cause", i)
			case 4:
				i := rapid.IntRange(0, len(plan.Weaknesses)-1).Draw(t, "index")
				plan.Weaknesses[i].Snippet = rtLong(t, "snippet", seek.MaxSnippet+1)
				path = fmt.Sprintf("weaknesses[%d].code_snippet", i)
			case 5:
				plan = rtGenValidPlan(t, seek.MaxWeaknesses+1, seek.MaxWeaknesses+1)
				path = "weaknesses"
			case 6:
				topK, path = rapid.IntRange(-1000, seek.MinTopK-1).Draw(t, "low_top_k"), "top_k"
			default:
				topK, path = rapid.IntRange(seek.MaxTopK+1, 1000).Draw(t, "high_top_k"), "top_k"
			}
			res := r.Run(context.Background(), plan, topK)
			found := false
			for _, is := range res.Issues {
				found = found || is.Path == path
			}
			if res.Status != "invalid_plan" || !found || len(res.Units) != 0 {
				t.Fatalf("path %q: result = %+v", path, res)
			}
		})
		if n := len(fake.Requests()); n != 0 {
			t.Fatalf("%d BSKG requests, want 0", n)
		}
	})

	t.Run("raw plan", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			plan := rtGenValidPlan(t, 1, seek.MaxWeaknesses)
			raw := map[string]any{"language": plan.Language, "reasoning": plan.Reasoning, "weaknesses": []map[string]any{}}
			units := make([]map[string]any, len(plan.Weaknesses))
			for i, u := range plan.Weaknesses {
				units[i] = map[string]any{"cwe_id": u.CWEID, "root_cause": u.RootCause, "code_snippet": u.Snippet}
			}
			raw["weaknesses"] = units

			target, prefix := raw, ""
			if rapid.Bool().Draw(t, "in_unit") {
				i := rapid.IntRange(0, len(units)-1).Draw(t, "index")
				target, prefix = units[i], fmt.Sprintf("weaknesses[%d].", i)
			}
			var fields []string
			for k := range target {
				fields = append(fields, k)
			}
			field := rapid.SampledFrom(sortedStrings(fields)).Draw(t, "field")
			path := prefix + field
			switch rapid.IntRange(0, 2).Draw(t, "violation") {
			case 0: // wrong type
				target[field] = rapid.SampledFrom([]any{42, true, nil, map[string]any{"a": 1}}).Draw(t, "wrong")
			case 1: // missing field
				delete(target, field)
			default: // extra field
				name := "x" + rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "extra_name")
				target[name] = rapid.SampledFrom([]any{"v", 1, nil}).Draw(t, "extra_value")
				path = prefix + name
			}
			body, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			got, rejected, issues := seek.ParsePlan(body)
			found := false
			for _, is := range issues {
				found = found || is.Path == path
			}
			if !found || len(got.Weaknesses) != 0 || len(rejected) != 0 {
				t.Fatalf("path %q: plan=%+v rejected=%v issues=%v body=%s", path, got, rejected, issues, body)
			}
		})
		if n := len(fake.Requests()); n != 0 {
			t.Fatalf("%d BSKG requests, want 0", n)
		}
	})

	t.Run("valid input passes", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			plan := rtGenValidPlan(t, 0, seek.MaxWeaknesses)
			topK := rapid.IntRange(seek.MinTopK, seek.MaxTopK).Draw(t, "top_k")
			raw := json.RawMessage(nil)
			if rapid.Bool().Draw(t, "explicit_top_k") {
				raw = json.RawMessage(fmt.Sprint(topK))
			}
			parsedTopK, issues := seek.ParseTopK(raw)
			if len(issues) != 0 || (raw != nil && parsedTopK != topK) || (raw == nil && parsedTopK != seek.DefaultTopK) {
				t.Fatalf("ParseTopK(%s) = %d %v", raw, parsedTopK, issues)
			}
			body, err := plan.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, rejected, issues := seek.ParsePlan(body); len(issues) != 0 || len(rejected) != 0 {
				t.Fatalf("valid plan: issues=%v rejected=%v", issues, rejected)
			}
			res := r.Run(context.Background(), plan, parsedTopK)
			if res.Status == "invalid_plan" || len(res.Issues) != 0 {
				t.Fatalf("valid plan rejected: %+v", res)
			}
		})
	})
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

var (
	rtAllowedPaths = []struct {
		re       *regexp.Regexp
		segments int
	}{
		{regexp.MustCompile(`^/v1/weaknesses/CWE-[0-9]{1,5}$`), 3},
		{regexp.MustCompile(`^/v1/weaknesses/CWE-[0-9]{1,5}/vulnerabilities$`), 4},
		{regexp.MustCompile(`^/v1/graph/neighborhood$`), 3},
		{regexp.MustCompile(`^/v1/vulnerabilities/CVE-[0-9]{4}-[0-9]{4,}$`), 3},
		{regexp.MustCompile(`^/v1/status$`), 2},
	}
	rtKnownCWEs = []int{79, 80, 89, 700, 710, 720, 730, 800}
)

func rtCheckRequest(t *rapid.T, req seektest.Request) {
	if req.Method != "GET" || req.Body != "" {
		t.Fatalf("request %s %s body=%q, want GET with no body", req.Method, req.Path, req.Body)
	}
	for _, s := range []string{req.Path, req.RawPath, req.RawQuery, req.Body} {
		if strings.Contains(s, rtKey) {
			t.Fatalf("key in URL or body: %q", s)
		}
	}
	for _, a := range rtAllowedPaths {
		if a.re.MatchString(req.Path) {
			if n := len(strings.Split(strings.Trim(req.Path, "/"), "/")); n != a.segments {
				t.Fatalf("path %q has %d segments, want %d", req.Path, n, a.segments)
			}
			return
		}
	}
	t.Fatalf("path %q is not allowlisted", req.Path)
}

// Feature: bellu-seek-planner, Property 4: Requests are read-only, allowlisted and injection-safe
// **Validates: Requirements 3.1, 3.2, 3.3, 3.7, 4.2, 4.5, 4.6, 9.3, 9.5, 9.8**
func TestRetrieveRequestsAreReadOnlyAllowlistedProperty(t *testing.T) {
	fake := seektest.New(t)
	r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 5*time.Second))

	var injectable []string
	for _, n := range rtKnownCWEs {
		id := fmt.Sprintf("CWE-%d", n)
		injectable = append(injectable, "/v1/weaknesses/"+id, "/v1/weaknesses/"+id+"/vulnerabilities")
	}
	injectable = append(injectable, "/v1/graph/neighborhood")
	rules := []seektest.Rule{
		{Status: 500}, {Status: 404}, {Status: 401}, {Status: 429}, {EchoKey: true}, {RedirectTo: fake.Foreign().URL},
	}

	rapid.Check(t, func(t *rapid.T) {
		fake.Clear()
		before := len(fake.Requests())
		for _, p := range rapid.SliceOfN(rapid.SampledFrom(injectable), 0, 4).Draw(t, "rule_paths") {
			fake.Inject(p, rapid.SampledFrom(rules).Draw(t, "rule"))
		}

		// Units mix fixture CWEs, which reach every endpoint, with arbitrary ids.
		count := rapid.IntRange(0, seek.MaxWeaknesses).Draw(t, "units")
		cwe := rapid.OneOf(rapid.SampledFrom(rtKnownCWEs), rapid.IntRange(0, 99999))
		ids := rapid.SliceOfNDistinct(cwe, count, count, func(i int) int { return i }).Draw(t, "cwe_nums")
		units := make([]seek.Unit, len(ids))
		for i, id := range ids {
			units[i] = seek.Unit{
				CWEID:     fmt.Sprintf("CWE-%d", id),
				RootCause: rapid.OneOf(rapid.Just(rtXSS), rapid.StringN(1, 60, -1)).Draw(t, "root_cause"),
				Snippet:   rapid.StringN(1, 60, -1).Draw(t, "snippet"),
			}
		}
		plan := seek.Plan{Language: "go", Reasoning: "test", Weaknesses: units}
		res := r.Run(context.Background(), plan, rapid.IntRange(seek.MinTopK, seek.MaxTopK).Draw(t, "top_k"))
		if res.Status == "invalid_plan" {
			t.Fatalf("generated plan rejected: %+v", res.Issues)
		}

		for _, req := range fake.Requests()[before:] {
			rtCheckRequest(t, req)
		}
		if n := len(fake.ForeignRequests()); n != 0 {
			t.Fatalf("foreign host received %d requests", n)
		}
	})

	t.Run("path builder", func(t *testing.T) {
		client, err := bskg.New(bskg.Config{BaseURL: fake.URL, Key: bskg.Secret(rtKey), Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		hostile := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`CWE-[0-9]{1,5}[/?#% .\\\n]{1,4}[a-z0-9./?#%]{0,6}`),
			rapid.StringMatching(`CVE-[0-9]{4}-[0-9]{4,6}[/?#% .\\\n]{1,4}[a-z0-9./?#%]{0,6}`),
			rapid.SampledFrom([]string{"../../v1/status", "CWE-79/../../status", "CWE-79?x=1", "CWE-79#f", "CWE-79%2f..", "CWE-79 ", " CWE-79", "..", "/", ""}),
		)
		rapid.Check(t, func(t *rapid.T) {
			fake.Clear()
			before := len(fake.Requests())
			s := hostile.Draw(t, "input")
			ctx := context.Background()
			_, _ = client.Weakness(ctx, s)
			_, _ = client.Children(ctx, s, 1)
			_, _ = client.WeaknessVulns(ctx, s, 5)
			_, _ = client.Vulnerability(ctx, s)

			reqs := fake.Requests()[before:]
			if len(reqs) > 4 {
				t.Fatalf("%d requests for one input %q", len(reqs), s)
			}
			for _, req := range reqs {
				rtCheckRequest(t, req)
				q, err := url.ParseQuery(req.RawQuery)
				if err != nil {
					t.Fatalf("query %q: %v", req.RawQuery, err)
				}
				allowed := map[string]bool{}
				switch {
				case strings.HasSuffix(req.Path, "/vulnerabilities"):
					allowed["limit"] = true
				case req.Path == "/v1/graph/neighborhood":
					for _, k := range []string{"type", "id", "depth", "relTypes"} {
						allowed[k] = true
					}
				}
				for k := range q {
					if !allowed[k] {
						t.Fatalf("path %q carries query key %q from input %q", req.Path, k, s)
					}
				}
				if req.RawQuery != "" && len(allowed) == 0 {
					t.Fatalf("path %q has query %q, want none", req.Path, req.RawQuery)
				}
			}
		})
	})
}
