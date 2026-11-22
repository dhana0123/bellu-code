package seek

import (
	"math"
	"reflect"
	"testing"
)

const eps = 1e-9

func near(a, b float64) bool { return math.Abs(a-b) < eps }

func set(words ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}

func fp(f float64) *float64 { return &f }

func TestTokens(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]struct{}
	}{
		{"empty", "", set()},
		{"lowercases and splits on non alphanumerics", "Buffer_Overflow in strcpy()", set("buffer", "overflow", "strcpy")},
		{"drops tokens shorter than 3", "an of to ab abc", set("abc")},
		{"keeps digits", "CVE-2021-44228 log4j", set("cve", "2021", "44228", "log4j")},
		{"deduplicates", "copy COPY Copy", set("copy")},
		{"only punctuation", "!! -- ??", set()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Tokens(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Tokens(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestJaccard(t *testing.T) {
	tests := []struct {
		name string
		a, b map[string]struct{}
		want float64
	}{
		{"both empty is 0", set(), set(), 0},
		{"one empty is 0", set("abc"), set(), 0},
		{"identical is 1", set("abc", "def"), set("abc", "def"), 1},
		{"disjoint is 0", set("abc"), set("def"), 0},
		{"2 of 4", set("aaa", "bbb", "ccc"), set("bbb", "ccc", "ddd"), 0.5},
		{"1 of 3", set("aaa", "bbb"), set("bbb", "ccc"), 1.0 / 3.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Jaccard(tc.a, tc.b); !near(got, tc.want) {
				t.Fatalf("Jaccard = %v, want %v", got, tc.want)
			}
			if got := Jaccard(tc.b, tc.a); !near(got, tc.want) {
				t.Fatalf("Jaccard is not symmetric: %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIdentMatch(t *testing.T) {
	tests := []struct {
		name                  string
		desc, snippet, rootCa string
		want                  float64
	}{
		{"shared token with snippet", "Overflow in strcpy allows code execution", "strcpy(dst, src);", "", 1},
		{"shared token with root cause", "Heap overflow in memcpy", "", "unchecked memcpy length", 1},
		{"case insensitive", "STRCPY overflow", "strcpy(a,b)", "", 1},
		{"no shared token", "Cross site scripting in widget", "strcpy(dst, src);", "unbounded copy", 0},
		{"shared token shorter than 3 does not count", "an xx issue", "int xx = 1", "", 0},
		{"empty inputs", "", "", "", 0},
		{"empty description", "", "strcpy(a,b)", "strcpy", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IdentMatch(tc.desc, tc.snippet, tc.rootCa); got != tc.want {
				t.Fatalf("IdentMatch = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSignalsFor(t *testing.T) {
	u := Unit{
		CWEID:     "CWE-120",
		RootCause: "unchecked copy overflow",
		Snippet:   "strcpy(dst, src);",
	}

	t.Run("all signals present", func(t *testing.T) {
		v := VulnDetail{
			CVEID:       "CVE-2020-0001",
			Description: "unchecked copy overflow via strcpy",
			CVSS:        fp(7.5),
			KEV:         true,
			EPSS:        fp(0.25),
			FixCommit:   "abc123",
			Repository:  "github.com/x/y",
		}
		got := SignalsFor(u, v)
		// Overlap is Jaccard(root_cause tokens, description tokens): 3 shared of 5.
		want := Signals{IdentMatch: 1, Overlap: 3.0 / 5.0, KEV: 1, EPSS: 0.25, CVSS: 0.75, Fix: 1}
		if !near(got.IdentMatch, want.IdentMatch) || !near(got.Overlap, want.Overlap) ||
			!near(got.KEV, want.KEV) || !near(got.EPSS, want.EPSS) ||
			!near(got.CVSS, want.CVSS) || !near(got.Fix, want.Fix) {
			t.Fatalf("SignalsFor = %+v, want %+v", got, want)
		}
	})

	t.Run("missing BSKG signals are 0", func(t *testing.T) {
		v := VulnDetail{CVEID: "CVE-2020-0002", Description: "cross site scripting widget"}
		got := SignalsFor(u, v)
		if got != (Signals{}) {
			t.Fatalf("SignalsFor = %+v, want all zero", got)
		}
	})

	t.Run("no fix commit means no fix signal", func(t *testing.T) {
		v := VulnDetail{CVEID: "CVE-2020-0003", Description: "x", Repository: "github.com/x/y"}
		if got := SignalsFor(u, v).Fix; got != 0 {
			t.Fatalf("Fix = %v, want 0", got)
		}
	})

	t.Run("CVSS is divided by 10", func(t *testing.T) {
		v := VulnDetail{CVEID: "CVE-2020-0004", CVSS: fp(10)}
		if got := SignalsFor(u, v).CVSS; !near(got, 1) {
			t.Fatalf("CVSS = %v, want 1", got)
		}
	})
}

func TestScore(t *testing.T) {
	tests := []struct {
		name string
		in   Signals
		want float64
	}{
		{"all zero", Signals{}, 0},
		{"all one", Signals{1, 1, 1, 1, 1, 1}, 1},
		{"ident only", Signals{IdentMatch: 1}, 0.30},
		{"overlap only", Signals{Overlap: 1}, 0.25},
		{"kev only", Signals{KEV: 1}, 0.15},
		{"epss only", Signals{EPSS: 1}, 0.10},
		{"cvss only", Signals{CVSS: 1}, 0.10},
		{"fix only", Signals{Fix: 1}, 0.10},
		{"mixed", Signals{IdentMatch: 1, Overlap: 0.4, KEV: 1, EPSS: 0.5, CVSS: 0.75, Fix: 0},
			0.30 + 0.25*0.4 + 0.15 + 0.10*0.5 + 0.10*0.75},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Score(tc.in); !near(got, tc.want) {
				t.Fatalf("Score(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	t.Run("clamped to [0,1]", func(t *testing.T) {
		if got := Score(Signals{IdentMatch: 5, Overlap: 5, KEV: 5, EPSS: 5, CVSS: 5, Fix: 5}); got != 1 {
			t.Fatalf("over range = %v, want 1", got)
		}
		if got := Score(Signals{IdentMatch: -5}); got != 0 {
			t.Fatalf("below range = %v, want 0", got)
		}
	})
}

func ids(cs []Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.CVEID
	}
	return out
}

func TestRank(t *testing.T) {
	t.Run("score descending", func(t *testing.T) {
		got := Rank([]Candidate{
			{CVEID: "CVE-2020-0001", Score: 0.3},
			{CVEID: "CVE-2020-0002", Score: 0.9},
			{CVEID: "CVE-2020-0003", Score: 0.6},
		})
		want := []string{"CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0001"}
		if !reflect.DeepEqual(ids(got), want) {
			t.Fatalf("order = %v, want %v", ids(got), want)
		}
	})

	t.Run("equal scores tie-break by ascending CVE id", func(t *testing.T) {
		got := Rank([]Candidate{
			{CVEID: "CVE-2021-0002", Score: 0.5},
			{CVEID: "CVE-2019-0009", Score: 0.5},
			{CVEID: "CVE-2020-0001", Score: 0.5},
		})
		want := []string{"CVE-2019-0009", "CVE-2020-0001", "CVE-2021-0002"}
		if !reflect.DeepEqual(ids(got), want) {
			t.Fatalf("order = %v, want %v", ids(got), want)
		}
	})

	t.Run("scores equal at 6 decimals tie-break by id", func(t *testing.T) {
		// 0.5000004 and 0.5000001 both round to 0.500000, so the id decides
		// even though the lower id has the lower raw score.
		got := Rank([]Candidate{
			{CVEID: "CVE-2020-0002", Score: 0.5000004},
			{CVEID: "CVE-2020-0001", Score: 0.5000001},
		})
		want := []string{"CVE-2020-0001", "CVE-2020-0002"}
		if !reflect.DeepEqual(ids(got), want) {
			t.Fatalf("order = %v, want %v", ids(got), want)
		}
	})

	t.Run("scores differing at 6 decimals order by score", func(t *testing.T) {
		got := Rank([]Candidate{
			{CVEID: "CVE-2020-0001", Score: 0.500001},
			{CVEID: "CVE-2020-0002", Score: 0.500002},
		})
		want := []string{"CVE-2020-0002", "CVE-2020-0001"}
		if !reflect.DeepEqual(ids(got), want) {
			t.Fatalf("order = %v, want %v", ids(got), want)
		}
	})

	t.Run("deterministic regardless of input order", func(t *testing.T) {
		a := []Candidate{
			{CVEID: "CVE-2020-0003", Score: 0.4}, {CVEID: "CVE-2020-0001", Score: 0.4}, {CVEID: "CVE-2020-0002", Score: 0.8},
		}
		b := []Candidate{a[2], a[0], a[1]}
		if !reflect.DeepEqual(ids(Rank(a)), ids(Rank(b))) {
			t.Fatalf("Rank depends on input order: %v vs %v", ids(Rank(a)), ids(Rank(b)))
		}
	})

	t.Run("empty", func(t *testing.T) {
		if got := Rank(nil); len(got) != 0 {
			t.Fatalf("Rank(nil) = %v, want empty", got)
		}
	})

	t.Run("candidate with only missing signals ranks last", func(t *testing.T) {
		missing := Score(SignalsFor(Unit{RootCause: "unrelated"}, VulnDetail{CVEID: "CVE-2020-0001"}))
		strong := Score(Signals{KEV: 1})
		got := Rank([]Candidate{
			{CVEID: "CVE-2020-0001", Score: missing},
			{CVEID: "CVE-2020-0002", Score: strong},
		})
		if got[0].CVEID != "CVE-2020-0002" || missing != 0 {
			t.Fatalf("order = %v, missing score = %v", ids(got), missing)
		}
	})
}

func TestCutoff(t *testing.T) {
	cs := []Candidate{
		{CVEID: "CVE-2020-0001", Score: 0.9},
		{CVEID: "CVE-2020-0002", Score: DefaultMinRelevance},
		{CVEID: "CVE-2020-0003", Score: DefaultMinRelevance - 0.000001},
		{CVEID: "CVE-2020-0004", Score: 0},
	}

	t.Run("score equal to cutoff is kept, one below is dropped", func(t *testing.T) {
		got := Cutoff(cs, DefaultMinRelevance)
		want := []string{"CVE-2020-0001", "CVE-2020-0002"}
		if !reflect.DeepEqual(ids(got), want) {
			t.Fatalf("kept = %v, want %v", ids(got), want)
		}
	})

	t.Run("zero cutoff keeps everything", func(t *testing.T) {
		if got := Cutoff(cs, 0); len(got) != len(cs) {
			t.Fatalf("kept %d, want %d", len(got), len(cs))
		}
	})

	t.Run("all dropped", func(t *testing.T) {
		if got := Cutoff(cs, 1); len(got) != 0 {
			t.Fatalf("kept %v, want none", ids(got))
		}
	})

	t.Run("preserves order", func(t *testing.T) {
		got := Cutoff([]Candidate{
			{CVEID: "CVE-2020-0009", Score: 0.8}, {CVEID: "CVE-2020-0001", Score: 0.7},
		}, 0.5)
		want := []string{"CVE-2020-0009", "CVE-2020-0001"}
		if !reflect.DeepEqual(ids(got), want) {
			t.Fatalf("kept = %v, want %v", ids(got), want)
		}
	})
}
