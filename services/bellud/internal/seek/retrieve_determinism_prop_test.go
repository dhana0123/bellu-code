package seek_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/seek"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
	"pgregory.net/rapid"
)

// rtDetCWEs are the CWE ids with fixtures, plus one unknown id.
var rtDetCWEs = []string{
	"CWE-79", "CWE-80", "CWE-81", "CWE-89", "CWE-700", "CWE-710",
	"CWE-720", "CWE-730", "CWE-800", "CWE-999",
}

var rtDetWords = []string{
	"cross-site", "scripting", "comment", "renderer", "title", "parameter", "profile",
	"script", "injection", "search", "SQL", "username", "integer", "wraparound",
	"allocator", "heap", "overflow", "parser", "buffer", "length", "candidate",
}

// rtDetPaths are the URL paths that get a jittered delay in each run.
func rtDetPaths() []string {
	var paths []string
	for _, c := range rtDetCWEs {
		paths = append(paths, "/v1/weaknesses/"+c, "/v1/weaknesses/"+c+"/vulnerabilities")
	}
	paths = append(paths, "/v1/graph/neighborhood")
	for _, id := range []string{"2021-0001", "2021-0002", "2022-0003", "2023-0702", "2024-1000", "2024-1050", "2024-1100"} {
		paths = append(paths, "/v1/vulnerabilities/CVE-"+id)
	}
	return paths
}

// Feature: bellu-seek-planner, Property 11: Determinism
//
// **Validates: Requirements 6.11, 12.5**
func TestPropRetrieveDeterministic(t *testing.T) {
	fake := seektest.New(t)
	r, _ := rtRetriever(t, fake.URL, rtConfig(2*time.Second, 10*time.Second))
	paths := rtDetPaths()

	text := rapid.Custom(func(t *rapid.T) string {
		words := rapid.SliceOfN(rapid.SampledFrom(rtDetWords), 1, 8).Draw(t, "words")
		return fmt.Sprint(words)
	})
	unit := rapid.Custom(func(t *rapid.T) seek.Unit {
		return seek.Unit{
			CWEID:     rapid.SampledFrom(rtDetCWEs).Draw(t, "cwe"),
			RootCause: text.Draw(t, "root_cause"),
			Snippet:   text.Draw(t, "snippet"),
		}
	})

	// rapid runs 100 generated cases by default.
	rapid.Check(t, func(t *rapid.T) {
		plan := seek.Plan{
			Language:   "go",
			Reasoning:  "r",
			Weaknesses: rapid.SliceOfN(unit, 0, seek.MaxWeaknesses).Draw(t, "units"),
		}
		topK := rapid.IntRange(seek.MinTopK, seek.MaxTopK).Draw(t, "topK")
		runs := rapid.IntRange(2, 3).Draw(t, "runs")

		var first []byte
		for i := 0; i < runs; i++ {
			// A different response timing for every run.
			fake.Clear()
			for _, p := range paths {
				d := rapid.IntRange(0, 3).Draw(t, "delay_ms")
				if d > 0 {
					fake.Inject(p, seektest.Rule{Delay: time.Duration(d) * time.Millisecond})
				}
			}
			body, err := json.Marshal(r.Run(context.Background(), plan, topK))
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				first = body
				continue
			}
			if string(body) != string(first) {
				t.Fatalf("run %d differs from run 0:\n%s\n%s", i, first, body)
			}
		}
	})
}
