package syncgraph

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 2: No leftover upstream names
// **Validates: Requirements 9.1, 9.2, 9.3, 9.4**

// loWord draws a "toise" token: canonical spellings the rename map covers, or
// arbitrary per-letter casing that it may not cover.
func loWord(t *rapid.T, label string) string {
	if rapid.Bool().Draw(t, label+"-canonical") {
		return rapid.SampledFrom([]string{
			"Toise", "toise", "TOISE", "TOISE_ADDR", "toise_events", "toise://graph/x", "toise.v1",
		}).Draw(t, label+"-word")
	}
	mask := rapid.SliceOfN(rapid.Bool(), 5, 5).Draw(t, label+"-mask")
	var b strings.Builder
	for i, c := range "toise" {
		if mask[i] {
			c -= 'a' - 'A'
		}
		b.WriteRune(c)
	}
	return b.String() + rapid.SampledFrom([]string{"", "_x", "://p"}).Draw(t, label+"-suffix")
}

func loSegment(t *rapid.T, label string) string {
	base := rapid.StringMatching(`[a-z]{1,6}`).Draw(t, label+"-base")
	if rapid.Bool().Draw(t, label+"-has") {
		return base + loWord(t, label)
	}
	return base
}

func loTree(t *rapid.T) map[string]string {
	files := map[string]string{"LICENSE": "Apache License 2.0\n"}
	n := rapid.IntRange(1, 6).Draw(t, "nfiles")
	for i := 0; i < n; i++ {
		l := "f" + string(rune('a'+i))
		dir := loSegment(t, l+"-dir")
		name := loSegment(t, l+"-name")
		ext := rapid.SampledFrom([]string{".go", ".md", ".txt", ".yaml"}).Draw(t, l+"-ext")
		var lines []string
		if ext == ".go" {
			lines = append(lines, "package p")
		}
		for j := 0; j < rapid.IntRange(0, 4).Draw(t, l+"-nlines"); j++ {
			lines = append(lines, "x "+loWord(t, l+"-w")+" y")
		}
		files[dir+"/"+name+ext] = strings.Join(lines, "\n") + "\n"
	}
	return files
}

func TestLeftoverNamesProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		files := loTree(rt)
		src := writeTree(t, files)
		parent := t.TempDir()
		out := filepath.Join(parent, "out")
		if err := os.MkdirAll(out, 0o755); err != nil {
			rt.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "sentinel.txt"), []byte("keep"), 0o644); err != nil {
			rt.Fatal(err)
		}
		before := snapshot(t, out)

		err := Sync(opts(t, src, out))
		if err == nil {
			if left := Scan(out); len(left) != 0 {
				rt.Fatalf("leftovers after successful sync: %v", left)
			}
			for rel, content := range snapshot(t, out) {
				if rel == "NOTICE" || rel == "UPSTREAM.md" {
					continue
				}
				if strings.Contains(strings.ToLower(rel), "toise") {
					rt.Fatalf("toise in path %s", rel)
				}
				for _, l := range strings.Split(content, "\n") {
					if strings.Contains(strings.ToLower(l), "toise") && !isAttribution(l) {
						rt.Fatalf("toise in %s: %q", rel, l)
					}
				}
			}
			return
		}
		// The tool may refuse inputs the rename map does not cover; then Out must be untouched.
		var se *StepError
		if !errors.As(err, &se) || se.Step != "leftover-scan" {
			rt.Fatalf("unexpected failure: %v", err)
		}
		if after := snapshot(t, out); !reflect.DeepEqual(before, after) {
			rt.Fatalf("Out modified by failed sync: %v -> %v", before, after)
		}
	})
}

func TestLeftoverCanonicalCasesSync(t *testing.T) {
	src := writeTree(t, map[string]string{
		"LICENSE":                "Apache\n",
		"pkg/toise_x/a.go":       "package a\n\nconst A = \"Toise toise TOISE TOISE_ADDR toise_events toise://g\"\n",
		"proto/toise/v1/e.proto": "package toise.v1;\n",
	})
	out := filepath.Join(t.TempDir(), "out")
	if err := Sync(opts(t, src, out)); err != nil {
		t.Fatal(err)
	}
	if left := Scan(out); len(left) != 0 {
		t.Fatalf("leftovers: %v", left)
	}
}

func TestLeftoverVendoredTreeIsClean(t *testing.T) {
	root := filepath.Join("..", "bellugraph")
	if _, err := os.Stat(root); err != nil {
		t.Skip("vendored tree not present")
	}
	if left := Scan(root); len(left) != 0 {
		t.Fatalf("vendored tree has %d leftover(s), first: %v", len(left), left[:min(len(left), 10)])
	}
}
