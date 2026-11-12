package syncgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/rename"
)

// Feature: go-server-bellu-graph, Property 1: Rename idempotence and determinism.
// **Validates: Requirements 8.4, 8.5, 8.6, 8.7, 8.8**

var rpTokens = []string{
	"Toise", "toise", "TOISE", "toised", "TOISE_ADDR", "toise_events", "toise://x", "toise.v1",
	"github.com/toise-dev/toise", "github.com/toise-dev/toise/internal/store", "proto/toise/v1",
	"\"Toise engine\"", "store", "foo", "bar", "BelluGraph", "bellugraph", "Bellu Graph Engine", "42",
}

var rpSeps = []string{" ", "\n", "\r\n", "/", "_", "-", ".", "\t", ""}

var rpSegments = []string{"store", "toise", "Toise", "api", "cmd", "pkg", "x1"}

var rpExts = []string{".go", ".md", ".txt", ".yaml", ".json", ".sh", ".proto", ".html", ""}

func rpText() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		n := rapid.IntRange(0, 12).Draw(t, "n")
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(rapid.SampledFrom(rpTokens).Draw(t, "tok"))
			b.WriteString(rapid.SampledFrom(rpSeps).Draw(t, "sep"))
		}
		return b.String()
	})
}

func rpPath() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		n := rapid.IntRange(1, 3).Draw(t, "depth")
		parts := make([]string, n)
		for i := range parts {
			parts[i] = rapid.SampledFrom(rpSegments).Draw(t, "seg")
		}
		return strings.Join(parts, "/") + rapid.SampledFrom(rpExts).Draw(t, "ext")
	})
}

func rpMap(t testing.TB) *rename.Map {
	t.Helper()
	p, err := filepath.Abs("../../script/rename.map.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := rename.LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func rpTree() *rapid.Generator[map[string]string] {
	return rapid.Custom(func(t *rapid.T) map[string]string {
		tree := map[string]string{"LICENSE": "Apache License\r\nVersion 2.0\r\n"}
		n := rapid.IntRange(0, 6).Draw(t, "files")
		for i := 0; i < n; i++ {
			p := rpPath().Draw(t, "path")
			// keep file/dir names consistent: a path can't be both file and dir
			ok := true
			for q := range tree {
				if strings.HasPrefix(q, p+"/") || strings.HasPrefix(p, q+"/") || q == p {
					ok = false
				}
			}
			if ok {
				tree[p] = rpText().Draw(t, "content")
			}
		}
		return tree
	})
}

func rpWrite(t *rapid.T, root string, files map[string]string) {
	for k, v := range files {
		p := filepath.Join(root, filepath.FromSlash(k))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func rpSnap(t *rapid.T, root string) map[string]string {
	m := map[string]string{}
	err := filepath.Walk(root, func(p string, i os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !i.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			m[rel] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPropertyRenameSyncDeterministic(t *testing.T) {
	mp, _ := filepath.Abs("../../script/rename.map.yaml")
	rapid.Check(t, func(t *rapid.T) {
		tree := rpTree().Draw(t, "tree")
		base, err := os.MkdirTemp("", "rp-sync-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(base)
		src := filepath.Join(base, "src")
		rpWrite(t, src, tree)
		opt := func(out string) Options {
			return Options{Commit: sha, Out: out, MapPath: mp, SumPath: filepath.Join(base, "sum"), SrcDir: src, Regen: RegenSkip}
		}
		outA := filepath.Join(base, "a", "bellugraph")
		outB := filepath.Join(base, "b", "bellugraph")
		if err := Sync(opt(outA)); err != nil {
			t.Fatalf("sync A: %v", err)
		}
		first := rpSnap(t, outA)
		if err := Sync(opt(outA)); err != nil { // same Out, twice
			t.Fatalf("sync A again: %v", err)
		}
		if err := Sync(opt(outB)); err != nil { // fresh Out
			t.Fatalf("sync B: %v", err)
		}
		second, other := rpSnap(t, outA), rpSnap(t, outB)
		for name, got := range map[string]map[string]string{"re-sync": second, "fresh": other} {
			if len(got) != len(first) {
				t.Fatalf("%s: file lists differ: %d vs %d", name, len(got), len(first))
			}
			for k, v := range first {
				if got[k] != v {
					t.Fatalf("%s: %s differs", name, k)
				}
			}
		}
		if len(Scan(outA)) != 0 {
			t.Fatalf("leftover: %v", Scan(outA))
		}
		if first["LICENSE"] != tree["LICENSE"] {
			t.Fatalf("LICENSE not byte-identical")
		}
		for k, v := range first {
			if strings.Contains(v, "\r") && k != "LICENSE" {
				t.Fatalf("%s retains CR", k)
			}
		}
	})
}

func TestPropertyRenameMapIdempotent(t *testing.T) {
	m := rpMap(t)
	rapid.Check(t, func(t *rapid.T) {
		text := rpText().Draw(t, "text")
		p := rpPath().Draw(t, "path")
		once := string(m.ApplyText(p, []byte(text)))
		twice := string(m.ApplyText(p, []byte(once)))
		if once != twice {
			t.Fatalf("ApplyText not idempotent for %q:\n once=%q\ntwice=%q", p, once, twice)
		}
		po := m.ApplyPath(p)
		if pt := m.ApplyPath(po); po != pt {
			t.Fatalf("ApplyPath not idempotent: %q -> %q -> %q", p, po, pt)
		}
		// the line-wise engine used by Sync is idempotent too
		r1 := renameContent(m, p, []byte(text))
		if r2 := renameContent(m, p, r1); string(r1) != string(r2) {
			t.Fatalf("renameContent not idempotent for %q", p)
		}
	})
}

func TestPropertyValidateRejectsChainedRules(t *testing.T) {
	word := rapid.StringMatching(`[a-z]{1,6}`)
	kind := rapid.SampledFrom([]string{rename.KindIdentifier, rename.KindText, rename.KindPath})
	rapid.Check(t, func(t *rapid.T) {
		k := kind.Draw(t, "kind")
		mid := word.Draw(t, "mid")
		pre, suf := word.Draw(t, "pre"), word.Draw(t, "suf")
		// a's output contains b's input, so a -> b is a chain
		a := rename.Rule{Kind: k, From: "Q" + word.Draw(t, "a"), To: pre + mid + suf}
		b := rename.Rule{Kind: k, From: mid, To: "Z" + word.Draw(t, "b")}
		chain := []rename.Rule{a, b}
		if rapid.Bool().Draw(t, "swap") { // order of listing must not matter
			chain = []rename.Rule{b, a}
		}
		if err := rename.Validate(chain); err == nil {
			t.Fatalf("chained rules accepted: %+v", chain)
		}
		// without the chain the same shape is accepted
		ok := []rename.Rule{a, {Kind: k, From: "Y" + mid, To: "Z" + suf}}
		if err := rename.Validate(ok); err != nil {
			t.Fatalf("independent rules rejected: %v", err)
		}
	})
}
