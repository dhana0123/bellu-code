package codesec

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, i os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if i.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		d, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), d, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) string {
	root := t.TempDir()
	copyTree(t, "testdata/repo", root)
	// .git cannot live in testdata; create it at test time.
	os.MkdirAll(filepath.Join(root, ".git"), 0o755)
	os.WriteFile(filepath.Join(root, ".git", "package.json"), []byte(`{"dependencies":{"ignored2":"1"}}`), 0o644)
	return root
}

func index(b []batch.Entity, typ string) map[string]batch.Entity {
	m := map[string]batch.Entity{}
	for _, e := range b {
		if e.Type == typ {
			k := ""
			for _, f := range []string{"name", "range", "path"} {
				k += e.Identity[f] + "|"
			}
			m[k] = e
		}
	}
	return m
}

func TestCollectFixture(t *testing.T) {
	root := fixture(t)
	c := New(root)
	b, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deps := map[string]bool{}
	for _, e := range b.Entities {
		if e.Type == "dependency" {
			deps[e.Identity["name"]+"@"+e.Identity["range"]] = true
		}
	}
	for _, want := range []string{
		"left-pad@^1.3.0", "vitest@~2.0.0", "left-pad@1.3.0", "@scope/pkg@2.1.0",
		"github.com/a/b@v1.2.3", "github.com/c/d@v0.4.0", "github.com/e/f@v1.0.0",
		"requests@>=2.31,<3", "flask@==3.0.0", "numpy@*",
	} {
		if !deps[want] {
			t.Errorf("missing dependency %s; have %v", want, deps)
		}
	}
	if deps["ignored@1"] || deps["ignored2@1"] {
		t.Error("node_modules/.git must be skipped")
	}
	if len(deps) != 10 {
		t.Errorf("deps=%d want 10: %v", len(deps), deps)
	}

	wf := index(b.Entities, "workflow")
	if len(wf) != 1 {
		t.Fatalf("workflows=%d", len(wf))
	}
	for _, w := range wf {
		a := w.Attributes
		if a["name"] != "CI" || a["triggers"] != "pull_request_target,push" ||
			a["permissions"] != "contents:read" || a["job_permissions"] != "build=id-token:write" ||
			a["pull_request_target"] != true ||
			a["uses"] != "actions/checkout@v4,org/repo/.github/workflows/x.yml@main" {
			t.Errorf("workflow attrs: %v", a)
		}
	}
	secrets := map[string]bool{}
	for _, e := range b.Entities {
		if e.Type == "secret_ref" {
			secrets[e.Identity["name"]] = true
		}
	}
	if len(secrets) != 3 || !secrets["DEPLOY_TOKEN"] || !secrets["API_KEY"] || !secrets["FALLBACK"] {
		t.Errorf("secrets: %v", secrets)
	}

	// Relations: attribute-free, endpoints in batch, expected types.
	ids := map[string]bool{}
	for _, e := range b.Entities {
		h, _ := identity.Hash(e.Type, e.Identity)
		ids[string(h)] = true
	}
	counts := map[string]int{}
	for _, r := range b.Relations {
		if len(r.Attributes) != 0 || !ids[r.From] || !ids[r.To] {
			t.Errorf("bad relation %+v", r)
		}
		counts[r.Type]++
	}
	if counts["declared_in"] != 10 || counts["depends_on"] != 10 || counts["defined_in"] != 1 || counts["used_by"] != 3 {
		t.Errorf("relation counts: %v", counts)
	}
}

func TestSkipsLargeFiles(t *testing.T) {
	root := t.TempDir()
	big := make([]byte, MaxFileSize+1)
	copy(big, `{"dependencies":{"huge":"1"}}`)
	os.WriteFile(filepath.Join(root, "package.json"), big, 0o644)
	b, _ := New(root).Collect(context.Background())
	for _, e := range b.Entities {
		if e.Type == "dependency" {
			t.Fatal("large file must be skipped")
		}
	}
}

func TestRescanOnChange(t *testing.T) {
	root := fixture(t)
	c := New(root)
	b1, _ := c.Collect(context.Background())
	b2, _ := c.Collect(context.Background())
	if !b1.ObservedAt.Equal(b2.ObservedAt) {
		t.Error("unchanged tree should return cached observation")
	}
	if c.Interval() > 5*time.Second {
		t.Error("interval must be <= 5s")
	}
	p := filepath.Join(root, "package.json")
	os.WriteFile(p, []byte(`{"dependencies":{"new-dep":"9"}}`), 0o644)
	os.Chtimes(p, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	b3, _ := c.Collect(context.Background())
	found := false
	for _, e := range b3.Entities {
		if e.Type == "dependency" && e.Identity["name"] == "new-dep" {
			found = true
		}
	}
	if !found {
		t.Error("change not picked up")
	}
}

func TestStripJSONC(t *testing.T) {
	got := string(stripJSONC([]byte(`{"a":"x,}", // c
 "b":[1,2,],}`)))
	if got != "{\"a\":\"x,}\", \n \"b\":[1,2]}" {
		t.Errorf("got %q", got)
	}
}
