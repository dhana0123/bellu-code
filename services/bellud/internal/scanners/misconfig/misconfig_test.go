package misconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

type sink struct {
	fs   []findings.Finding
	errs []string
}

func (s *sink) Findings(f []findings.Finding) error { s.fs = append(s.fs, f...); return nil }
func (s *sink) ScannerError(in, cause string) error { s.errs = append(s.errs, in); return nil }
func (s *sink) Seen(string)                         {}
func (s *sink) Batch(batch.Batch) error             { return nil }

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFixtures(t *testing.T) {
	td := filepath.Join("..", "testdata", "iac")
	cases := []struct{ name, expected string }{
		{"terraform.tf", "terraform.tf.expected.json"},
		{"cloudformation.yaml", "cloudformation.yaml.expected.json"},
		{"kubernetes.yaml", "kubernetes.yaml.expected.json"},
		{"helm", "helm.expected.json"},
		{"Dockerfile", "Dockerfile.expected.json"},
		{"azure-arm.json", "azure-arm.json.expected.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(td, c.name)
			if fi, _ := os.Stat(src); fi.IsDir() {
				if err := os.CopyFS(filepath.Join(dir), os.DirFS(src)); err != nil {
					t.Fatal(err)
				}
			} else {
				copyFile(t, src, filepath.Join(dir, c.name))
			}
			var exp struct {
				CheckIDs []string `json:"check_ids"`
			}
			b, err := os.ReadFile(filepath.Join(td, c.expected))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &exp); err != nil {
				t.Fatal(err)
			}
			s := &sink{}
			if err := New().Run(context.Background(), scanners.Target{Type: scanners.TargetRepository, ID: "repo1", Path: dir}, s); err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, f := range s.fs {
				got[f.RuleID] = true
				if f.Type != findings.TypeMisconfiguration || f.AssetID != "repo1" || len(f.Evidence) == 0 {
					t.Errorf("bad finding %+v", f)
				}
			}
			for _, id := range exp.CheckIDs {
				if !got[id] {
					t.Errorf("missing %s; got %v", id, got)
				}
			}
		})
	}
}

func TestSkipsUnparseableAndLinks(t *testing.T) {
	td := filepath.Join("..", "testdata", "iac")
	dir := t.TempDir()
	copyFile(t, filepath.Join(td, "terraform.tf"), filepath.Join(dir, "main.tf"))
	if err := os.WriteFile(filepath.Join(dir, "broken.tf"), []byte("resource \"a\" {{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	if err := New().Run(context.Background(), scanners.Target{Type: scanners.TargetRepository, ID: "r", Path: dir}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.errs) != 1 || s.errs[0] != "broken.tf" {
		t.Fatalf("scanner errors = %v", s.errs)
	}
	if len(s.fs) == 0 {
		t.Fatal("no findings from the parseable file")
	}
	linked := 0
	for _, f := range s.fs {
		for _, e := range f.Evidence {
			if e.Kind == "entity" {
				linked++
			}
		}
	}
	if linked == 0 {
		t.Error("no finding linked to an iac_resource")
	}
	d1, _ := New().Digest(context.Background(), scanners.Target{Type: scanners.TargetRepository, Path: dir})
	d2, _ := New().Digest(context.Background(), scanners.Target{Type: scanners.TargetRepository, Path: dir})
	if d1 == "" || d1 != d2 {
		t.Errorf("digest unstable: %q %q", d1, d2)
	}
}

const customRego = `# METADATA
# title: Dockerfile must not use latest-ish alpine
# description: custom test check
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   id: USR-0001
#   avd_id: AVD-USR-0001
#   severity: HIGH
#   input:
#     selector:
#     - type: dockerfile
package user.dockerfile.USR0001

import rego.v1

deny contains res if {
	some instruction in input.Stages[_].Commands
	instruction.Cmd == "from"
	res := result.new("custom check fired", instruction)
}
`

func dockerRepo(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runCustom(t *testing.T, repo, custom string) *sink {
	t.Helper()
	s := &sink{}
	a := New().WithCustomDir(custom)
	if err := a.Run(context.Background(), scanners.Target{Type: scanners.TargetRepository, ID: "r", Path: repo}, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func ruleIDs(s *sink) map[string]findings.Finding {
	m := map[string]findings.Finding{}
	for _, f := range s.fs {
		m[f.RuleID] = f
	}
	return m
}

func TestCustomCheckFires(t *testing.T) {
	custom := t.TempDir()
	if err := os.WriteFile(filepath.Join(custom, "usr0001.rego"), []byte(customRego), 0o644); err != nil {
		t.Fatal(err)
	}
	s := runCustom(t, dockerRepo(t, "FROM alpine:3.19\nUSER root\n"), custom)
	got := ruleIDs(s)
	if _, ok := got["AVD-USR-0001"]; !ok {
		t.Fatalf("custom check did not fire: %v errs=%v", got, s.errs)
	}
	if _, ok := got["AVD-DS-0002"]; !ok {
		t.Errorf("bundled check missing: %v", got)
	}
}

func TestBadCustomCheckSkipped(t *testing.T) {
	custom := t.TempDir()
	bad := filepath.Join(custom, "bad.rego")
	if err := os.WriteFile(bad, []byte("package user.bad\n\ndeny contains x if {{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := runCustom(t, dockerRepo(t, "FROM alpine:3.19\nUSER root\n"), custom)
	if len(s.errs) != 1 || s.errs[0] != bad {
		t.Fatalf("errs = %v", s.errs)
	}
	if _, ok := ruleIDs(s)["AVD-DS-0002"]; !ok {
		t.Errorf("bundled checks did not run: %v", ruleIDs(s))
	}
}

func TestMissingCustomDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	s := runCustom(t, dockerRepo(t, "FROM alpine:3.19\nUSER root\n"), missing)
	if len(s.errs) != 1 || s.errs[0] != missing {
		t.Fatalf("errs = %v", s.errs)
	}
	if _, ok := ruleIDs(s)["AVD-DS-0002"]; !ok {
		t.Errorf("bundled checks did not run: %v", ruleIDs(s))
	}
}

func TestInlineIgnore(t *testing.T) {
	s := runCustom(t, dockerRepo(t, "FROM alpine:3.19\n#trivy:ignore:AVD-DS-0002\nUSER root\n"), "")
	f, ok := ruleIDs(s)["AVD-DS-0002"]
	if !ok {
		t.Fatalf("no finding for ignored check: %v", ruleIDs(s))
	}
	if f.Status != findings.StatusIgnored || f.IgnoreReason != "inline" {
		t.Errorf("status=%s reason=%q", f.Status, f.IgnoreReason)
	}
}
