package secretscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

const corpus = "../testdata/secrets"

type sink struct {
	fs   []findings.Finding
	errs []string
}

func (s *sink) Findings(f []findings.Finding) error { s.fs = append(s.fs, f...); return nil }
func (s *sink) ScannerError(in, c string) error     { s.errs = append(s.errs, in+": "+c); return nil }
func (s *sink) Seen(string)                         {}
func (s *sink) Batch(batch.Batch) error             { return nil }

type expectation map[string][]struct {
	Rule string `json:"rule"`
	Line int    `json:"line"`
}

func loadExpected(t *testing.T) expectation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpus, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m expectation
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func run(t *testing.T, o Options) *sink {
	t.Helper()
	s := &sink{}
	a := NewAdapter(o)
	if err := a.Run(context.Background(), scanners.Target{Type: scanners.TargetRepository, ID: "repo1", Path: corpus}, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCorpusDetection(t *testing.T) {
	s := run(t, Options{WorkspaceDir: t.TempDir()})
	got := map[string]bool{}
	for _, f := range s.fs {
		if f.Type != findings.TypeSecret || string(f.Category) != "secrets" || f.AssetID != "repo1" {
			t.Fatalf("bad finding %+v", f)
		}
		want, _ := findings.MapSeverity("gitleaks", f.RuleID)
		if f.Severity != want {
			t.Fatalf("severity %s for %s", f.Severity, f.RuleID)
		}
		ev := f.Evidence[0]
		got[fmt.Sprintf("%s|%s|%d", ev.Ref, f.RuleID, ev.Line)] = true
	}
	for file, hits := range loadExpected(t) {
		for _, h := range hits {
			if k := fmt.Sprintf("%s|%s|%d", file, h.Rule, h.Line); !got[k] {
				t.Errorf("missing %s in %v", k, got)
			}
		}
		if len(hits) == 0 {
			for k := range got {
				if strings.HasPrefix(k, file+"|") {
					t.Errorf("clean file flagged: %s", k)
				}
			}
		}
	}
}

func TestNoSecretValueAnywhere(t *testing.T) {
	s := run(t, Options{WorkspaceDir: t.TempDir()})
	eng, _ := New(Options{})
	dump := fmt.Sprintf("%#v", s.fs) + strings.Join(s.errs, "\n")
	n := 0
	for file, hits := range loadExpected(t) {
		if len(hits) == 0 {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(corpus, file))
		for _, h := range eng.det.DetectString(string(b)) {
			n++
			if v := h.Secret; len(v) >= 8 && strings.Contains(dump, v) {
				t.Fatalf("output contains secret from %s", file)
			}
		}
	}
	if n == 0 {
		t.Fatal("no secrets re-detected")
	}
}

func TestFingerprintStableAndPrefix(t *testing.T) {
	dir := t.TempDir()
	a, b := run(t, Options{WorkspaceDir: dir}), run(t, Options{WorkspaceDir: dir})
	if len(a.fs) == 0 || len(a.fs) != len(b.fs) {
		t.Fatalf("counts %d %d", len(a.fs), len(b.fs))
	}
	for i := range a.fs {
		if a.fs[i].ID != b.fs[i].ID || string(a.fs[i].Details) != string(b.fs[i].Details) {
			t.Fatal("finding not stable across scans")
		}
		var d struct{ Prefix, Fingerprint string }
		_ = json.Unmarshal(a.fs[i].Details, &d)
		if len(d.Fingerprint) != 64 || len(d.Prefix) > 4 {
			t.Fatalf("bad details %s", a.fs[i].Details)
		}
	}
	e1, _ := New(Options{WorkspaceDir: dir})
	e2, _ := New(Options{WorkspaceDir: t.TempDir()})
	if e1.Fingerprint("v") == e2.Fingerprint("v") {
		t.Fatal("salt not per workspace")
	}
	if Prefix("short-value") != "" || Prefix("abcdefghijkl") != "abcd" {
		t.Fatal("prefix rule")
	}
}

func TestBadCustomConfigFailsBeforeScan(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.toml")
	os.WriteFile(bad, []byte("[[rules]\nid = "), 0o600)
	for _, p := range []string{bad, filepath.Join(dir, "missing.toml")} {
		s := &sink{}
		err := NewAdapter(Options{ConfigPath: p}).Run(context.Background(),
			scanners.Target{Type: scanners.TargetRepository, ID: "r", Path: corpus}, s)
		if err == nil || !strings.Contains(err.Error(), p) || len(s.fs) != 0 {
			t.Fatalf("want error naming %s, got %v", p, err)
		}
	}
}
