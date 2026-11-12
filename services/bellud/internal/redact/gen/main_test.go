package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBadPatternNamesRuleAndKeepsOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bellu.yaml")
	out := filepath.Join(dir, "patterns.go")
	yaml := "redaction:\n  key_patterns:\n    - \"(?i)ok\"\n    - \"(unclosed\"\n"
	if err := os.WriteFile(in, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	existing := []byte("package redact\n// existing\n")
	if err := os.WriteFile(out, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(in, out)
	if err == nil {
		t.Fatal("expected error for bad regex")
	}
	if !strings.Contains(err.Error(), "key_unclosed") {
		t.Fatalf("error does not name rule id: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, existing) {
		t.Fatal("existing output was modified")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("stray temp files left: %d entries", len(ents))
	}
}

func TestRunReproducesCommittedPatterns(t *testing.T) {
	const real = "/home/ubuntu/bellu-ai-cyber/bellu.yaml"
	if _, err := os.Stat(real); err != nil {
		t.Skip("bellu.yaml not reachable")
	}
	out := filepath.Join(t.TempDir(), "patterns.go")
	if err := run(real, out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	want, err := os.ReadFile(filepath.Join("..", "patterns.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("generated output differs from committed patterns.go")
	}
}
