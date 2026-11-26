package aiinv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

type sink struct {
	errs    []string
	batches []batch.Batch
}

func (s *sink) Findings([]findings.Finding) error { return nil }
func (s *sink) ScannerError(in, c string) error   { s.errs = append(s.errs, in+": "+c); return nil }
func (s *sink) Seen(string)                       {}
func (s *sink) Batch(b batch.Batch) error         { s.batches = append(s.batches, b); return nil }

func write(t *testing.T, p, c string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	repo, user := t.TempDir(), t.TempDir()
	write(t, filepath.Join(repo, "app/agent.py"), "@tool\ndef search(q):\n  pass\nagent = AgentExecutor(a)\n")
	write(t, filepath.Join(repo, "lone.py"), "x = create_react_agent(m)\n")
	write(t, filepath.Join(repo, "models/m.gguf"), "x")
	write(t, filepath.Join(user, "bad.yaml"), "signatures:\n  - {id: broken, kind: ai_agent, files: ['*.py'], pattern: '('}\n  - {id: mine, kind: ai_tool, files: ['*.py'], pattern: 'MYTOOL'}\n")
	write(t, filepath.Join(repo, "my.py"), "MYTOOL\n")
	tg := scanners.Target{Type: scanners.TargetRepository, ID: "r1", Path: repo}
	a := New(user)
	var first int
	for i := 0; i < 2; i++ {
		s := &sink{}
		if err := a.Run(context.Background(), tg, s); err != nil {
			t.Fatal(err)
		}
		if len(s.errs) != 1 || s.errs[0][:len(user)] != user {
			t.Fatalf("errs %v", s.errs)
		}
		b := s.batches[0]
		ids := map[string]bool{}
		unresolved, hasTool := 0, 0
		for _, e := range b.Entities {
			if e.Type == "repository" {
				continue
			}
			if ids[e.Type+e.Identity["id"]] {
				t.Fatal("duplicate entity")
			}
			ids[e.Type+e.Identity["id"]] = true
			if e.Attributes["repo"] != "r1" || e.Attributes["path"] == nil || e.Attributes["line"] == nil {
				t.Fatalf("attrs %v", e.Attributes)
			}
			if e.Attributes[LinkUnresolved] != nil {
				unresolved++
			}
		}
		for _, r := range b.Relations {
			if r.Type == "ai_has_tool" {
				hasTool++
			}
		}
		if unresolved != 1 || hasTool == 0 {
			t.Fatalf("unresolved=%d hasTool=%d", unresolved, hasTool)
		}
		if i == 0 {
			first = len(b.Entities)
		} else if first != len(b.Entities) {
			t.Fatal("entity count changed")
		}
	}
	if first != 6 { // repository, tool search, agent, lone agent, model, mine
		t.Fatalf("entities %d", first)
	}
}

func TestRuleAttributes(t *testing.T) {
	repo := t.TempDir()
	write(t, filepath.Join(repo, "a.py"), "@tool\ndef delete_user(q):\n  pass\nx = input()\nagent = AgentExecutor(a)\n")
	write(t, filepath.Join(repo, "m.pt"), "x")
	s := &sink{}
	if err := New(t.TempDir()).Run(context.Background(), scanners.Target{Type: scanners.TargetRepository, ID: "r", Path: repo}, s); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range s.batches[0].Entities {
		switch e.Type {
		case "ai_agent":
			seen++
			if e.Attributes["has_write_tool"] != "true" || e.Attributes["external_input"] != "true" || e.Attributes["input_validated"] != "false" {
				t.Fatalf("agent attrs %v", e.Attributes)
			}
		case "ai_model":
			seen++
			if e.Attributes["serialization_format"] != "pt" {
				t.Fatalf("model attrs %v", e.Attributes)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("seen %d", seen)
	}
}
