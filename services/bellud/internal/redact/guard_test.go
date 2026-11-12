package redact

import (
	"reflect"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

func sample() batch.Batch {
	return batch.Batch{
		Collector: "git",
		Entities: []batch.Entity{{
			Type:     "repo",
			Identity: map[string]string{"name": "r"},
			Attributes: map[string]any{
				"note":        "key AKIAABCDEFGHIJKLMNOP end",
				"api_key":     "hunter2",
				"count":       3,
				"environment": map[string]any{"variables": map[string]any{"A": "b"}, "other": "ok"},
				"nested":      []any{"ghp_" + strings.Repeat("a", 36), map[string]any{"password": "x"}},
			},
		}},
		Relations: []batch.Relation{{Type: "has", From: "a", To: "b", Attributes: map[string]any{"t": "Bearer abcdefghijklmnopqrstuvwxyz"}}},
	}
}

func TestScrub(t *testing.T) {
	g := New()
	in := sample()
	orig := sample()
	out := g.Scrub(in)
	if !reflect.DeepEqual(in, orig) {
		t.Fatal("input mutated")
	}
	a := out.Entities[0].Attributes
	if a["note"] != "key [REDACTED:value_aws_access_key] end" || a["api_key"] != "[REDACTED:key_api_key]" || a["count"] != 3 {
		t.Fatalf("bad scrub: %v", a)
	}
	env := a["environment"].(map[string]any)
	if env["variables"] != "[REDACTED:path_environment_variables]" || env["other"] != "ok" {
		t.Fatalf("path rule: %v", env)
	}
	n := a["nested"].([]any)
	if n[0] != "[REDACTED:value_github_token]" || n[1].(map[string]any)["password"] != "[REDACTED:key_password]" {
		t.Fatalf("nested: %v", n)
	}
	if out.Relations[0].Attributes["t"] != "[REDACTED:value_bearer_token]" {
		t.Fatal("relation not scrubbed")
	}
	if !reflect.DeepEqual(out.Entities[0].Identity, in.Entities[0].Identity) || len(out.Entities) != 1 {
		t.Fatal("structure changed")
	}
	if !reflect.DeepEqual(g.Scrub(out), out) {
		t.Fatal("not idempotent")
	}
	if g.Leaks(out) {
		t.Fatal("leak after scrub")
	}
	if id, ok := g.FirstLeak(in); !ok || id == "" {
		t.Fatal("expected leak in raw input")
	}
}

func TestIdentityLeak(t *testing.T) {
	g := New()
	b := batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "t", Identity: map[string]string{"k": "AKIAABCDEFGHIJKLMNOP"}}}}
	out := g.Scrub(b)
	if out.Entities[0].Identity["k"] != "AKIAABCDEFGHIJKLMNOP" {
		t.Fatal("identity changed")
	}
	if id, ok := g.FirstLeak(out); !ok || id != "value_aws_access_key" {
		t.Fatalf("got %q %v", id, ok)
	}
}

func TestPrivateKeyHeader(t *testing.T) {
	g := New()
	b := batch.Batch{Entities: []batch.Entity{{Attributes: map[string]any{"x": "-----BEGIN RSA PRIVATE KEY-----\nabc"}}}}
	out := g.Scrub(b)
	if g.Leaks(out) || !strings.Contains(out.Entities[0].Attributes["x"].(string), "[REDACTED:value_private_key_header]") {
		t.Fatal("private key not scrubbed")
	}
}
