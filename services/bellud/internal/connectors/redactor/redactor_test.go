package redactor

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

func TestStringAllForms(t *testing.T) {
	r := New()
	secret := "p@ss/w0rd+\"ü\n<x>"
	rel := r.Register([]byte(secret))
	j, _ := json.Marshal(secret)
	forms := []string{
		secret, string(j[1 : len(j)-1]), base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)), url.QueryEscape(secret), url.PathEscape(secret),
	}
	for _, f := range forms {
		got := r.String("a " + f + " b")
		if got != "a "+Marker+" b" {
			t.Errorf("form %q -> %q", f, got)
		}
	}
	rel()
	rel()
	if got := r.String("x " + secret); got != "x "+secret {
		t.Errorf("released secret still redacted: %q", got)
	}
}

func TestShortIgnoredAndPatterns(t *testing.T) {
	r := New()
	r.Register([]byte("short"))
	if r.String("short") != "short" {
		t.Fatal("short secret redacted")
	}
	if got := r.String("k AKIAABCDEFGHIJKLMNOP k"); strings.Contains(got, "AKIA") {
		t.Fatal(got)
	}
}

func TestJSONStaysValid(t *testing.T) {
	r := New()
	r.Register([]byte("sup3r\"secret\\value"))
	b, _ := json.Marshal(map[string]string{"m": "has sup3r\"secret\\value inside"})
	out := r.JSON(b)
	if !json.Valid(out) || strings.Contains(string(out), "sup3r") {
		t.Fatalf("%s", out)
	}
}

func TestRefCountedRelease(t *testing.T) {
	r := New()
	a := r.Register([]byte("duplicate-secret"))
	b := r.Register([]byte("duplicate-secret"))
	a()
	if r.String("duplicate-secret") != Marker {
		t.Fatal("released too early")
	}
	b()
	if r.String("duplicate-secret") == Marker {
		t.Fatal("not released")
	}
}

func TestGuard(t *testing.T) {
	r := New()
	r.Register([]byte("registered-value-123"))
	g := r.Guard(redact.New())
	b := batch.Batch{Collector: "c", Entities: []batch.Entity{{
		Type: "t", Identity: map[string]string{"id": "1"},
		Attributes: map[string]any{"note": "x registered-value-123 y"},
	}}}
	if !g.Leaks(b) {
		t.Fatal("expected leak")
	}
	if got := g.Scrub(b).Entities[0].Attributes["note"]; got != "x registered-value-123 y" {
		t.Fatalf("scrub must not remove registered values: %v", got)
	}
	clean := batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "t", Attributes: map[string]any{"n": "ok"}}}}
	if g.Leaks(clean) {
		t.Fatal("unexpected leak")
	}
	pat := batch.Batch{Collector: "c", Entities: []batch.Entity{{Type: "t", Attributes: map[string]any{"n": "AKIAABCDEFGHIJKLMNOP"}}}}
	if !g.Leaks(pat) {
		t.Fatal("base leak must propagate")
	}
}

func TestGuardRelationAttributes(t *testing.T) {
	r := New()
	r.Register([]byte("registered-value-123"))
	g := r.Guard(redact.New())
	tok := "Bearer abcdefghijklmnopqrstuvwxyz"
	b := batch.Batch{Collector: "c", Relations: []batch.Relation{{
		Type: "has", From: "a", To: "b",
		Attributes: map[string]any{"evidence": tok, "nested": []any{"x registered-value-123"}},
	}}}
	if id, ok := g.FirstLeak(b); !ok || id == "" {
		t.Fatal("expected leak in relation attributes")
	}
	out := g.Scrub(b)
	if got := out.Relations[0].Attributes["evidence"]; got != "[REDACTED:value_bearer_token]" {
		t.Fatalf("relation value not scrubbed: %v", got)
	}
	if !g.Leaks(out) {
		t.Fatal("registered value in relation attributes must still leak")
	}
	b.Relations[0].Attributes = map[string]any{"evidence": "ok"}
	if g.Leaks(b) {
		t.Fatal("unexpected leak")
	}
}
