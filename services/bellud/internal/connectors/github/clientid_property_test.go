package github

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: github-app-signin, Property 14: The effective client id follows the override rule
//
// For any value of BELLUCODE_GITHUB_CLIENT_ID including whitespace-only and
// padded values, EffectiveClientID returns the trimmed value when the trimmed
// value is non-empty and the compiled constant otherwise.
//
// **Validates: Requirements 4.2, 4.3**
func TestProperty14EffectiveClientIDOverride(t *testing.T) {
	ws := rapid.StringOf(rapid.SampledFrom([]rune{' ', '\t', '\n', '\r'}))
	rapid.Check(t, func(t *rapid.T) {
		var v string
		switch rapid.IntRange(0, 2).Draw(t, "kind") {
		case 0:
			v = rapid.String().Draw(t, "any")
		case 1:
			v = ws.Draw(t, "ws")
		default:
			core := rapid.StringMatching(`[A-Za-z0-9._-]{1,40}`).Draw(t, "core")
			v = ws.Draw(t, "pre") + core + ws.Draw(t, "post")
		}
		var asked string
		got := EffectiveClientID(func(k string) string {
			asked = k
			return v
		})
		if asked != EnvClientID {
			t.Fatalf("read env %q, want %q", asked, EnvClientID)
		}
		want := ClientID
		if tr := strings.TrimSpace(v); tr != "" {
			want = tr
		}
		if got != want {
			t.Fatalf("EffectiveClientID(%q) = %q, want %q", v, got, want)
		}
	})
}
