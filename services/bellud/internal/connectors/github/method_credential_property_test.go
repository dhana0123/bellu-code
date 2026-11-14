package github

import (
	"strings"
	"testing"
	"unicode"

	"pgregory.net/rapid"
)

// Feature: github-app-signin, Property 33: Token prefix validation depends on the method
//
// For any byte string, ValidateCredentialFor("pat", s) accepts it iff it starts
// with github_pat_ and has more characters, and ValidateCredentialFor("device", s)
// accepts it iff it starts with ghu_, has more characters and has no whitespace.
//
// **Validates: Requirements 11.2**
func TestProperty33TokenPrefixByMethod(t *testing.T) {
	p := NewProvider(ProviderConfig{})
	spaces := []string{" ", "\t", "\n", "\r", "\v", "\f", "\u0085", "\u00a0", "\u1680", "\u2003", "\u3000"}
	rapid.Check(t, func(t *rapid.T) {
		var s string
		switch rapid.IntRange(0, 4).Draw(t, "kind") {
		case 0:
			s = PATPrefix + rapid.StringN(1, 100, -1).Draw(t, "rest")
		case 1:
			s = UserTokenPrefix + rapid.StringN(1, 100, -1).Draw(t, "rest")
		case 2: // ghu_ token with embedded whitespace
			a := rapid.StringMatching(`[A-Za-z0-9_]{0,20}`).Draw(t, "a")
			b := rapid.StringMatching(`[A-Za-z0-9_]{0,20}`).Draw(t, "b")
			s = UserTokenPrefix + a + rapid.SampledFrom(spaces).Draw(t, "ws") + b
		case 3: // near misses and bare prefixes
			pre := rapid.SampledFrom([]string{PATPrefix, UserTokenPrefix, "ghp_", "gho_", " ghu_", " github_pat_", "GHU_", "ghu", ""}).Draw(t, "pre")
			s = pre + rapid.StringMatching(`[A-Za-z0-9_]{0,10}`).Draw(t, "tail")
		default:
			s = rapid.String().Draw(t, "any")
		}

		wantPAT := strings.HasPrefix(s, PATPrefix) && len(s) > len(PATPrefix)
		wantDevice := strings.HasPrefix(s, UserTokenPrefix) && len(s) > len(UserTokenPrefix) &&
			strings.IndexFunc(s, unicode.IsSpace) < 0

		if got := p.ValidateCredentialFor("pat", []byte(s)) == nil; got != wantPAT {
			t.Fatalf("pat %q: accepted=%v want %v", s, got, wantPAT)
		}
		if got := p.ValidateCredentialFor("device", []byte(s)) == nil; got != wantDevice {
			t.Fatalf("device %q: accepted=%v want %v", s, got, wantDevice)
		}
	})
}
