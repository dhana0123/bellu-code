package github

import (
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
)

// Feature: cloud-connectors, Property 22: GitHub token prefix
//
// For any submitted token, it is accepted only if it starts with github_pat_
// followed by a non-empty remainder; otherwise the error states classic tokens
// are unsupported and never contains the token.
//
// **Validates: Requirements 4.2**
func TestProperty22GitHubTokenPrefix(t *testing.T) {
	p := NewProvider(ProviderConfig{})
	rapid.Check(t, func(t *rapid.T) {
		var tok string
		switch rapid.IntRange(0, 3).Draw(t, "kind") {
		case 0: // valid prefix plus non-empty rest
			tok = PATPrefix + rapid.StringN(1, 200, -1).Draw(t, "rest")
		case 1: // prefix only
			tok = PATPrefix
		case 2: // arbitrary string, with a distinctive marker so leaks are detectable
			tok = rapid.String().Draw(t, "any")
		default: // near misses: classic prefixes, whitespace, wrong case, truncated prefix
			pre := rapid.SampledFrom([]string{"ghp_", "gho_", " github_pat_", "GITHUB_PAT_", "github_pat", "github_pa", "\ngithub_pat_", ""}).Draw(t, "pre")
			tok = pre + rapid.StringN(1, 100, -1).Draw(t, "tail")
		}
		want := strings.HasPrefix(tok, PATPrefix) && len(tok) > len(PATPrefix)

		for name, err := range map[string]error{
			"ValidateToken":      ValidateToken([]byte(tok)),
			"ValidateCredential": p.ValidateCredential([]byte(tok)),
		} {
			if want {
				if err != nil {
					t.Fatalf("%s rejected valid token: %v", name, err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("%s accepted %q", name, tok)
			}
			msg := err.Error()
			var le *lifecycle.Error
			if errors.As(err, &le) {
				if le.Code != lifecycle.CodeValidationFailed {
					t.Fatalf("%s code=%v", name, le.Code)
				}
				msg += "|" + le.Message
			} else if name == "ValidateToken" && !errors.Is(err, ErrClassicToken) {
				t.Fatalf("%s unexpected error %v", name, err)
			}
			if !strings.Contains(msg, "Classic tokens are not supported") {
				t.Fatalf("%s message does not state classic tokens unsupported: %q", name, msg)
			}
			// Only meaningful for tokens long enough to be distinguishable from
			// the fixed message text.
			if len(tok) >= 4 && strings.Contains(msg, tok) {
				t.Fatalf("%s message contains the token", name)
			}
		}
	})
}
