package tschild

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 8: Credential isolation (child environment)
// **Validates: Requirements 7.1, 7.2, 4.2, 4.13**
func TestPropertyChildEnvExcludesExternalPassword(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		external := "EXT-" + rapid.StringMatching(`[A-Za-z0-9_\-]{8,40}`).Draw(t, "external")
		internal := "INT-" + rapid.StringMatching(`[A-Za-z0-9_\-]{8,40}`).Draw(t, "internal")
		base := []string{"PATH=/usr/bin", "HOME=/tmp/h"}
		for _, n := range passwordEnvNames {
			base = append(base, n+"="+external)
		}
		extra := map[string]string{}
		if rapid.Bool().Draw(t, "extraPw") {
			extra["OPENCODE_SERVER_PASSWORD"] = external
		}
		s := New(Config{BaseEnv: base, Env: extra})
		env := s.buildEnv(internal)

		var pwEntries []string
		for _, kv := range env {
			if strings.Contains(kv, external) {
				t.Fatalf("external password in child env: %q", kv)
			}
			if strings.HasPrefix(kv, PasswordEnv+"=") {
				pwEntries = append(pwEntries, kv)
			}
		}
		if len(pwEntries) != 1 || pwEntries[0] != PasswordEnv+"="+internal {
			t.Fatalf("expected only internal credential, got %v", pwEntries)
		}
		for _, a := range s.cfg.Command {
			if strings.Contains(a, external) || strings.Contains(a, internal) {
				t.Fatalf("credential in child args: %v", s.cfg.Command)
			}
		}
	})
}
