package config

import "testing"

func TestLoadSecrets(t *testing.T) {
	env := func(v string) func(string) (string, bool) {
		return func(k string) (string, bool) { return v, k == "BELLUCODE_SECRETS_HISTORY_COMMITS" }
	}
	for in, want := range map[string]int{"": 1000, "1": 1, "100000": 100000, " 5 ": 5} {
		if c, err := LoadSecrets(env(in)); err != nil || c.HistoryCommits != want {
			t.Errorf("%q: %v %v", in, c, err)
		}
	}
	for _, in := range []string{"0", "100001", "x", "-1"} {
		if _, err := LoadSecrets(env(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
