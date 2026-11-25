package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Defaults and bounds for secrets.history_commits.
const (
	DefaultSecretsHistoryCommits = 1000
	MinSecretsHistoryCommits     = 1
	MaxSecretsHistoryCommits     = 100000
)

// Secrets holds the secrets.* configuration keys, read from BELLUCODE_SECRETS_*.
type Secrets struct {
	// HistoryCommits is secrets.history_commits: the commits scanned per ref
	// in git history, 1 to 100000, default 1000.
	HistoryCommits int
}

// LoadSecrets reads and validates the secrets.* keys through env. An empty
// value counts as unset.
func LoadSecrets(env func(string) (string, bool)) (Secrets, error) {
	c := Secrets{HistoryCommits: DefaultSecretsHistoryCommits}
	v, _ := env(envName("secrets.history_commits"))
	if v = strings.TrimSpace(v); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < MinSecretsHistoryCommits || n > MaxSecretsHistoryCommits {
			return c, fmt.Errorf("invalid secrets.history_commits %q: want an integer from 1 to 100000", v)
		}
		c.HistoryCommits = n
	}
	return c, nil
}
