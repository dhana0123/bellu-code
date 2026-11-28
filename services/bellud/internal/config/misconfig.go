package config

import "strings"

// Misconfig holds the misconfig.* configuration keys. Each key is read from
// BELLUCODE_ plus the key in upper case with "." replaced by "_", for example
// BELLUCODE_MISCONFIG_CUSTOM_DIR (Requirement 8.7).
type Misconfig struct {
	// CustomDir is misconfig.custom_dir: a directory of custom Rego checks
	// loaded in addition to the bundled ones. Empty means none.
	CustomDir string
}

// LoadMisconfig reads the misconfig.* keys through env. An empty value counts
// as unset.
func LoadMisconfig(env func(string) (string, bool)) Misconfig {
	v, _ := env(envName("misconfig.custom_dir"))
	return Misconfig{CustomDir: strings.TrimSpace(v)}
}
