package config

import "strings"

// FeatureEnabled reports whether the feature flag key is on. It mirrors the
// BELLUCODE_FLAGS grammar of packages/schema/src/config/flag.ts: a comma
// separated list of `<key>`, `-<key>` and `all`. An opt-out (`-<key>`) wins
// over `<key>` and `all`; otherwise either entry turns the flag on. With
// neither, the default is on in dev builds and off in release builds, so the
// caller passes release (graph.IsRelease). `experimental.<key>` in config is
// read by the TypeScript side only.
func FeatureEnabled(getenv func(string) string, key string, release bool) bool {
	on := false
	for _, entry := range strings.Split(getenv("BELLUCODE_FLAGS"), ",") {
		switch strings.TrimSpace(entry) {
		case "-" + key:
			return false
		case key, "all":
			on = true
		}
	}
	return on || !release
}
