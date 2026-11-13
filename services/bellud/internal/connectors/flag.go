// Package connectors holds the cloud connector subsystem of bellud.
package connectors

import (
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// isRelease reports a release build; tests replace it.
var isRelease = graph.IsRelease

// flagKey is the feature flag guarding all connector behavior.
const flagKey = "connectors"

// Enabled reports whether the connectors flag is on. It mirrors the
// BELLUCODE_FLAGS grammar of packages/schema/src/config/flag.ts: a comma
// separated list of `connectors`, `-connectors` and `all`. An opt-out
// (`-connectors`) wins over `connectors` and `all`; otherwise either entry
// turns the flag on. With neither, the default is on in dev builds and off in
// release builds (graph.IsRelease).
func Enabled(getenv func(string) string) bool {
	on := false
	for _, entry := range strings.Split(getenv("BELLUCODE_FLAGS"), ",") {
		switch strings.TrimSpace(entry) {
		case "-" + flagKey:
			return false
		case flagKey, "all":
			on = true
		}
	}
	return on || !isRelease()
}
