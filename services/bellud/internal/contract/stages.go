package contract

import (
	"net/http"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
)

// Stage is one step of the owner promotion order (Requirements 2.5, 22.1, 22.2).
//
// Stage order (earlier stages must be promoted before later ones):
//
//	0  graph, connectors, overview and findings routes (/api/experimental/{graph,connectors,overview,findings}/*): Go-native, TS never served them,
//	   so no TS fixtures exist; validated by the Go-side contract test instead.
//	1  auth, pairing, web UI
//	2  server info, health, event feed
//	3+ remaining route groups; the LLM session runtime is last.
//
// A route may be owned by `go` only when its stage is Promoted. For non-native
// stages every go-owned operation needs at least one fixture and a passing
// Check against its registered handler.
type Stage struct {
	Index    int
	Name     string
	Groups   []string // route groups covered
	Prefix   string   // alternative selector: route pattern prefix (used by Stage 0)
	Extra    []string // additional Go-native route pattern prefixes (e.g. connectors)
	Native   bool     // Go-native: exempt from TS-fixture parity
	Promoted bool     // go ownership permitted
}

// Stages is the promotion manifest. Only Stage 0 is promoted today.
var Stages = []Stage{
	{Index: 0, Name: "graph", Prefix: "/api/experimental/graph", Extra: []string{"/api/experimental/connectors", "/api/experimental/overview", "/api/experimental/findings", "/api/experimental/scans", "/api/experimental/sbom", "/api/experimental/bom", "/api/experimental/issues", "/api/experimental/rules", "/api/experimental/data", "/api/experimental/cve"}, Native: true, Promoted: true},
	{Index: 1, Name: "auth-pairing-webui", Groups: []string{"auth", "web"}},
	{Index: 2, Name: "server-info-health-events", Groups: []string{"server", "event", "openapi"}},
	{Index: 3, Name: "remaining", Groups: []string{"agent", "api", "command", "config", "credential", "debug", "filesystem", "form", "generate", "integration", "location", "mcp", "migration", "model", "permission", "persistentPty", "plugin", "project", "provider", "pty", "reference", "rpc", "shell", "skill", "usage", "vcs", "voice", "websearch", "worktree", "experimental"}},
	{Index: 4, Name: "session-runtime", Groups: []string{"session"}},
}

// StageOf returns the stage a route belongs to (prefix selectors win over groups).
func StageOf(r routes.Route) (Stage, bool) {
	for _, s := range Stages {
		if s.Prefix != "" && strings.HasPrefix(r.Pattern, s.Prefix) {
			return s, true
		}
		for _, p := range s.Extra {
			if strings.HasPrefix(r.Pattern, p) {
				return s, true
			}
		}
	}
	for _, s := range Stages {
		for _, g := range s.Groups {
			if g == r.Group {
				return s, true
			}
		}
	}
	return Stage{}, false
}

// HandlerFor resolves the registered Go handler for a route (nil if none).
type HandlerFor func(r routes.Route) http.Handler

// GateViolations returns every owner-gate failure for the table: a go-owned route
// outside a promoted stage, or (for non-native stages) with a missing fixture,
// missing handler, or failing contract check.
func GateViolations(t *routes.Table, fixtures []Fixture, handler HandlerFor, opts Options) []string {
	var out []string
	for _, r := range t.Routes() {
		if r.Owner != routes.OwnerGo {
			continue
		}
		id := r.Method + " " + r.Pattern
		st, ok := StageOf(r)
		if !ok || !st.Promoted {
			out = append(out, id+": go-owned but its stage is not promoted")
			continue
		}
		if st.Native {
			continue
		}
		var fx []Fixture
		for _, f := range fixtures {
			if got, ok := t.Lookup(f.Method, f.Path); ok && got == r {
				fx = append(fx, f)
			}
		}
		if len(fx) == 0 {
			out = append(out, id+": missing fixture")
			continue
		}
		var h http.Handler
		if handler != nil {
			h = handler(r)
		}
		if h == nil {
			out = append(out, id+": no registered Go handler")
			continue
		}
		for _, v := range Check(id, h, fx, opts) {
			out = append(out, v.String())
		}
	}
	return out
}
