package lens

// commonAttrs is the allowlist for kinds without a specific entry.
var commonAttrs = []string{"name", "region", "state", "internet_exposed", "canonical_key"}

// kindAttrs is the per-kind attribute allowlist. Nothing outside it leaves
// the engine, so no unreviewed attribute reaches the UI or an agent.
var kindAttrs = map[string][]string{
	"github_org":      {"name", "canonical_key"},
	"github_repo":     {"name", "visibility", "canonical_key", "internet_exposed"},
	"github_workflow": {"name", "state"},
	"github_alert":    {"name", "state", "severity", "summary"},
	"package":         {"name", "purl", "canonical_key", "internet_exposed"},
	"vulnerability":   {"name", "canonical_key", "summary", "severity", "fixed_in"},
	"aws_account":     {"name", "canonical_key"},
	"aws_resource":    {"name", "region", "state", "internet_exposed", "canonical_key"},
	"image":           {"name", "canonical_key", "internet_exposed"},
}

// FilterAttrs returns a new map holding only the allowlisted attributes of
// kind. The result is never nil.
func FilterAttrs(kind string, attrs map[string]string) map[string]string {
	allowed, ok := kindAttrs[kind]
	if !ok {
		allowed = commonAttrs
	}
	out := make(map[string]string, len(allowed))
	for _, k := range allowed {
		if v, ok := attrs[k]; ok {
			out[k] = v
		}
	}
	return out
}
