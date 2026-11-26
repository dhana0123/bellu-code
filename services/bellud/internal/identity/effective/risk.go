package effective

import (
	"sort"
	"strings"
	"time"
)

// DefaultHighRiskActions are the entries of config identity.high_risk_actions
// when the config is empty (requirement 11.5).
var DefaultHighRiskActions = []string{"iam:PassRole", "iam:*", "sts:AssumeRole", "*:*"}

// LastUsedMaxAge is the age after which a recorded last use becomes a finding (11.7).
const LastUsedMaxAge = 90 * 24 * time.Hour

// Confidence of a derived relation.
type Confidence string

const (
	Extracted Confidence = "extracted"
	Inferred  Confidence = "inferred"
)

// Finding is an identity_risk finding produced by this package.
type Finding struct {
	Type     string // always "identity_risk"
	Severity string
	Identity string
	Action   string // empty for last-used findings
	Reason   string
}

// FindingKey identifies an identity and action pair for de-duplication.
func FindingKey(identity, action string) string { return identity + "\x00" + action }

// HighRiskFindings returns one high finding per identity and action pair that
// the identity is allowed to perform. open holds FindingKey values of findings
// that are still open; those pairs produce nothing. A nil actions list uses
// DefaultHighRiskActions. sts:AssumeRole counts only on adminRoles (role ARNs
// with administrator rights); every other action is evaluated on "*".
func HighRiskFindings(identity string, in Inputs, actions, adminRoles []string, open map[string]bool) []Finding {
	if actions == nil {
		actions = DefaultHighRiskActions
	}
	seen := map[string]bool{}
	var out []Finding
	for _, a := range actions {
		if seen[a] || open[FindingKey(identity, a)] {
			continue
		}
		resources := []string{"*"}
		if strings.EqualFold(a, "sts:AssumeRole") {
			resources = adminRoles
		}
		for _, r := range resources {
			if Evaluate(in, a, r).Decision != Allow {
				continue
			}
			seen[a] = true
			out = append(out, Finding{Type: "identity_risk", Severity: "high", Identity: identity, Action: a,
				Reason: "identity can perform high-risk action " + a})
			break
		}
	}
	return out
}

// Use is the collected last-use data of one identity. LastUsed is nil when no
// last-used data was collected.
type Use struct {
	Identity string
	LastUsed *time.Time
}

// LastUsedFindings returns a low finding for each identity whose collected
// last use is older than 90 days. Identities without data produce nothing.
func LastUsedFindings(now time.Time, uses []Use, open map[string]bool) []Finding {
	var out []Finding
	for _, u := range uses {
		if u.LastUsed == nil || now.Sub(*u.LastUsed) <= LastUsedMaxAge || open[FindingKey(u.Identity, "")] {
			continue
		}
		out = append(out, Finding{Type: "identity_risk", Severity: "low", Identity: u.Identity,
			Reason: "identity last used " + u.LastUsed.UTC().Format("2006-01-02")})
	}
	return out
}

// Provider of a trust relation.
type Provider string

const (
	AWS   Provider = "aws"
	GCP   Provider = "gcp"
	Azure Provider = "azure"
)

// Trust is one trust entry of a target role or service account.
// Principal is an ARN, account id or "*" (AWS), a member such as
// serviceAccount:x@p.iam.gserviceaccount.com (GCP) or an object id (Azure).
// PrincipalScope is the account, project or subscription the principal lives
// in; TargetScope is the one of the target.
type Trust struct {
	Provider       Provider
	Principal      string
	PrincipalScope string
	Target         string
	TargetScope    string
}

// CanAssume is a can_assume relation. State is "confirmed" for Extracted and
// "inferred" for Inferred.
type CanAssume struct {
	From, To   string
	Confidence Confidence
	State      string
}

// CanAssumeRelations derives can_assume relations for cross-account or
// cross-project trusts. An exact principal is extracted/confirmed; a wildcard
// or account-root principal is inferred. Same-scope trusts produce nothing.
func CanAssumeRelations(trusts []Trust) []CanAssume {
	var out []CanAssume
	for _, t := range trusts {
		wild := isWildcard(t)
		if !wild && t.PrincipalScope == t.TargetScope {
			continue
		}
		if wild && t.PrincipalScope != "" && t.PrincipalScope == t.TargetScope {
			continue
		}
		c, s := Extracted, "confirmed"
		if wild {
			c, s = Inferred, "inferred"
		}
		out = append(out, CanAssume{From: t.Principal, To: t.Target, Confidence: c, State: s})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func isWildcard(t Trust) bool {
	p := t.Principal
	if p == "*" {
		return true
	}
	switch t.Provider {
	case AWS:
		return strings.HasSuffix(p, ":root") || isDigits(p)
	case GCP:
		return p == "allUsers" || p == "allAuthenticatedUsers" || strings.HasPrefix(p, "domain:") || strings.HasPrefix(p, "projectOwner:")
	case Azure:
		return p == "" || strings.HasPrefix(p, "tenant:")
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Gap is a missing_data entry recorded when collection is denied (11.11).
type Gap struct {
	Connector    string
	ResourceType string
	Scope        string
	Reason       string // missing_permission, rate_limited or failed_call
	Permission   string // the permission needed, for missing_permission
}

// CollectionResult is the outcome of collecting one identity kind.
type CollectionResult struct {
	Kind       string
	Scope      string
	Denied     bool
	Permission string
	Err        error
}

// Gaps turns denied or failed identity collections into gaps. Other kinds
// are unaffected, so callers keep all collected data and continue.
func Gaps(connector string, results []CollectionResult) []Gap {
	var out []Gap
	for _, r := range results {
		switch {
		case r.Denied:
			out = append(out, Gap{connector, r.Kind, r.Scope, "missing_permission", r.Permission})
		case r.Err != nil:
			out = append(out, Gap{connector, r.Kind, r.Scope, "failed_call", ""})
		}
	}
	return out
}
