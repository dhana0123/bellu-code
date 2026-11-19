// Package githubschema declares the kinds that the github source owns. It
// imports only the standard library and schema.
package githubschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// Kind names.
const (
	KindOrg         = "github_org"
	KindRepo        = "github_repo"
	KindWorkflow    = "github_workflow"
	KindPullRequest = "github_pull_request"
	KindAlert       = "github_alert"
	KindPackage     = "package"
)

func kind(name, desc string, identity ...string) schema.KindDeclaration {
	return schema.KindDeclaration{Name: name, Identity: identity, Description: desc}
}

// Declaration returns the github source declaration. Its kinds are
// connection-scoped so that Disconnect removes exactly one connection's
// entities.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{
		Source: schema.SourceGitHub,
		Prefix: "github_",
		Kinds: []schema.KindDeclaration{
			kind(KindOrg, "A GitHub organization or user account.", "connection", "login"),
			kind(KindRepo, "A GitHub repository.", "connection", "full_name"),
			kind(KindWorkflow, "A GitHub Actions workflow in a repository.", "connection", "repo", "path"),
			kind(KindPullRequest, "A GitHub pull request.", "connection", "repo", "number"),
			kind(KindAlert, "A GitHub security alert on a repository.", "connection", "repo", "alert_type", "number"),
			kind(KindPackage, "A software package that a connection reports, identified by its package URL.", "connection", "scope", "purl"),
		},
	}
}
