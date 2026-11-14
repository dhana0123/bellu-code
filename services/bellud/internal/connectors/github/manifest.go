package github

import (
	"encoding/json"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

// ConnectorID is the id of the built-in GitHub connector.
const ConnectorID = "github"

// Auth method ids.
const (
	MethodDevice = manifest.MethodDevice
	MethodPAT    = "pat"
)

// GitHubHost serves the device-flow endpoints.
const GitHubHost = "github.com"

// DefaultAPIHost is the public GitHub API host.
const DefaultAPIHost = "api.github.com"

// GHESBasePath is the REST prefix of GitHub Enterprise Server.
const GHESBasePath = "/api/v3"

// UnverifiableMessage is shown for the permission check of a PAT.
const UnverifiableMessage = "Permissions can't be verified; write requests are still blocked by the allowlist"

// hostPlaceholder is filled by the policy with Descriptor.Host: always the API
// host of the connection (api.github.com or the validated GHES host).
const hostPlaceholder = "{host}"

func get(name, path string, strip ...string) manifest.Operation {
	return manifest.Operation{
		Name: "GET " + name, Class: manifest.ClassRead, Method: "GET",
		Host: hostPlaceholder, Path: path, StripKeys: strip,
	}
}

// Manifest returns the built-in GitHub connector manifest. Every operation is
// a GET read, except POST /graphql which is a read only when its body is a
// query (see IsGraphQLQuery). Secret-scanning responses drop the "secret" key.
// The device method is listed only when clientID is non-empty.
func Manifest(clientID string) manifest.Manifest {
	methods := []manifest.AuthMethod{}
	if clientID != "" {
		methods = append(methods, manifest.AuthMethod{ID: MethodDevice, Name: "Sign in with GitHub", Enabled: true,
			Device: &manifest.DeviceSpec{
				DeviceCodeURL: "https://" + GitHubHost + "/login/device/code",
				TokenURL:      "https://" + GitHubHost + "/login/oauth/access_token",
				ClientID:      clientID,
				Scopes:        []string{},
			}})
	}
	methods = append(methods, manifest.AuthMethod{ID: MethodPAT, Name: "Fine-grained personal access token", Enabled: true})
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "GitHub", Icon: "github", Builtin: true,
		AuthMethods: methods,
		Permissions: []manifest.Permission{
			{Name: "Metadata", Description: "Read repository metadata", ReadOnly: true},
			{Name: "Contents", Description: "Read repository contents", ReadOnly: true},
			{Name: "Pull requests", Description: "Read pull requests", ReadOnly: true},
			{Name: "Issues", Description: "Read issues", ReadOnly: true},
			{Name: "Actions", Description: "Read workflows", ReadOnly: true},
			{Name: "Dependabot alerts", Description: "Read Dependabot alerts", ReadOnly: true},
			{Name: "Code scanning alerts", Description: "Read code scanning alerts", ReadOnly: true},
			{Name: "Secret scanning alerts", Description: "Read secret scanning alerts", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			get("/user", "/user"),
			get("/user/repos", "/user/repos"),
			get("/user/installations", "/user/installations"),
			get("/installation/repositories", "/installation/repositories"),
			get("/user/installations/{i}/repositories", "/user/installations/{i}/repositories"),
			get("/orgs/{org}", "/orgs/{org}"),
			get("/repos/{o}/{r}", "/repos/{o}/{r}"),
			get("/repos/{o}/{r}/pulls", "/repos/{o}/{r}/pulls"),
			get("/repos/{o}/{r}/actions/workflows", "/repos/{o}/{r}/actions/workflows"),
			get("/repos/{o}/{r}/code-scanning/alerts", "/repos/{o}/{r}/code-scanning/alerts"),
			get("/repos/{o}/{r}/dependabot/alerts", "/repos/{o}/{r}/dependabot/alerts"),
			get("/repos/{o}/{r}/secret-scanning/alerts", "/repos/{o}/{r}/secret-scanning/alerts", "secret"),
			// Issues are only counted; the Client reads the Link header.
			get("/repos/{o}/{r}/issues", "/repos/{o}/{r}/issues"),
			{Name: "POST /graphql", Class: manifest.ClassRead, Method: "POST", Query: true,
				Host: hostPlaceholder, Path: "/graphql"},
			{Name: "POST /login/device/code", Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: GitHubHost, Path: "/login/device/code", MaxBytes: 16 << 10},
			{Name: "POST /login/oauth/access_token", Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: GitHubHost, Path: "/login/oauth/access_token", MaxBytes: 16 << 10, IssuesCredential: true},
		},
		Egress:   []string{DefaultAPIHost, GitHubHost, hostPlaceholder},
		Entities: []string{"github_org", "github_repo", "github_workflow", "github_pull_request", "github_alert"},
	}
}

// IsGraphQLQuery reports whether body is a GraphQL request whose every
// operation is a query. Mutations, subscriptions, unparsable documents and
// documents without an operation are rejected (fail closed).
func IsGraphQLQuery(query string) bool {
	if strings.TrimSpace(query) == "" {
		return false
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: query})
	if err != nil || len(doc.Operations) == 0 {
		return false
	}
	for _, op := range doc.Operations {
		if op.Operation != ast.Query {
			return false
		}
	}
	return true
}

// IsGraphQLRequestBody reports whether body is a JSON GraphQL request object
// whose query field is read-only (see IsGraphQLQuery). Anything else, including
// batched arrays, is rejected. Wire it as broker.Config.QueryValidators["github"].
func IsGraphQLRequestBody(body []byte) bool {
	var req struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	return IsGraphQLQuery(req.Query)
}
