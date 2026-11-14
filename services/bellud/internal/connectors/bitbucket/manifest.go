// Package bitbucket is the Bitbucket Cloud connector: an Atlassian API token
// plus the account email, sent as HTTP Basic auth. Bitbucket Cloud has no
// device flow, so there is no sign-in method.
package bitbucket

import "github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"

// ConnectorID is the id of the built-in Bitbucket connector.
const ConnectorID = "bitbucket"

// MethodAPIToken is the auth method id of a pasted email plus API token.
const MethodAPIToken = "api_token"

// APIHost is the Bitbucket Cloud API host.
const APIHost = "api.bitbucket.org"

func get(path string) manifest.Operation {
	return manifest.Operation{
		Name: "GET " + path, Class: manifest.ClassRead, Method: "GET",
		Host: APIHost, Path: path,
	}
}

// Manifest returns the built-in Bitbucket manifest. Every operation is a GET.
func Manifest() manifest.Manifest {
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "Bitbucket", Icon: "bitbucket", Builtin: true,
		AuthMethods: []manifest.AuthMethod{
			{ID: MethodAPIToken, Name: "Email and Atlassian API token", Enabled: true},
		},
		Permissions: []manifest.Permission{
			{Name: "Account", Description: "Read the authenticated account", ReadOnly: true},
			{Name: "Workspaces", Description: "Read workspaces", ReadOnly: true},
			{Name: "Repositories", Description: "Read repositories", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			get("/2.0/user"),
			get("/2.0/workspaces"),
			get("/2.0/repositories/{workspace}"),
		},
		Egress:   []string{APIHost},
		Entities: []string{"bitbucket_workspace", "bitbucket_repo"},
	}
}
