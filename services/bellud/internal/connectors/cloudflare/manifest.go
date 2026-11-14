// Package cloudflare is the Cloudflare connector: API token paste, bearer
// auth, read-only allowlist.
package cloudflare

import "github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"

// ConnectorID is the id of the built-in Cloudflare connector.
const ConnectorID = "cloudflare"

// MethodToken is the API token paste method.
const MethodToken = "token"

// APIHost is the Cloudflare API host.
const APIHost = "api.cloudflare.com"

// Allowlisted read paths.
const (
	pathVerify   = "/client/v4/user/tokens/verify"
	pathAccounts = "/client/v4/accounts"
	pathZones    = "/client/v4/zones"
	pathToken    = "/client/v4/user/tokens/{id}"
)

func get(path string) manifest.Operation {
	return manifest.Operation{
		Name: "GET " + path, Class: manifest.ClassRead, Method: "GET",
		Host: APIHost, Path: path,
	}
}

// Manifest returns the built-in Cloudflare connector manifest. Every operation
// is a GET read.
func Manifest() manifest.Manifest {
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "Cloudflare", Icon: "cloudflare", Builtin: true,
		AuthMethods: []manifest.AuthMethod{
			{ID: MethodToken, Name: "API token", Enabled: true},
		},
		Permissions: []manifest.Permission{
			{Name: "Account Settings: Read", Description: "List the accounts the token can access", ReadOnly: true},
			{Name: "Zone: Read", Description: "List zones", ReadOnly: true},
			{Name: "API Tokens: Read", Description: "Read the token's own policy to check for write permissions", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			get(pathVerify),
			get(pathAccounts),
			get(pathZones),
			get(pathToken),
		},
		Egress:   []string{APIHost},
		Entities: []string{"cloudflare_account", "cloudflare_zone"},
	}
}
