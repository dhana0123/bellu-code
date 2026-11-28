// Package gcp is the Google Cloud connector: a pasted service-account key,
// exchanged by the broker for short-lived read access tokens.
package gcp

import (
	"encoding/json"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

// ConnectorID is the id of the built-in Google Cloud connector.
const ConnectorID = "gcp"

// MethodServiceAccount is the only auth method: a pasted service-account key.
const MethodServiceAccount = "service_account"

// Hosts used by the connector.
const (
	ResourceManagerHost = "cloudresourcemanager.googleapis.com"
	TokenHost           = "oauth2.googleapis.com"
	ComputeHost         = "compute.googleapis.com"
	ContainerHost       = "container.googleapis.com"
	StorageHost         = "storage.googleapis.com"
	SQLAdminHost        = "sqladmin.googleapis.com"
	IAMHost             = "iam.googleapis.com"
	AIPlatformHost      = "aiplatform.googleapis.com"
)

// Operation names and paths.
const (
	opSearchProjects = "GET /v3/projects:search"
	opListProjects   = "GET /v1/projects"
	opTestIAM        = "POST /v1/projects/{p}:testIamPermissions"
)

// SignInUnavailableMessage tells the wizard why sign-in is not offered.
const SignInUnavailableMessage = "Sign-in is unavailable for Google Cloud: no public client ID is available. Paste a service-account key instead."

// Manifest returns the built-in Google Cloud manifest. Every operation is a
// GET read, except testIamPermissions (a POST read query, see
// IsTestIAMPermissionsBody) and the token exchange (class auth).
func Manifest() manifest.Manifest {
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "Google Cloud", Icon: "gcp", Builtin: true,
		AuthMethods: []manifest.AuthMethod{
			{ID: MethodServiceAccount, Name: "Service account key (JSON)", Enabled: true},
		},
		Permissions: []manifest.Permission{
			{Name: "Viewer", Description: "Read projects and resources", ReadOnly: true},
			{Name: "Security Reviewer", Description: "Read IAM policies and security settings", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			{Name: opSearchProjects, Class: manifest.ClassRead, Method: "GET",
				Host: ResourceManagerHost, Path: "/v3/projects:search"},
			{Name: opListProjects, Class: manifest.ClassRead, Method: "GET",
				Host: ResourceManagerHost, Path: "/v1/projects"},
			// The placeholder matches one whole segment, so it also matches
			// "{project}:testIamPermissions". The body validator restricts the
			// operation to a permission probe.
			{Name: opTestIAM, Class: manifest.ClassRead, Method: "POST", Query: true,
				Host: ResourceManagerHost, Path: "/v1/projects/{p}", MaxBytes: 64 << 10},
			// Collector listings: GET only.
			{Name: "GET /compute/v1/projects/{p}/global/networks", Class: manifest.ClassRead, Method: "GET",
				Host: ComputeHost, Path: "/compute/v1/projects/{p}/global/networks"},
			{Name: "GET /compute/v1/projects/{p}/global/firewalls", Class: manifest.ClassRead, Method: "GET",
				Host: ComputeHost, Path: "/compute/v1/projects/{p}/global/firewalls"},
			{Name: "GET /compute/v1/projects/{p}/aggregated/subnetworks", Class: manifest.ClassRead, Method: "GET",
				Host: ComputeHost, Path: "/compute/v1/projects/{p}/aggregated/subnetworks"},
			{Name: "GET /compute/v1/projects/{p}/aggregated/instances", Class: manifest.ClassRead, Method: "GET",
				Host: ComputeHost, Path: "/compute/v1/projects/{p}/aggregated/instances"},
			{Name: "GET /v1/projects/{p}/locations/-/clusters", Class: manifest.ClassRead, Method: "GET",
				Host: ContainerHost, Path: "/v1/projects/{p}/locations/-/clusters"},
			{Name: "GET /storage/v1/b", Class: manifest.ClassRead, Method: "GET",
				Host: StorageHost, Path: "/storage/v1/b"},
			{Name: "GET /v1/projects/{p}/instances", Class: manifest.ClassRead, Method: "GET",
				Host: SQLAdminHost, Path: "/v1/projects/{p}/instances"},
			{Name: "GET /v1/projects/{p}/serviceAccounts", Class: manifest.ClassRead, Method: "GET",
				Host: IAMHost, Path: "/v1/projects/{p}/serviceAccounts"},
			{Name: "GET /v1/projects/{p}/locations/-/endpoints", Class: manifest.ClassRead, Method: "GET",
				Host: AIPlatformHost, Path: "/v1/projects/{p}/locations/-/endpoints"},
			{Name: broker.GCPTokenOperation, Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: TokenHost, Path: "/token", MaxBytes: 16 << 10, IssuesCredential: true},
		},
		Egress:   []string{ResourceManagerHost, TokenHost, ComputeHost, ContainerHost, StorageHost, SQLAdminHost, IAMHost, AIPlatformHost},
		Entities: []string{"gcp_project"},
	}
}

// IsTestIAMPermissionsBody reports whether body is a testIamPermissions
// request: a JSON object with only a "permissions" array of strings. A
// setIamPolicy body (key "policy") is rejected. Wire it as
// broker.Config.QueryValidators["gcp"].
func IsTestIAMPermissionsBody(body []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil || len(m) != 1 {
		return false
	}
	raw, ok := m["permissions"]
	if !ok {
		return false
	}
	var perms []string
	return json.Unmarshal(raw, &perms) == nil
}
