package gitlab

import "github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"

// ConnectorID is the id of the built-in GitLab Source.
const ConnectorID = "gitlab"

// Auth method ids.
const (
	MethodDevice = manifest.MethodDevice
	MethodPAT    = "pat"
)

// GitLabHost serves the OAuth device endpoints and, by default, the API.
const GitLabHost = "gitlab.com"

// DeviceScope is the only OAuth scope requested by device sign-in.
const DeviceScope = "read_api"

// hostPlaceholder is filled by the policy with Descriptor.Host: gitlab.com or
// a validated self-managed host.
const hostPlaceholder = "{host}"

func get(name, path string) manifest.Operation {
	return manifest.Operation{
		Name: "GET " + name, Class: manifest.ClassRead, Method: "GET",
		Host: hostPlaceholder, Path: path,
	}
}

// Manifest returns the built-in GitLab manifest. Every operation is a GET
// read. The device method is listed only when clientID is non-empty.
func Manifest(clientID string) manifest.Manifest {
	methods := []manifest.AuthMethod{}
	if clientID != "" {
		methods = append(methods, manifest.AuthMethod{ID: MethodDevice, Name: "Sign in with GitLab", Enabled: true,
			Device: &manifest.DeviceSpec{
				DeviceCodeURL: "https://" + GitLabHost + "/oauth/authorize_device",
				TokenURL:      "https://" + GitLabHost + "/oauth/token",
				ClientID:      clientID,
				Scopes:        []string{DeviceScope},
				Refresh:       true,
			}})
	}
	methods = append(methods, manifest.AuthMethod{ID: MethodPAT, Name: "Personal access token", Enabled: true})
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "GitLab", Icon: "gitlab", Builtin: true,
		AuthMethods: methods,
		Permissions: []manifest.Permission{
			{Name: "read_api", Description: "Read projects, groups and the authenticated user", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			get("/api/v4/user", "/api/v4/user"),
			get("/api/v4/personal_access_tokens/self", "/api/v4/personal_access_tokens/self"),
			get("/api/v4/projects", "/api/v4/projects"),
			get("/api/v4/groups", "/api/v4/groups"),
			{Name: "POST /oauth/authorize_device", Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: GitLabHost, Path: "/oauth/authorize_device", MaxBytes: 16 << 10},
			{Name: "POST /oauth/token", Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: GitLabHost, Path: "/oauth/token", MaxBytes: 16 << 10, IssuesCredential: true},
		},
		Egress:   []string{GitLabHost, hostPlaceholder},
		Entities: []string{"gitlab_group", "gitlab_project"},
	}
}
