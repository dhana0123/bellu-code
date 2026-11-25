package azure

import "github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"

// ConnectorID is the id of the built-in Microsoft Azure connector.
const ConnectorID = "azure"

// Auth method ids.
const (
	MethodDevice = manifest.MethodDevice
	// MethodServicePrincipal is the pasted service principal (tenant id,
	// client id, client secret).
	MethodServicePrincipal = "service-principal"
)

// Hosts.
const (
	// ARMHost serves the Azure Resource Manager API.
	ARMHost = "management.azure.com"
	// LoginHost serves the Entra device code and token endpoints.
	LoginHost = "login.microsoftonline.com"
	// VerificationHost and AltVerificationHost are the hosts the device code
	// response points the user at (microsoft.com/devicelogin and
	// login.microsoft.com/device). They are listed in egress so the manifest
	// declares every host the sign-in involves.
	VerificationHost    = "microsoft.com"
	AltVerificationHost = "login.microsoft.com"
)

// Scopes and URLs.
const (
	// DeviceScope is the delegated ARM scope requested at sign-in.
	DeviceScope = "https://management.azure.com/user_impersonation"
	// OfflineScope makes Entra return a refresh token.
	OfflineScope = "offline_access"
	// ServicePrincipalScope is the scope of the client_credentials exchange.
	ServicePrincipalScope = "https://management.azure.com/.default"

	DeviceCodeURL = "https://" + LoginHost + "/{tenant}/oauth2/v2.0/devicecode"
	TokenURL      = "https://" + LoginHost + "/{tenant}/oauth2/v2.0/token"

	// SPTokenOperation is the auth operation of the client_credentials
	// exchange (the same endpoint as the device token operation).
	SPTokenOperation = "POST /{tenant}/oauth2/v2.0/token"
)

// API versions.
const (
	SubscriptionsAPIVersion = "2022-12-01"
	AuthorizationAPIVersion = "2022-04-01"
)

// Manifest returns the built-in Azure connector manifest. Every operation is
// a GET read except the two auth operations, which are lifecycle only. The
// device method is listed only when clientID is non-empty.
//
// The service-principal method is declared but not Enabled: the broker has no
// auth kind that exchanges the pasted client secret for a token yet (see
// Provider.Verify). Enable it once such a kind exists.
func Manifest(clientID string) manifest.Manifest {
	methods := []manifest.AuthMethod{}
	if clientID != "" {
		methods = append(methods, manifest.AuthMethod{ID: MethodDevice, Name: "Sign in with Microsoft", Enabled: true,
			Device: &manifest.DeviceSpec{
				DeviceCodeURL: DeviceCodeURL,
				TokenURL:      TokenURL,
				ClientID:      clientID,
				Scopes:        []string{DeviceScope, OfflineScope},
				Tenant:        manifest.DefaultTenant,
				Refresh:       true,
			}})
	}
	methods = append(methods, manifest.AuthMethod{ID: MethodServicePrincipal, Name: "Service principal", Enabled: false, DisabledReason: "Coming soon"})
	read := func(name, path string) manifest.Operation {
		return manifest.Operation{Name: "GET " + name, Class: manifest.ClassRead, Method: "GET", Host: ARMHost, Path: path}
	}
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "Microsoft Azure", Icon: "azure", Builtin: true,
		AuthMethods: methods,
		Permissions: []manifest.Permission{
			{Name: "Reader", Description: "Read Azure subscriptions and resources", ReadOnly: true},
			{Name: "Security Reader", Description: "Read Azure security posture", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			read("/subscriptions", "/subscriptions"),
			read("/subscriptions/{s}/resourcegroups", "/subscriptions/{s}/resourcegroups"),
			read("/subscriptions/{s}/resources", "/subscriptions/{s}/resources"),
			read("/subscriptions/{s}/providers/Microsoft.Authorization/roleAssignments",
				"/subscriptions/{s}/providers/Microsoft.Authorization/roleAssignments"),
			read("/subscriptions/{s}/providers/Microsoft.Authorization/permissions",
				"/subscriptions/{s}/providers/Microsoft.Authorization/permissions"),
			{Name: "POST /{tenant}/oauth2/v2.0/devicecode", Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: LoginHost, Path: "/{tenant}/oauth2/v2.0/devicecode", MaxBytes: 16 << 10},
			{Name: SPTokenOperation, Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: LoginHost, Path: "/{tenant}/oauth2/v2.0/token", MaxBytes: 16 << 10, IssuesCredential: true},
		},
		Egress:   []string{ARMHost, LoginHost, VerificationHost, AltVerificationHost},
		Entities: []string{"azure_subscription"},
	}
}
