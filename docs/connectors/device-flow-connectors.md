# Adding device-flow sign-in to a source

This guide is for contributors who want a source to offer "Sign in with X" using the OAuth device authorization flow (RFC 8628). GitHub is the reference implementation. All paths are under `services/bellud/internal/connectors/` unless noted.

A source supplies five inputs. Four are data in its manifest (device-code URL, token URL, client id, scopes). The fifth is code it already has: `lifecycle.Provider.Verify`. The `deviceflow` package does the rest.

## What the generic code does for you

`deviceflow.Service` owns the protocol. A provider has no hook to change any of it:

- **Polling.** It waits one interval before the first poll (5 s when the server sends none). `slow_down` raises the interval for every later poll. Network failures back off exponentially up to 60 s. A `Retry-After` is honored.
- **Expiry.** The authorization ends as `expired` when the device code's lifetime runs out (900 s when the server sends none).
- **Cancel.** `DELETE .../device-authorizations/{id}` stops polling and zeroes the device code. A token that arrives after a cancel is dropped and no Connection is created.
- **Duplicates.** A second start for the same source and alias while one is pending is rejected with `already_pending`. At most 8 authorizations can be pending.
- **Audit.** One `device_authorization` entry per phase: `started`, `connected`, `denied`, `expired`, `cancelled`, `failed`. `started` is written before anything is sent to the provider. Entries never contain a code or token.
- **Redaction.** The device code and the access token are registered with the redactor before use. The device code lives in memory only. `refresh_token` is never decoded.
- **Verification URL.** The `verification_uri` must be `https` with a host listed in the manifest `egress`, or the start fails.
- **Failure cleanup.** If `Verify` fails, the token is dropped from the vault and the Connection ends in ERROR with the typed code.

Current limits: the generic code sends only `client_id` when requesting a device code. The manifest `scopes` are validated and published to the catalog but not yet sent. The token response must have `token_type` `bearer`.

## All HTTP goes through the broker

Every device-flow request is made with a client from `broker.HTTPClient(ref, policy.CallerLifecycle)`, with the pre-connection ref `broker.PreConnectionRef` (`AuthNone`, no credential injected). The two endpoints are manifest operations of class `auth`, which only the `lifecycle` caller may use. A collector or agent that tries them is blocked before any bytes are sent.

Your provider must do the same: `Verify` uses `lifecycle.Call.Client`, which is already built on the broker. Do not create `http.Client`, `http.Transport`, or call `http.Get`/`http.Post` in a provider package. `arch_test.go` fails and names the package and import path if you do.

## Steps

### 1. Create the provider package and its manifest

Add `connectors/<id>/manifest.go` with a `Manifest(clientID string) manifest.Manifest` function. For the `device` method:

1. Add an auth method with id `manifest.MethodDevice` (`"device"`) and a `*manifest.DeviceSpec`:
   - `DeviceCodeURL` and `TokenURL`: `https` URLs without query or userinfo.
   - `ClientID`: your public client id (1 to 256 characters). Never put a client secret anywhere.
   - `Scopes`: 0 to 20 entries.
2. List both hosts in `Egress`.
3. Add two class `auth` operations, one per endpoint. Each is `Method: "POST"`, `Query: true`, with `Host` and `Path` equal to the URL's host and path. Set `IssuesCredential: true` on the token endpoint only. That tells the broker not to apply token-pattern redaction to the response body, which would otherwise replace the token with `[REDACTED:credential]`.
4. Add the read operations your `Verify` and collector need (class `read`, GET).

`registry.Register` runs `manifest.Validate`. A `device` method with a missing field, a non-https URL, a host not in `egress`, or a URL without a matching auth operation is rejected. The source is left out of the catalog and the error names the source and field, not the value.

If the client id is empty, leave the `device` method out of the manifest (as `github.Manifest` does). The catalog then shows only the other methods and the UI falls back to them.

### 2. Implement `lifecycle.Provider`, with `Verify` for method `device`

Implement the interface in `lifecycle/provider.go`: `Verify`, `CheckPermissions`, `Refresh`, `Collector`, `Describe`.

- `Verify(ctx, c lifecycle.Call)` branches on `c.Connection.Method == "device"`. Call an identity endpoint (401 means invalid credential) and return `lifecycle.Identity{AccountLabel: ..., ExpiresAt: ...}`. Do not require data that a freshly signed-in user might not have yet (GitHub's `Verify` avoids `/user/repos` for this reason and probes `/user/installations`). Return `*lifecycle.Error` for failures (`lifecycle.NewError(code, msg, nil)`). Broker errors can pass through and the manager classifies them.
- `Refresh` for a token you cannot renew should return the known expiry. Also implement `lifecycle.NonRefreshable` (`Refreshable(conn) bool`, false for `device`) so the supervisor marks the Connection EXPIRED at its recorded expiry instead of calling `Refresh`.
- `Describe` returns the `lifecycle.Descriptor`. Today only `broker.AuthGitHubToken` makes the transport inject `Authorization: Bearer <secret>` from the vault. Despite its name, use it for any bearer token provider until a neutral kind is added.

Optional: implement `lifecycle.MethodCredentialValidator` (`ValidateCredentialFor(method string, secret []byte) error`). The manager calls it before the secret reaches the vault, and it takes precedence over `CredentialValidator`. Use it to reject an obviously wrong token shape per method.

### 3. Wire the source into the service

In `service.go` (`connectors.New`), next to the GitHub lines:

- `s.registry.Register(<id>.Manifest(clientID))`
- `s.mgr.RegisterProvider(<id>.ConnectorID, provider)`
- Add a `case <id>.ConnectorID:` to the connection-ref switch that calls `provider.Describe(conn)` (it currently returns "unknown connector" for anything else).

Nothing is needed in `deviceflow`, `device.go`, the API routes or the protocol. `device.go` already builds the pre-connection ref from the registry and creates the Connection with method `device` and the source's default Auth_Config.

### 4. Check that the UI needs no code for the prompt

The dialog reads the `device` method from the catalog payload (`manifest.auth_methods[].device`, which carries `device_code_url`, `token_url`, `client_id`, `scopes`). It then uses the three generic routes:

- `POST /api/experimental/connectors/device-authorizations` with `{connectorId, alias}` (or `reconnectId`). The response has `id`, `userCode`, `verificationUri`, `expiresAt`, `intervalSec` and never the device code.
- `GET .../device-authorizations/{id}` for status: `pending`, `connected` (with the Connection), `expired`, `denied`, `failed`, with a typed `error.code` and optional `retryAfterSec`.
- `DELETE .../device-authorizations/{id}` to cancel.

The generic `device-prompt.tsx` renders the user code, verification link, countdown and cancel button from those values only. Your source adds no code to the prompt. What happens after "connected" (for GitHub, the repository picker) is a connector-specific panel registered in `connect-dialog.tsx`. If your source needs no extra step, no panel is needed beyond a close.

## Worked example (illustration only)

This is a hypothetical provider, `examplelab`, modelled on a GitLab-style service at `examplelab.test`. It is not in the repository. The code uses the real types and signatures above. The collector is left out because it is unrelated to sign-in (see `github/collector.go` for a real one).

`examplelab/manifest.go`:

```go
package examplelab

import "github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"

const (
	ConnectorID = "examplelab"
	Host        = "examplelab.test"
	// ClientID is a public identifier, not a secret. Empty hides sign-in.
	ClientID = "example-public-client-id"
)

func Manifest() manifest.Manifest {
	methods := []manifest.AuthMethod{}
	if ClientID != "" {
		methods = append(methods, manifest.AuthMethod{
			ID: manifest.MethodDevice, Name: "Sign in with ExampleLab", Enabled: true,
			Device: &manifest.DeviceSpec{
				DeviceCodeURL: "https://" + Host + "/oauth/authorize_device",
				TokenURL:      "https://" + Host + "/oauth/token",
				ClientID:      ClientID,
				Scopes:        []string{"read_api"},
			},
		})
	}
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "ExampleLab", Icon: "examplelab", Builtin: true,
		AuthMethods: methods,
		Permissions: []manifest.Permission{
			{Name: "read_api", Description: "Read projects", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			{Name: "GET /api/v4/user", Class: manifest.ClassRead, Method: "GET", Host: Host, Path: "/api/v4/user"},
			{Name: "GET /api/v4/projects", Class: manifest.ClassRead, Method: "GET", Host: Host, Path: "/api/v4/projects"},
			{Name: "POST /oauth/authorize_device", Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: Host, Path: "/oauth/authorize_device", MaxBytes: 16 << 10},
			{Name: "POST /oauth/token", Class: manifest.ClassAuth, Method: "POST", Query: true,
				Host: Host, Path: "/oauth/token", MaxBytes: 16 << 10, IssuesCredential: true},
		},
		Egress:   []string{Host},
		Entities: []string{"examplelab_project"},
	}
}
```

`examplelab/provider.go`:

```go
package examplelab

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
	"unicode"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

type Provider struct{}

var (
	_ lifecycle.Provider                = (*Provider)(nil)
	_ lifecycle.MethodCredentialValidator = (*Provider)(nil)
	_ lifecycle.NonRefreshable          = (*Provider)(nil)
)

// ValidateCredentialFor runs before the token reaches the vault.
func (*Provider) ValidateCredentialFor(method string, secret []byte) error {
	if method == "device" && len(secret) > 0 && !bytes.ContainsFunc(secret, unicode.IsSpace) {
		return nil
	}
	return lifecycle.NewError(lifecycle.CodeValidationFailed, "unsupported credential", nil)
}

// Verify proves the token with GET /api/v4/user. c.Client is built on the
// broker, which injects the Authorization header and enforces the allowlist.
func (*Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+Host+"/api/v4/user", nil)
	if err != nil {
		return lifecycle.Identity{}, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return lifecycle.Identity{}, err // broker errors are classified by the manager
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeInvalidCredential, "token is invalid, revoked or expired", nil)
	case http.StatusForbidden:
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeInsufficientPermission, "token lacks the required read permissions", nil)
	case http.StatusTooManyRequests:
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeRateLimited, "provider rate limit reached", nil)
	default:
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeNetwork, "unexpected response from provider", nil)
	}
	var u struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil || u.Username == "" {
		return lifecycle.Identity{}, lifecycle.NewError(lifecycle.CodeNetwork, "unexpected response from provider", nil)
	}
	return lifecycle.Identity{AccountLabel: u.Username}, nil
}

func (*Provider) CheckPermissions(context.Context, lifecycle.Call) (lifecycle.PermissionReport, error) {
	return lifecycle.PermissionReport{Unverifiable: true}, nil
}

// Refreshable is false for device tokens: the supervisor expires them instead.
func (*Provider) Refreshable(store.Connection) bool { return false }

func (*Provider) Refresh(_ context.Context, c lifecycle.Call) (time.Time, error) {
	if e := c.Connection.CredentialExpiresAt; e != nil {
		return *e, nil
	}
	return time.Time{}, nil
}

func (*Provider) Describe(store.Connection) lifecycle.Descriptor {
	// The only kind that injects "Authorization: Bearer <secret>" today.
	return lifecycle.Descriptor{Auth: broker.AuthGitHubToken, APIHost: Host, Host: Host}
}

func (*Provider) Collector(conn store.Connection, ref broker.ConnectionRef) collectors.Collector {
	return nil // replace with the connector's collector; not part of sign-in
}
```

Wiring in `service.go`:

```go
if err := s.registry.Register(examplelab.Manifest()); err != nil {
	return nil, err
}
// ...
s.mgr.RegisterProvider(examplelab.ConnectorID, &examplelab.Provider{})
// and in the connection-ref switch:
case examplelab.ConnectorID:
	d = (&examplelab.Provider{}).Describe(conn)
```

That is the whole change for sign-in. Polling, expiry, cancel, audit, redaction, duplicate rejection, the routes and the prompt come from the generic code.

## Checking your work manually

No tests are required for a new source today. To check it:

1. From `services/bellud`, run `go test ./internal/connectors/...`. The manifest validation, registry and architecture tests cover the manifest rules and the "all HTTP through the broker" rule for your package.
2. Start bellud with the `connectors` flag on and open the Connect dialog. Your source should appear with the sign-in method. If it is missing, bellud logs the source id and the invalid manifest field.
3. Start a sign-in. Check that the prompt shows the code and your provider's verification URL, approve it in the browser, and confirm the Connection becomes ACTIVE with your `AccountLabel`.
4. Try the failure paths: cancel mid-flow (no Connection should remain), let the code expire, deny the request, and use a token `Verify` rejects (the Connection should end in ERROR and the vault should hold no token).
5. Open the audit view. You should see `device_authorization` entries for each phase and no device code or token anywhere.
