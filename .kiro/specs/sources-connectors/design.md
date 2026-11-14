# Design Document

## Overview

Six new Sources (Google Cloud, Microsoft Azure, GitLab, Bitbucket, Kubernetes, Cloudflare) are added as `connectors` packages in Bellud next to `github` and `aws`. Version 1 verifies and connects only: every Provider returns a nil Collector. The App gets one shared Wizard driven by a per-source descriptor, and AWS and GitHub move onto it.

This round adds no tests. The correctness properties below are for a later round. Build only; never restart services in the dev loop.

## Architecture

### Auth decision per provider (checked against provider docs)

| Source | Sign-in | Pasted credential (v1 fallback) | Broker auth kind |
|---|---|---|---|
| GitLab | Device grant (GitLab 17.1+, public non-confidential OAuth app, no secret). Scope `read_api`. | PAT with `read_api` | `bearer` |
| Microsoft Azure | Entra device code on a public client, no secret. Scopes `https://management.azure.com/user_impersonation offline_access`. Endpoints `login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` and `/token`. Tenant defaults to `organizations`. | Service principal (tenant, client ID, client secret) with Reader + Security Reader | `bearer` (token from sign-in, or client-credentials exchange done server side) |
| Google Cloud | None. The device flow needs a client secret on `/token` and only allows openid, email, profile, Drive and YouTube scopes, so it cannot grant `cloud-platform`. | Service-account JSON key with `roles/viewer` + `roles/iam.securityReviewer` | `gcp-sa`: server signs a JWT, exchanges it at `oauth2.googleapis.com/token`, caches the access token in memory |
| Bitbucket | None. Bitbucket Cloud has no device flow. | Atlassian API token (app passwords are being removed) plus account email, read scopes only | `basic` (`email:token`) |
| Cloudflare | None (no public-client flow). | API token with read-only permission groups | `bearer` |
| Kubernetes | None. | API server URL + read-only ServiceAccount token + CA certificate (or a kubeconfig the App parses into these three). The wizard shows kubectl YAML to copy: ServiceAccount, ClusterRoleBinding to `view`, token Secret. | `k8s-bearer` |

Sign-in is offered only when its client ID is non-empty (Requirement 2). Google never offers it. Bitbucket, Cloudflare and Kubernetes never offer it. For those, the Wizard states that sign-in is unavailable and shows the pasted path.

### Backend (services/bellud/internal/connectors)

#### Packages

Each Source gets a package `gitlab`, `azure`, `gcp`, `bitbucket`, `cloudflare`, `kubernetes` with `manifest.go`, `provider.go` and, where sign-in exists, `clientid.go`. Registration follows `github`.

#### Client IDs

`clientid.go` mirrors `github/clientid.go`. The compiled constant is empty by default, and `BELLUCODE_<PROVIDER>_CLIENT_ID` (`GITLAB`, `AZURE`) overrides it. `EffectiveClientID(getenv)` returns the trimmed env value, else the constant. `Manifest(clientID)` lists the `device` method only when the ID is non-empty.

#### Device flow generalization

`manifest.DeviceSpec` and `deviceflow` change as follows. The `DeviceSpec` and vault changes are listed under Data Models.

- Send `scope` (space-joined) in the device-code request. `DeviceSpec.Scopes` already exists.
- Token responses are parsed generically: `access_token`, `refresh_token`, `expires_in`.
- `NonRefreshable` stays for pasted credentials that cannot be renewed (PATs, API tokens). Service-account and service-principal credentials refresh by re-exchange.

### App wiring (packages/app/src/settings/connectors)

#### Migration

`aws-panel.tsx` and `github-panel.tsx` become descriptors plus the shared component. The existing machines (`aws-wizard.ts`, `github-wizard.ts`, `signin-machine.ts`) are folded into the generic machine with their transitions unchanged, and their current tests keep passing. `connect-page.tsx` keeps building each panel once and untracked; panels stay in the `PANELS` record keyed by connector id and read the connection list only through untracked accessors. New Sources register as entries in that record via the shared component.

#### Catalog, flag, text, logos

- `planned.ts` loses the six entries. Because manifests exist, `withPlannedCards` has nothing to add; the file keeps its mechanism for future planned Sources.
- The six Sources are hidden while the `connectors` flag is off, through the existing `enabled.ts` path.
- User-facing text says "Sources". Code names keep `connectors`.
- Logos: `packages/ui/script/connector-icons.ts` already maps `googlecloud`, `azure`, `gitlab`, `bitbucket`, `kubernetes`, `cloudflare`. Run it and use the generated `connectorLogos` entries on cards, detail and wizard header.
- The client protocol gains the manifest fields above (`token_grant`, new auth method ids). After changing it, run `bun run generate` from `packages/client`.

## Components and Interfaces

### Providers

Each Source package provides a `Provider` with Verify, CheckPermissions and Refresh. The Provider returns a nil Collector in v1.

#### Verify and CheckPermissions

| Source | Verify (identity) | CheckPermissions (excess = write-capable) |
|---|---|---|
| GitLab | `GET /user` → username | `personal_access_tokens/self` scopes; any of `api`, `write_*`, `create_runner`, `sudo`, etc. is an offender (OAuth sign-in tokens carry only `read_api`) |
| Azure | `GET /subscriptions` → tenant/subscription count | Role assignments for the principal; any role other than Reader and Security Reader whose actions allow writes is an offender |
| Google Cloud | JWT exchange succeeds; label is `client_email` | `testIamPermissions` with a fixed probe set of write permissions (for example `resourcemanager.projects.setIamPolicy`, `compute.instances.delete`); granted ones are offenders |
| Bitbucket | `GET /user` → display name | `X-OAuth-Scopes` response header; any `write`, `admin`, `delete` scope is an offender |
| Cloudflare | `tokens/verify` → status `active` | Token permission groups when the token can read its own policy; otherwise `Unverifiable` |
| Kubernetes | `GET /version` | `selfsubjectrulesreviews` for the chosen namespace; any rule with verbs create, update, patch, delete, `*` is an offender |

Offenders go to `PermissionReport.WriteOffenders`. If a check cannot complete, `Unverifiable` is true and the write block still comes from the allowlist.

#### Refresh

`Provider.Refresh` posts `grant_type=refresh_token` with the client ID and no secret. This works for Azure and GitLab. The refresh token never leaves the vault.

### Broker auth kinds

`AuthGitHubToken` is renamed `AuthBearer` (`"bearer"`). The old constant stays as an alias with the same value so stored connections keep working. New kinds:

- `AuthBasic`: header `Authorization: Basic base64(user:secret)`. The vault holds `user\nsecret` in one slot.
- `AuthGCPServiceAccount`: signs an RS256 JWT with the key from the vault, exchanges it for an access token, caches it in memory until 60 s before expiry, and injects it as bearer.
- `AuthK8sBearer`: bearer plus a per-connection host (`Descriptor.Host`) and a custom CA pool built from the vault. The transport still goes through `netguard`. A private-range API server must be allowed explicitly per connection; the default stays denied.

Each kind keeps the single policy choke point. Token exchange calls are `ClassAuth` operations.

### Wizard

New `wizard/` module (in `packages/app/src/settings/connectors`) with two parts.

1. A pure step machine, `transitionWizard(descriptor, state, event)`. Steps are `choose`, `create`, `paste`, `scope`, `done`. `selectWizardStep` and `selectCanGoBack` are derived. A failed verification event keeps the current step and stores the reason. Sign-in skips `create` and `paste` and uses the existing sign-in machine for the device prompt.
2. A Wizard component with a stepper, method cards, a code-plus-copy block, the device prompt (copyable code and provider link), paste fields, a scope list and the Connected screen with the Describe result.

### Source descriptors

A `SourceDescriptor` per Source supplies the methods, one instruction and one docs link per step, the paste field definitions (label, secret flag, multiline), and optional copy blocks (the Kubernetes YAML, the GCP role list). Descriptors live in `descriptors/<id>.ts`. Their types are listed under Data Models.

## Data Models

### Manifest fields

#### Manifests (read-only allowlists, minimal for Verify and CheckPermissions)

| Source | Egress hosts | Operations (all GET unless noted) |
|---|---|---|
| GitLab | `gitlab.com` (and a validated self-managed host via `{host}`) | `/api/v4/user`, `/api/v4/personal_access_tokens/self` |
| Azure | `management.azure.com`, `login.microsoftonline.com` | `/subscriptions?api-version=2022-12-01`, `/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments`, `/roleDefinitions/{id}`; auth: devicecode and token |
| Google Cloud | `cloudresourcemanager.googleapis.com`, `oauth2.googleapis.com`, `iam.googleapis.com` | `POST /v3/projects/{p}:testIamPermissions` (read query, `Query: true`), `GET /v3/projects:search`; auth: token exchange |
| Bitbucket | `api.bitbucket.org` | `/2.0/user`, `/2.0/workspaces` |
| Cloudflare | `api.cloudflare.com` | `/client/v4/user/tokens/verify`, `/client/v4/accounts/{id}/tokens/verify`, `/client/v4/accounts`, `/client/v4/zones` |
| Kubernetes | connection host | `GET /version`, `GET /api/v1/namespaces`, `POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews` (read query) |

`entities` lists what a later collector would cover (projects, subscriptions, workspaces, zones, namespaces). Each permission has `read_only: true`.

### DeviceSpec additions

- `DeviceSpec` gains `TokenGrant` (default `urn:ietf:params:oauth:grant-type:device_code`) and `Tenant` placeholders resolved at start. Azure uses `/devicecode` and `/token` on one host with different paths, so the two URLs stay independent. No provider-specific code enters `deviceflow`.

### Vault slots

- The vault stores the refresh token and expiry beside the access token.
- For `AuthBasic`, the vault holds `user\nsecret` in one slot.
- For `AuthGCPServiceAccount` and `AuthK8sBearer`, the vault holds the service-account key and the CA certificate respectively.

### Selection (scope step)

Per Source: GitLab projects/groups, Azure subscriptions, Google Cloud projects, Bitbucket workspaces, Cloudflare accounts/zones, Kubernetes namespaces. The list comes from the manifest read operations above. In v1 the selection is stored on the connection and nothing is collected.

### SourceDescriptor types

`SourceDescriptor` holds the methods, per-step instruction and https docs link, paste field definitions (label, secret flag, multiline) and optional copy blocks. Wizard state holds the current step and the last failure reason.

## Error Handling

- Provider failures return `*lifecycle.Error` with the existing codes; the Wizard shows the reason and stays on the current step.
- Invalid pasted input (bad JSON key, missing CA, wrong token shape) is rejected by `ValidateCredentialFor(method, secret)` before any vault or audit step. Messages name the field, never the value.
- Device flow denial, expiry and slow-down reuse the existing poller statuses.
- Credentials are redacted from logs and audit by the existing redactor; the response projection never contains a secret.

## Testing Strategy

This round adds no tests. The correctness properties listed below will be used in a later round to drive property-based tests.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Planned cards never duplicate catalog entries

For any catalog of connector cards, `withPlannedCards` returns no planned card whose id appears in the catalog.

**Validates: Requirements 1.4**

### Property 2: Sign-in availability follows the client ID

For any environment values and compiled constant, a Source's manifest lists the device method if and only if its effective client ID is non-empty, and the pasted-credential method is always listed for Sources that support it.

**Validates: Requirements 2.1, 2.2**

### Property 3: Broker injects the required auth scheme

For any secret and auth kind, the outbound request carries `Bearer <secret>` for bearer kinds and `Basic base64(user:secret)` for the basic kind, and no other credential header.

**Validates: Requirements 2.6**

### Property 4: Only read-only requests pass

For any request method, host and path, the broker accepts it only if it matches an allowlisted read (or read-query) operation of the connection's manifest.

**Validates: Requirements 3.1**

### Property 5: Credentials never leak

For any credential value, no API response to the App, log line or audit event contains it after submission.

**Validates: Requirements 3.3, 3.4**

### Property 6: Write permissions are reported

For any set of granted scopes, roles, permissions or rules for a provider, `WriteOffenders` equals exactly the write-capable subset.

**Validates: Requirements 3.5**

### Property 7: Wizard steps stay in bounds

For any descriptor and any sequence of wizard events, the selected step is one of choose, create, paste, scope or done, and Back never moves before choose.

**Validates: Requirements 4.3**

### Property 8: Every descriptor step has instruction and docs link

For any Source descriptor and any of its steps, the step has a non-empty instruction and an https docs link.

**Validates: Requirements 4.5**

### Property 9: Failed verification keeps the step

For any wizard state and failure event, the step is unchanged and the failure reason is present in the state.

**Validates: Requirements 4.7**
