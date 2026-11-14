# Implementation Plan: Sources (connectors)

## Overview

Backend shared pieces first (broker auth kinds, device flow, client IDs), then the six provider packages, then wiring, API and client regeneration, then the shared Wizard, AWS and GitHub migration, six new panels, logos, docs and a final build check. No test tasks this round. Never restart services; build and typecheck only. Backend paths are under `services/bellud/internal/connectors`, App paths under `packages/app/src/settings/connectors`.

## Tasks

- [ ] 1. Backend shared pieces
  - [x] 1.1 Add broker auth kinds
    - In `broker`, rename `AuthGitHubToken` to `AuthBearer` (`"bearer"`) and keep the old constant as an alias with the same value
    - Add `AuthBasic` (`user\nsecret` from the vault), `AuthGCPServiceAccount` (RS256 JWT, token exchange, in-memory cache until 60 s before expiry) and `AuthK8sBearer` (per-connection `Descriptor.Host`, custom CA pool, still through `netguard`, private ranges denied unless allowed per connection)
    - Token exchange calls are `ClassAuth` operations; all kinds go through the single policy choke point
    - _Requirements: 2.6, 3.1_
  - [x] 1.2 Generalize the device flow
    - In `manifest.DeviceSpec` add `TokenGrant` (default device_code grant) and tenant placeholders resolved at start; keep device-code and token URLs independent
    - In `deviceflow`, send space-joined `scope`, parse `access_token`, `refresh_token`, `expires_in` generically, and store refresh token and expiry in the vault
    - Implement refresh-token renewal (client ID, no secret) for use by `Provider.Refresh`; keep `NonRefreshable` for PATs and API tokens
    - _Requirements: 2.1, 2.4_
  - [x] 1.3 Add client ID constants
    - Create `gitlab/clientid.go` and `azure/clientid.go` mirroring `github/clientid.go`: empty compiled constant, `BELLUCODE_GITLAB_CLIENT_ID` and `BELLUCODE_AZURE_CLIENT_ID` overrides, `EffectiveClientID(getenv)`
    - _Requirements: 2.1, 2.2_
  - [x] 1.4 Add credential validation hook
    - Add `ValidateCredentialFor(method, secret)` that rejects bad pasted input before any vault or audit step, with messages naming the field and never the value
    - _Requirements: 2.5, 3.4_

- [x] 2. Checkpoint - backend shared build
  - Run `go build ./...` and `go vet ./...` in `services/bellud`. Ask the user if questions arise.

- [ ] 3. Provider packages
  - [-] 3.1 GitLab package
    - Create `gitlab/manifest.go` and `gitlab/provider.go`: device sign-in (scope `read_api`) when client ID is set, PAT paste, `bearer` auth, allowlist `/api/v4/user` and `/api/v4/personal_access_tokens/self`
    - Verify via `/user`; CheckPermissions reports write-capable PAT scopes in `WriteOffenders`; nil Collector
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 3.5_
  - [-] 3.2 Azure package
    - Create `azure/manifest.go` and `azure/provider.go`: Entra device code (tenant defaults to `organizations`) when client ID is set, service-principal paste, `bearer` auth, subscriptions and role assignment reads
    - Verify via `/subscriptions`; CheckPermissions reports roles beyond Reader and Security Reader that allow writes; nil Collector
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 3.5_
  - [-] 3.3 Google Cloud package
    - Create `gcp/manifest.go` and `gcp/provider.go`: service-account JSON paste only, `gcp-sa` auth, allowlist for resource manager, IAM and token exchange
    - Verify by JWT exchange (label `client_email`); CheckPermissions uses `testIamPermissions` with a fixed write probe set; nil Collector
    - _Requirements: 1.1, 1.2, 1.3, 2.2, 2.5, 3.5_
  - [-] 3.4 Bitbucket package
    - Create `bitbucket/manifest.go` and `bitbucket/provider.go`: email plus Atlassian API token paste, `basic` auth, `/2.0/user` and `/2.0/workspaces`
    - CheckPermissions reads `X-OAuth-Scopes` and reports `write`, `admin`, `delete` scopes; nil Collector
    - _Requirements: 1.1, 1.2, 1.3, 2.2, 3.5_
  - [-] 3.5 Cloudflare package
    - Create `cloudflare/manifest.go` and `cloudflare/provider.go`: API token paste, `bearer` auth, token verify, accounts and zones reads
    - CheckPermissions reports write permission groups, or `Unverifiable` when the token cannot read its policy; nil Collector
    - _Requirements: 1.1, 1.2, 1.3, 2.3, 3.5_
  - [~] 3.6 Kubernetes package
    - Create `kubernetes/manifest.go` and `kubernetes/provider.go`: API server URL, ServiceAccount token and CA paste (kubeconfig parsed into the three), `k8s-bearer` auth, `/version`, namespaces and `selfsubjectrulesreviews` reads
    - CheckPermissions reports rules with create, update, patch, delete or `*`; nil Collector
    - _Requirements: 1.1, 1.2, 1.3, 2.3, 3.5_

- [~] 4. Checkpoint - providers build
  - Run `go build ./...` and `go vet ./...` in `services/bellud`. Ask the user if questions arise.

- [ ] 5. Wiring, API and client
  - [~] 5.1 Register Sources in the service
    - In `service.go`, register the six manifests and providers in the Catalog next to `github` and `aws`, using `EffectiveClientID(os.Getenv)` for GitLab and Azure
    - Hide the six Sources while the `connectors` flag is off
    - Wire scope listing per Source and store the selection on the connection
    - _Requirements: 1.1, 1.5, 2.4, 2.5_
  - [~] 5.2 Update protocol and schema
    - Add manifest fields (`token_grant`, new auth method ids, per-source scope kinds) to the Protocol and Schema packages; keep dependency direction Schema → Core/Protocol → Server
    - Ensure responses never contain credential values
    - _Requirements: 3.3, 5.2_
  - [~] 5.3 Regenerate client and route table
    - Run `bun run generate` from `packages/client`; regenerate the route table in `services/bellud/internal/api/connectors` if routes changed. Do not edit generated files by hand
    - _Requirements: 5.2_

- [~] 6. Checkpoint - backend and client build
  - Run `go build ./...` in `services/bellud` and `bun typecheck` in `packages/client`. Ask the user if questions arise.

- [x] 7. Shared Wizard
  - [x] 7.1 Step machine and descriptor types
    - Create `wizard/machine.ts` with `transitionWizard(descriptor, state, event)`, steps `choose`, `create`, `paste`, `scope`, `done`, derived `selectWizardStep` and `selectCanGoBack`; failed verification keeps the step and stores the reason; sign-in skips `create` and `paste`
    - Define `SourceDescriptor` (methods, one instruction and one https docs link per step, paste fields, copy blocks) in `wizard/descriptor.ts`
    - _Requirements: 4.1, 4.3, 4.5, 4.7_
  - [x] 7.2 Wizard component
    - Create `wizard/wizard.tsx` and CSS: stepper, method cards, copy block, device prompt (copyable code and provider link), paste fields, scope list, Connected screen with the Describe result, failure reason display, "sign-in unavailable" note when no device method
    - _Requirements: 2.2, 4.1, 4.3, 4.4, 4.5, 4.6, 4.7_

- [ ] 8. Migrate AWS and GitHub
  - [~] 8.1 Migrate AWS
    - Create `descriptors/aws.ts`; fold `aws-wizard.ts` transitions into the generic machine unchanged; reduce `aws-panel.tsx` to descriptor plus shared Wizard
    - _Requirements: 4.2, 5.1_
  - [~] 8.2 Migrate GitHub
    - Create `descriptors/github.ts`; fold `github-wizard.ts` and `signin-machine.ts` into the generic machine unchanged; reduce `github-panel.tsx` to descriptor plus shared Wizard
    - Keep `connect-page.tsx` building each panel once, untracked, with untracked connection list reads
    - _Requirements: 4.2, 5.1_

- [~] 9. Checkpoint - app typecheck
  - Run `bun typecheck` in `packages/app`. Ask the user if questions arise.

- [ ] 10. New Source panels
  - [~] 10.1 GitLab and Bitbucket descriptors
    - Create `descriptors/gitlab.ts` (sign-in plus PAT) and `descriptors/bitbucket.ts` (email plus API token), register in the `PANELS` record in `connect-page.tsx`
    - _Requirements: 1.1, 2.1, 2.2, 4.2, 4.5_
  - [~] 10.2 Azure and Google Cloud descriptors
    - Create `descriptors/azure.ts` (sign-in plus service principal) and `descriptors/gcp.ts` (service-account JSON, role list copy block), register in `PANELS`
    - _Requirements: 1.1, 2.1, 2.2, 4.2, 4.5_
  - [~] 10.3 Cloudflare and Kubernetes descriptors
    - Create `descriptors/cloudflare.ts` (API token) and `descriptors/kubernetes.ts` (URL, token, CA or kubeconfig parse, kubectl YAML copy block), register in `PANELS`
    - _Requirements: 1.1, 2.3, 4.2, 4.5_

- [ ] 11. Logos, planned list and text
  - [~] 11.1 Logos
    - Run `packages/ui/script/connector-icons.ts` and use the generated `connectorLogos` entries on cards, detail and wizard header
    - _Requirements: 6.1, 6.2_
  - [~] 11.2 Remove planned entries and apply the flag and naming
    - Remove the six entries from `planned.ts` (keep the mechanism); confirm the six Sources are hidden through `enabled.ts` when the flag is off
    - Change user-facing text from "connectors" to "Sources"; keep code names
    - _Requirements: 1.4, 1.5, 4.8_

- [ ] 12. Docs
  - [~] 12.1 Per-source docs
    - Add a short page per Source under `docs/connectors` (auth method, required read-only permissions, how to connect, client ID env var for GitLab and Azure)
    - _Requirements: 2.1, 2.2, 3.5_

- [~] 13. Final checkpoint - build
  - Run `go build ./...` and `go vet ./...` in `services/bellud`, `bun typecheck` in `packages/client`, `packages/ui` and `packages/app`, then the app build, and `bun run check` from the root. Do not restart services. Ask the user if questions arise.

## Notes

- No test tasks in this round; tests come later and will use the correctness properties in design.md.
- Generated client files are never edited by hand.
- Checkpoints are build and typecheck only.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "7.1"] },
    { "id": 1, "tasks": ["1.3", "1.4", "7.2"] },
    { "id": 2, "tasks": ["3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "8.1"] },
    { "id": 3, "tasks": ["5.1", "5.2", "8.2"] },
    { "id": 4, "tasks": ["5.3", "10.1"] },
    { "id": 5, "tasks": ["10.2"] },
    { "id": 6, "tasks": ["10.3"] },
    { "id": 7, "tasks": ["11.1"] },
    { "id": 8, "tasks": ["11.2", "12.1"] }
  ]
}
```
