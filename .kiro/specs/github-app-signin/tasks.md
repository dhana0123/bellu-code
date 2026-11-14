# Implementation Plan: GitHub App Sign-In

## Overview

Backend first (Go in `services/bellud`, then protocol and client), then the UI in `packages/app`, then docs. Languages are Go and TypeScript, as in the design. The Client ID is not available yet. Every task must work with an empty `ClientID` constant: the manifest omits the `device` method, sign-in is hidden and Advanced is expanded. The project owner sets the constant after registering the App; no task here does that.

Defaults applied to the design's open decisions: no `fast-check` (TypeScript properties are exhaustive table tests over bounded event sequences), and the 30-minute abandon timer is an optional task.

## Tasks

- [x] 1. Client ID, manifest and broker
  - [x] 1.1 Add `github/clientid.go` (`ClientID` constant, `AppSlug`, `EffectiveClientID`) and extend the manifest
    - `manifest.DeviceSpec`, `Operation.IssuesCredential`, validation, `manifest.schema.json`, TS `ManifestAuthMethod`
    - GitHub manifest: `device` method (omitted when client id is empty), two `auth` ops, `github.com` egress, `/user/installations/{i}/repositories` read op; remove the "later release" rows
    - `connectors.New` reads the effective id once; never reads a secret variable
    - _Requirements: 1.2, 4.1, 4.2, 4.3, 4.7, 8.6, 8.7, 8.8, 16.2, 16.3_
  - [x] 1.2 Broker changes
    - `AuthNone`, `PreConnectionRef`, `checkAuthBody` (allowed keys only, `client_secret` blocked, fail closed), `issues_credential` response handling
    - _Requirements: 4.4, 4.6, 8.3, 8.4, 8.5, 9.7_
  - [x]* 1.3 Write property test for client id override
    - **Property 14: The effective client id follows the override rule**
    - **Validates: Requirements 4.2, 4.3**
  - [x]* 1.4 Write property test for device manifest validation
    - **Property 36: Device manifests are validated**
    - **Validates: Requirements 16.2, 16.3**
  - [x]* 1.5 Write property test for device-flow request bodies
    - **Property 15: Device-flow request bodies contain only allowed keys**
    - **Validates: Requirements 4.4, 8.3, 9.7**
  - [x]* 1.6 Write property test for the device endpoint allowlist
    - **Property 17: Device endpoints are reachable only by the lifecycle caller**
    - **Validates: Requirements 8.1, 8.2, 8.4, 8.5**

- [x] 2. Lifecycle and GitHub provider
  - [x] 2.1 Error codes and method-aware validation
    - Add `device_code_expired`, `authorization_denied`, `device_flow_disabled`, `already_pending` and `RetryAfterSec` (Go and TS); `MethodCredentialValidator`; GitHub `pat` vs `device` prefix rules
    - _Requirements: 11.2, 13.3, 13.4_
  - [x] 2.2 Verification, reconnect and expiry
    - `Verify` for `device` (`GET /user`, `GET /user/installations`), drop token on any verification failure, `ReconnectVerified`, `NonRefreshable` expiry in the supervisor, `PAUSED -> EXPIRED`
    - `Installations` and `InstallationRepositories` listing with 10 s deadline, de-duplication, `installations` and `installUrl` in the repo list, selection maximum of 500
    - _Requirements: 5.1, 5.4, 5.5, 5.8, 6.1, 6.2, 6.3, 6.4, 6.5, 9.2, 9.4, 9.5, 9.6, 9.7, 9.8_
  - [x] 2.3 Startup reconcile in `service.go`
    - Set credential-less GitHub Connections to EXPIRED before collectors start
    - _Requirements: 14.2, 14.3_
  - [x]* 2.4 Write property test for token prefix validation
    - **Property 33: Token prefix validation depends on the method**
    - **Validates: Requirements 11.2**
  - [x]* 2.5 Write property test for the account label
    - **Property 18: The account label equals the login GitHub returned**
    - **Validates: Requirements 6.2, 6.3**
  - [x]* 2.6 Write property test for failed verification
    - **Property 19: A failed verification leaves no token**
    - **Validates: Requirements 6.4, 6.5**
  - [x]* 2.7 Write property test for expiry recording
    - **Property 25: Expiry is recorded exactly when GitHub sends one**
    - **Validates: Requirements 9.2**
  - [x]* 2.8 Write property test for reconnect identity
    - **Property 27: Reconnect preserves identity**
    - **Validates: Requirements 9.5**
  - [x]* 2.9 Write property test for failed reconnect
    - **Property 28: A failed reconnect changes nothing**
    - **Validates: Requirements 9.8**
  - [ ]* 2.10 Write property test for startup reconcile
    - **Property 29: Startup reconcile expires exactly the credential-less Connections**
    - **Validates: Requirements 14.3**
  - [x]* 2.11 Write property test for repository union
    - **Property 31: Repository listing is the union across installations**
    - **Validates: Requirements 5.4**
  - [x]* 2.12 Write property test for selection bounds (Go)
    - **Property 32: Selection bounds and the required message**
    - **Validates: Requirements 5.4, 5.6**

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Generic `deviceflow` package
  - [x] 4.1 Pure `Poller` (`Next`: interval, `slow_down`, backoff capped at 60 s, expiry cutoff)
    - _Requirements: 3.1, 3.2, 3.3, 3.9_
  - [x] 4.2 `Service` (`Start`, `Status`, `Cancel`, `Close`) and wiring in `service.go`
    - In-memory entries and race-safe state transitions, device code zeroed on terminal state, redactor registration, strict audit (`device_authorization`) with rollback via `Connect` and `Abandon`, duplicate rejection, `https` and egress check on `verification_uri`, response decoding rules, refresh token never decoded, `rate_limited` with clamped `retryAfterSec`
    - _Requirements: 2.7, 2.8, 3.4, 3.5, 3.6, 3.7, 3.8, 3.10, 6.6, 6.7, 6.8, 6.9, 7.1, 7.2, 7.3, 7.7, 16.1, 16.5_
  - [ ] 4.3 Update `arch_test.go` (every non-infrastructure connector directory and `deviceflow` use the broker only), with a violating fixture
    - _Requirements: 16.6_
  - [ ]* 4.4 Add the 30-minute abandon timer for unsaved `connected` entries
    - _Requirements: 6.6, 6.7_
  - [x]* 4.5 Write property test for the poll schedule
    - **Property 8: The poll schedule never polls faster than the interval**
    - **Validates: Requirements 3.1, 3.2, 3.3**
  - [x]* 4.6 Write property test for network backoff
    - **Property 9: Network backoff is bounded, monotone and resets**
    - **Validates: Requirements 3.9**
  - [ ]* 4.7 Write property test for terminal outcomes
    - **Property 10: Terminal outcomes map to exactly one status and code**
    - **Validates: Requirements 3.5, 3.6, 13.2, 17.3**
  - [ ]* 4.8 Write property test for cancel racing a token
    - **Property 11: Cancel wins the race with a token**
    - **Validates: Requirements 3.7, 17.5**
  - [ ]* 4.9 Write property test for duplicate starts
    - **Property 12: A duplicate start is rejected without disturbing the first**
    - **Validates: Requirements 3.8**
  - [ ]* 4.10 Write property test for the start response
    - **Property 13: The start response never carries the device code**
    - **Validates: Requirements 2.8, 17.2**
  - [ ]* 4.11 Write property test for abandoning unsaved Connections
    - **Property 20: Abandoning an unsaved Connection removes it**
    - **Validates: Requirements 6.6, 6.7**
  - [ ]* 4.12 Write property test for audit entries
    - **Property 21: Every milestone writes one clean audit entry**
    - **Validates: Requirements 6.8**
  - [ ]* 4.13 Write property test for audit failure rollback
    - **Property 22: An audit failure rolls the attempt back**
    - **Validates: Requirements 6.9**
  - [ ]* 4.14 Write property test for secrecy across output channels
    - **Property 23: No secret reaches any output channel**
    - **Validates: Requirements 2.7, 7.1, 7.2, 7.3, 7.8**
  - [ ]* 4.15 Write property test for vault write failure
    - **Property 24: A failed vault write leaves the previous credential intact**
    - **Validates: Requirements 7.7**
  - [ ]* 4.16 Write property test for the retry time clamp
    - **Property 34: The retry time is a clamped whole number of seconds**
    - **Validates: Requirements 13.4**
  - [ ]* 4.17 Write property test for status lookups
    - **Property 37: Status lookups are exact and unknown ids are harmless**
    - **Validates: Requirements 17.3, 17.4**

- [x] 5. API and protocol
  - [x] 5.1 Schema and protocol
    - `packages/schema/src/connectors.ts` (device schemas, `GithubRepoList` fields, error codes, manifest fields) and `packages/protocol` group with exactly three `experimental.connectors.*` routes
    - _Requirements: 17.1, 17.2, 17.3_
  - [x] 5.2 Go handlers and routes
    - Start, status, cancel behind the `connectors` flag (404 when off); closed body parsers that ignore secret-like fields; reject `method: "device"` on public `createConnection`; `retryAfterSec` on errors; regenerate `testdata/operations.json`
    - _Requirements: 4.6, 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.8_
  - [x] 5.3 Run `bun run generate` from `packages/client`; do not edit generated files
    - _Requirements: 17.7_
  - [ ]* 5.4 Write property test for ignored secrets
    - **Property 16: Supplied secrets are ignored and never stored**
    - **Validates: Requirements 4.6**
  - [ ]* 5.5 Write property test for the request guard on the new routes
    - **Property 38: The request guard covers the new routes**
    - **Validates: Requirements 17.6**
  - [ ]* 5.6 Add the device routes to `token_export_property_test.go`
    - _Requirements: 7.5_

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Sign-in UI (`packages/app/src/settings/connectors`)
  - [x] 7.1 `signin-machine.ts`: six-phase union, closed events and effects, pure `transition`, selectors; compose `github-machine.ts` and accept `repos.retried` from `ready`
    - _Requirements: 1.4, 15.1-15.11, 15.14_
  - [x] 7.2 `signin.ts` driver: per-attempt abort, 2 s status poll with 5 s timeout, expiry timer, 15 s and 10 s request timeouts, `disposed` cleanup within 100 ms
    - _Requirements: 1.7, 3.11, 3.12, 5.8, 15.8, 15.9, 15.12, 15.13_
  - [x] 7.3 `errors.ts` (`CODE_KEYS satisfies Record<...>`), `request_timeout`, and all new English i18n keys
    - _Requirements: 13.6, 13.7, 18.1, 18.2_
  - [x] 7.4 Components
    - Generic `device-prompt.tsx`; `github-panel.tsx` (sign-in above a collapsed Advanced section, host selector, PAT exclusion, memory-only notice, install and Check again view); `connect-dialog.tsx` panel registry; reconnect with sign-in; GitHub `REVOCATION_URLS` entry; hide sign-in and expand Advanced when the catalog has no `device` method
    - _Requirements: 1.1, 1.3, 1.5, 1.6, 2.1-2.5, 2.9, 2.10, 4.7, 5.2-5.4, 9.3, 9.9, 10.2, 11.1, 11.4, 11.5, 12.1-12.5, 14.1, 14.4, 14.5, 16.4, 18.3-18.8_
  - [x]* 7.5 Write property test for one request per activation (table test over event sequences)
    - **Property 1: One activation starts at most one request**
    - **Validates: Requirements 1.4, 15.4, 15.5**
  - [x]* 7.6 Write property test for sign-in availability
    - **Property 2: The sign-in action is enabled exactly when it is allowed**
    - **Validates: Requirements 1.5, 1.6, 11.4, 11.5**
  - [x]* 7.7 Write property test for transition totality
    - **Property 3: Transition is total, pure and identity-preserving**
    - **Validates: Requirements 15.1, 15.2, 15.3, 15.13**
  - [x]* 7.8 Write property test for attempt ids
    - **Property 4: Attempt ids are unique and stale results are ignored**
    - **Validates: Requirements 13.5, 15.6, 15.7**
  - [x]* 7.9 Write property test for selectors
    - **Property 5: Selectors are a function of state and match the contract**
    - **Validates: Requirements 2.6, 2.11, 13.3, 15.10, 15.11**
  - [x]* 7.10 Write property test for countdown formatting
    - **Property 6: Countdown formatting round trips**
    - **Validates: Requirements 2.1**
  - [x]* 7.11 Write property test for terminal outcomes in the machine
    - **Property 7: A pending phase ends in exactly one terminal outcome**
    - **Validates: Requirements 2.10, 3.10, 13.8**
  - [x]* 7.12 Write property test for "Expires soon"
    - **Property 26: "Expires soon" shows inside the open window only**
    - **Validates: Requirements 9.3**
  - [ ]* 7.13 Write property test for host visibility
    - **Property 30: Sign-in visibility follows the host field**
    - **Validates: Requirements 12.1, 12.2, 12.3**
  - [x]* 7.14 Write property test for selection message (UI)
    - **Property 32: Selection bounds and the required message**
    - **Validates: Requirements 5.6, 5.7**
  - [ ]* 7.15 Write property test for error messages
    - **Property 35: Every error code has a message**
    - **Validates: Requirements 13.6, 13.7**
  - [ ]* 7.16 Write driver and component tests
    - Driver timers and disposal; Advanced collapsed, "Open GitHub" attributes, copy paths, one `Loader`, live region, memory-only notice, no-installation view, disconnect link
    - _Requirements: 2.2-2.6, 3.11, 3.12, 14.1, 15.12, 18.5-18.8_

- [ ] 8. Documentation
  - [x] 8.1 Write `docs/connectors/github-app.md`: registration checklist, secret policy, fork setup (`BELLUCODE_GITHUB_CLIENT_ID`, `BELLUCODE_GITHUB_APP_SLUG`), expiration disabled, master key setup; note the owner supplies the Client ID
    - _Requirements: 4.8, 9.1, 14.6, 19.1-19.4_
  - [x] 8.2 Write `docs/connectors/device-flow-connectors.md` with a non-GitHub worked example
    - _Requirements: 16.7_
  - [ ]* 8.3 Add smoke tests: single `ClientID` constant and no secret literal, new i18n keys exist, docs headings present
    - _Requirements: 4.1, 4.5_

- [x] 9. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked `*` are optional and can be skipped for a faster MVP.
- Each property test goes in its own file so tests can run in parallel.
- Run Go tests from `services/bellud`, TypeScript tests from the package directory, and `bun run check` from the root.
- The `connectors` flag guards everything; no new flag is added.

## Task Dependency Graph

```json
{
  "waves": [
    {
      "id": 0,
      "tasks": [
        "3"
      ]
    },
    {
      "id": 1,
      "tasks": [
        "4.2"
      ]
    },
    {
      "id": 2,
      "tasks": [
        "5.2",
        "8.1",
        "8.2"
      ]
    },
    {
      "id": 3,
      "tasks": [
        "5.3"
      ]
    },
    {
      "id": 4,
      "tasks": [
        "6"
      ]
    },
    {
      "id": 5,
      "tasks": [
        "7.2"
      ]
    },
    {
      "id": 6,
      "tasks": [
        "7.4"
      ]
    },
    {
      "id": 7,
      "tasks": [
        "9"
      ]
    }
  ]
}
```
