# Implementation Plan: Cloud Connectors (MVP)

## Overview

Scope is the MVP of the design's Phasing section only. Build bottom-up in Go under `services/bellud/internal/connectors/*`, then the HTTP/MCP layer, then protocol and client, then the Settings UI:

1. spike: AWS operation-name resolution in the RoundTripper;
2. flag, graph kinds, manifest, registry, policy;
3. key sources, audit, vault;
4. redactor, store, runner extensions, broker;
5. lifecycle state machine, manager, auth configs, supervisor;
6. checkpoint: Go core;
7. AWS provider, then GitHub provider (PAT only);
8. checkpoint: providers;
9. service assembly, `connector_read` MCP, HTTP API, route table, protocol, client regen;
10. checkpoint: API;
11. Settings → Connectors UI;
12. checkpoint: UI;
13. ops script and systemd unit, final checkpoint.

Conventions for every task:
- Go is at `/usr/local/go/bin`. Run Go commands (`go build ./...`, `go vet ./...`, `go test ./internal/connectors/... ./internal/api/connectors/...`) from `services/bellud`.
- Property tests use `pgregory.net/rapid` (already in `go.mod`), run at least 100 checks, and carry `// Feature: cloud-connectors, Property N: <title>`. Failure output passes through the redactor so counterexamples never print credentials.
- Use fakes (in-memory key source, counting `http.RoundTripper`, fake provider `Client`, fake clock, real `facade` engine and real `collectors.Runner`), not mocks of internals.
- Pin exact dependency versions when running `go get` (re-verify the versions listed in design D9 first).
- Bun tests run from the package directory (`packages/app`, `packages/protocol`, `packages/schema`), never from the repo root. Read the matching skill in `.bellucode/skills` (`unit-tests`, `component-tests`, `app-e2e-tests`) before writing TS tests. Use `bun typecheck` in the touched package while iterating and `bun run check` from the repo root at checkpoints.
- Follow `AGENTS.md`: no aliased or star imports, no `any`, early returns, English-only i18n, no `.changeset` files.
- No credential value may reach logs, errors, audit, graph batches, API responses, or the TS child at any step.

## Tasks

- [x] 1. Spike: AWS operation-name resolution
  - [x] 1.1 Prove the RoundTripper can resolve the AWS operation name
    - Add `aws-sdk-go-v2` core, `service/sts` and `service/ec2` at pinned versions. Create a throwaway-quality but committed test under `services/bellud/internal/connectors/broker/opname/` that builds an SDK client on a counting `http.RoundTripper` with a fake credentials provider.
    - Verify that the operation name set by the SDK's `RegisterServiceMetadata` middleware is readable from the request context inside the RoundTripper, and that it can be cross-checked against the body `Action=`, `X-Amz-Target` or REST path for STS (`GetCallerIdentity`, `AssumeRole`), EC2 (`DescribeInstances`) and S3 (`ListBuckets`).
    - If the context value is not reachable, implement the fallback in the same package: a Smithy `Initialize` middleware that stores the name under our own context key, plus a helper that installs it on `aws.Config`.
    - Expose a small `opname.Resolve(req *http.Request) (string, bool)` that returns false on a missing name or a mismatch with the wire action (fail closed). Record the chosen mechanism in a package doc comment.
    - Add a test for each operation above and for a mismatch and a missing name (both denied).
    - _Requirements: 3.12, 5.1, 5.2, 12.4, 16.1_

- [x] 2. Foundations: flag, graph kinds, manifest, registry, policy
  - [x] 2.1 Add the `connectors` feature flag in TS and Go
    - Add key `connectors` with a description to `packages/schema/src/config/flag.ts` (on in local/dev builds, off in releases).
    - Create `services/bellud/internal/connectors/flag.go` with `Enabled(getenv func(string) string) bool` mirroring the `BELLUCODE_FLAGS` grammar (`connectors`, `-connectors`, `all`) and the release-build default used by `graph.IsRelease()`.
    - Add table-driven Go tests for the grammar and release default; add or extend the schema flag test in `packages/schema` if one lists flag keys.
    - _Requirements: 11.4, 11.5, 1.2_

  - [x] 2.2 Register the seven connector graph kinds
    - In `services/bellud/internal/bellugraph/internal/bge/ident/ident.go` register `aws_account`, `aws_resource`, `github_org`, `github_repo`, `github_workflow`, `github_pull_request`, `github_alert` with the identity attributes (every kind includes `connection`) and descriptive attributes from the design's table. No attribute name may match the secret-name rule (use `detector`, never `secret_type`; no `data`).
    - Update the pinned kind count from 16 to 23 in `ident_test.go` and the facade/describe-schema tests that enumerate kinds.
    - _Requirements: 7.8, 7.13, 2.7_

  - [x] 2.3 Implement the `manifest` package and JSON Schema
    - Create `internal/connectors/manifest` with `Manifest`, `AuthMethod`, `Permission`, `Operation` and `FieldError` types, `Validate(m) []FieldError` (bounds: id 1–64 `[a-z0-9-]`, semver version, name 1–64, auth methods 1–5, permissions 0–50, operations 0–200, egress 0–50, entities 1–100; names offending fields and never echoes values) and `IsWrite(op)` (method and verb classifier, AWS verb prefixes).
    - Reject any operation classified as write but listed `class: read`.
    - Embed `manifest.schema.json` and publish a copy under `docs/connectors/manifest.schema.json`. JSON round-trip serialization for manifests.
    - _Requirements: 5.8, 8.1, 8.2, 8.3, 8.14_

  - [x]* 2.4 Write property tests for manifest validation and serialization
    - **Property 8: Manifest validation**
    - **Property 9: Manifest and state serialization round trip** (manifest part)
    - **Validates: Requirements 5.8, 8.2, 8.3, 8.14, 9.2**

  - [x] 2.5 Implement the `registry` package
    - `Registry` interface (`List`, `Get`, `Register`) backed by a mutex-guarded map. `Register` runs `manifest.Validate` and rejects duplicate ids. Built-in and plugin entries share one `Entry` shape with a `Plugin` indicator.
    - Add unit tests for duplicate id, invalid manifest, and identical shape for built-in and plugin entries.
    - _Requirements: 8.1, 8.3, 5.8_

  - [x] 2.6 Implement the pure `policy` package
    - `Request`, `Decision`, `Reason`, `Selection`, `Compile(manifest, selection)` and `(*Policy).Check`. Allow only GET/HEAD/OPTIONS or a listed read-query operation, only hosts in the Egress_Allowlist for the selected regions or GHES host, only operations on the read allowlist. Unknown or unresolved operation is a deny (fail closed). Class `auth` is allowed only for caller `lifecycle`. Agent caller additionally requires the scope inputs (added in task 10.2).
    - _Requirements: 3.12, 4.12, 5.1, 5.2, 8.11, 16.1, 16.6_

  - [x] 2.7 Write property test for the policy allowlist
    - **Property 7: Policy decision equals allowlist membership** (pure `Check` part; broker-level zero-egress and audit assertion is task 4.8)
    - Generate requests (method, host, path, operation, class, caller) against compiled policies; assert allow iff method, host and operation conditions hold, and that unresolved operations are denied.
    - **Validates: Requirements 3.12, 4.12, 5.1, 5.2, 8.11, 12.4, 16.1, 16.6**

- [x] 3. Key sources, audit log and Credential_Vault
  - [x] 3.1 Implement the `keysource` package
    - `Source` interface and `Select(ctx, order)`. Sources: `oskeyring` (`github.com/zalando/go-keyring`, must report unavailable without hanging when no Secret Service exists: wrap in a short timeout), `systemd` (read `$CREDENTIALS_DIRECTORY/bellucode-master-key`, then unset `CREDENTIALS_DIRECTORY`), `keyfile` (`BELLUCODE_MASTER_KEY_FILE`, must be mode 0400, owned by the bellud user, outside the data dir), `passphrase` (Argon2id from `golang.org/x/crypto`, 16-byte random salt, m=65536, t=3, p=4, 32-byte key, reject passphrases shorter than 12 characters; params and salt stored in a non-secret header beside `vault.json`).
    - Priority order: OS key store, systemd credential, key file, passphrase. Master_Key pages are `mlock`ed and the process sets `PR_SET_DUMPABLE=0` where supported.
    - Add a small spike-style test showing `go-keyring` with no Secret Service reports unavailable promptly, and a systemd-creds read-path test using a temp `CREDENTIALS_DIRECTORY`.
    - _Requirements: 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 6.11_

  - [x]* 3.2 Write property test for key source selection and passphrase rules
    - **Property 27: Master key source selection and passphrase rules**
    - **Validates: Requirements 6.3, 6.6**

  - [x] 3.3 Implement the `audit` package
    - Append-only JSONL under `connectors/audit/audit-YYYY-MM-DD.jsonl` (dir 0700, files 0600, `O_APPEND`, fsync before return), `Entry` with `Seq`, UTC millisecond `TS`, ids, `Event`, `Outcome`, `Actor`, sanitized `Detail`, and `Prev` hash chain. `List(connID, cursor, limit)` newest first, 50 per page, also filtered by retention window. `Prune(now, retentionDays)` deletes whole day files at start and every 24 h; reject retention outside 1–365. No update or delete API.
    - Define the event type constants listed in the design.
    - _Requirements: 9.1, 9.2, 9.4, 9.5, 9.6_

  - [x]* 3.4 Write property test for audit paging, retention and entry round trip
    - **Property 12: Audit paging and retention**
    - **Property 9: Manifest and state serialization round trip** (audit entry part)
    - **Validates: Requirements 9.2, 9.4, 9.6**

  - [x] 3.5 Implement the `vault` package (envelope encryption and Opener)
    - `Ref`, `Meta`, `Vault`, `Opener` interfaces. Per-credential random 256-bit DEK, AES-256-GCM with a fresh 96-bit random nonce, AAD `"bellud.vault.v1" || len‖connectorId || len‖ownerId || len‖slot || be64(version)`, DEK wrapped under the Master_Key with AAD `kid|owner|ownerId|slot|version`. `vault.json` (0600 in a 0700 directory) written via temp file + fsync + rename + directory fsync. `Put` zeroes the input secret; `Use` zeroes the plaintext buffer on return (success or failure), with `clear()` and `runtime.KeepAlive`. Last 4 characters stored in clear as `Meta.Last4`.
    - Startup mode verification: try to set the expected mode once, then refuse to load and report `store`, `directory` or `key-file` without touching data.
    - Memory-only mode when no key source is available: in-process map, `Status().Persistent=false`, notice text for the UI.
    - Decrypt failure appends an audit entry that logs only the record ref, never key material, ciphertext or plaintext. `Put` appends audit first and fails with `audit_failed` leaving the stored credential unchanged.
    - _Requirements: 6.1, 6.2, 6.4, 6.7, 6.8, 6.9, 6.10, 6.11, 6.13, 9.3, 10.5_

  - [x] 3.6 Write property test for vault round trip
    - **Property 1: Vault round trip**
    - Credentials of 1–65,536 bytes including non-ASCII and control bytes; arbitrary connector id, connection id, slot, version.
    - **Validates: Requirements 6.1, 12.1**

  - [x] 3.7 Write property test for tamper and AAD binding
    - **Property 2: Tamper and AAD binding**
    - Single-bit flip, truncation or appended byte in ciphertext, nonce or wrapped DEK, and any change of connector id, connection id, slot or version; assert error, zero plaintext bytes, and an audit entry with no key material, ciphertext or plaintext.
    - **Validates: Requirements 6.2, 10.5, 12.2**

  - [x]* 3.8 Write property tests for fresh DEK/nonce and buffer zeroing
    - **Property 3: Fresh data key and nonce per seal**
    - **Property 4: Plaintext buffer is zeroed after use**
    - **Validates: Requirements 6.1, 6.11**

  - [x] 3.9 Implement Master_Key rotation and Forget all in the vault
    - `RotateMasterKey`: write the new key under slot `next`, re-wrap every DEK into `vault.json.new`, fsync, rename, then promote `next`; startup recovery promotes `next` when `kid` matches. No plaintext credential is written to disk. Failure before the rename leaves the old file untouched and returns an error. Offer rotation only for key sources that can store (os-keyring, key file, passphrase).
    - `ForgetAll`: delete records and wrapped keys, drop the cached Master_Key and in-memory credentials, complete within 5 s, audit `vault_forget`.
    - _Requirements: 6.17, 6.18, 6.19, 6.20_

  - [x]* 3.10 Write property test for rotation atomicity
    - **Property 26: Master key rotation atomicity** (inject a failure at every step)
    - **Validates: Requirements 6.17, 6.18**

- [x] 4. Redactor, store, runner extensions and broker
  - [x] 4.1 Implement the `redactor` package and graph guard
    - `Register(secret) (release)`, `String`, `JSON`, `Guard(base redact.Guard) redact.Guard`. Detect registered values (≥8 bytes) in plain, JSON-escaped, base64 and URL-escaped forms plus known token patterns; replace with `[REDACTED:credential]`. The guard delegates `Scrub` to the base and makes `Leaks` true when any registered value appears (it must not scrub registered values from batches).
    - _Requirements: 6.16, 7.6, 7.7, 15.5, 16.3, 16.4_

  - [x] 4.2 Write property test for secret redaction on every channel
    - **Property 5: Secret redaction on every output channel**
    - Credentials of 8–4,096 characters including non-ASCII and control characters embedded in log lines, error messages, audit entries, graph batches, API responses and Proxy_Request results; assert absence of the verbatim, JSON-escaped, base64 and URL-escaped forms and that the non-secret remainder is unchanged.
    - **Validates: Requirements 6.16, 12.3, 15.5, 16.3, 16.4**

  - [x] 4.3 Implement the `store` package (`state.json`)
    - Types for settings, auth configs, connections (with `removed` tombstone, `selection`, `intervalSec`, `allowAgentLiveReads`, `permissionCheck`, `lastSync`), scopes and plugins as in the design's data model. Atomic temp+fsync+rename writes, 0600/0700. No secrets in this file.
    - Validators: alias 1–40 chars and unique per connector, collection interval whole minutes 1 min–24 h (default 15 min), rotation interval 1–365 days (default 90), retention 1–365 days; rejections name the field or allowed range and keep the previous value. Connections are created with `allowAgentLiveReads=false`.
    - _Requirements: 1.12, 1.13, 1.15, 7.10, 9.6, 9.10, 17.6_

  - [x]* 4.4 Write property tests for store validators and state round trip
    - **Property 13: Account alias validation**
    - **Property 14: Bounded settings validators**
    - **Property 9: Manifest and state serialization round trip** (state document part)
    - **Validates: Requirements 1.13, 1.15, 7.10, 9.6, 9.10**

  - [x] 4.5 Extend `collectors.Runner` for connector runs
    - Optional `interface{ Timeout() time.Duration }` on a Collector (connector runs 120 s, built-ins keep 30 s), `Runner.Forget(name)` to remove a collector's `collector_status` entity on the next status write, and `PartialError{Types []string}` so a run records `ok` with `last_error = "partial: ec2,rds"`. Backward compatible; do not edit existing tests, add new ones.
    - _Requirements: 7.4, 7.9, 10.4_

  - [x] 4.6 Write property test that leaking batches are discarded
    - **Property 6: Leaking batches are discarded**
    - Real `collectors.Runner` built with `collectors.WithGuard(redactor.Guard(redact.New()))` and the real `facade` engine; embed a registered credential in any key, value or nested position; assert nothing is applied, prior entities are unchanged, `collector_status` is `leak`, and status text, logs and events do not contain the value.
    - **Validates: Requirements 7.6, 7.7**

  - [x] 4.7 Implement the `broker` package
    - `Broker.Do` and `Broker.HTTPClient`. Single policy `RoundTripper` in the order: policy check, rate limit (10 req/s per connection via `golang.org/x/time/rate`, honoring `Retry-After`, `X-RateLimit-Reset` and AWS throttling), credential injection through `vault.Opener` (GitHub `Authorization` header; AWS vault-backed `aws.CredentialsProvider`), dial with `Dialer.Control` blocking loopback, link-local and metadata addresses (IMDS only for the AWS ambient source, STS only), response redaction and `StripKeys`, size caps. Re-check every redirect hop. 30 s per-call deadline returns a typed network error. Use `opname.Resolve` from task 1.1 for AWS.
    - A blocked call sends zero bytes and appends an audit entry (connection id, caller, operation, violated policy) before returning. Vault release failure sends zero requests and returns a typed credential-free error. Panics are recovered into a generic error.
    - _Requirements: 5.1, 5.2, 7.12, 16.1, 16.2, 16.3, 16.4, 16.6, 16.7, 16.8_

  - [x] 4.8 Write property test for broker-level deny behavior
    - **Property 7: Policy decision equals allowlist membership** (broker part)
    - With a counting transport, assert denied calls produce zero outbound requests and an audit entry written before the error returns; unresolved operations are denied; a read allowlist rejection never reaches the transport.
    - **Validates: Requirements 5.2, 12.4, 16.6**

  - [x]* 4.9 Write property test for rate limiting
    - **Property 31: Rate limiting** (fake clock; no sliding one-second window exceeds 10 sent requests; nothing is sent before a provider-indicated retry time)
    - **Validates: Requirements 7.12**

- [x] 5. Lifecycle: state machine, manager, auth configs, supervisor
  - [x] 5.1 Implement `lifecycle.Next` and the typed error set
    - `Status` constants and the pure `Next(from, to)` table exactly as Requirement 14.9. Typed errors `invalid_credential`, `insufficient_permission`, `excess_permission`, `network`, `rate_limited`, `expired` plus the non-credential codes from the design, each with a message of at most 200 characters passed through the redactor.
    - _Requirements: 14.1, 14.9, 10.1_

  - [x] 5.2 Write property test for lifecycle transitions
    - **Property 10: Lifecycle transitions**
    - Arbitrary sequences of requested changes from any status; assert the status changes iff the pair is in the table, every accepted change appends an audit entry with previous status, new status and timestamp, every rejected change appends a rejection entry, and the connection is always in exactly one status.
    - **Validates: Requirements 2.3, 14.1, 14.8, 14.9**

  - [x] 5.3 Implement `lifecycle.Manager` and the `Provider` interface
    - A provider-neutral `Provider` interface (`Verify`, `CheckPermissions`, `Refresh`, `Collector`) registered per connector id. Manager methods: `Create`, `Test`, `Reconnect`, `Rotate`, `Pause`, `Resume`, `SyncNow`, `Update`, `Disconnect` as in the design.
    - Create: INITIATED, audit, `vault.Put`, VERIFYING, identity and permission checks via the broker (30 s deadline), then ACTIVE or ERROR. Excess permission: ERROR, name every offender, delete the stored credential on first verification, start no collector. Verification errors return exactly one typed error and leave state and stored credential unchanged for tests. Rotate verifies the candidate first and swaps only if both checks pass. Reconnect keeps connection id, alias and source tag. Disconnect: stop collectors ≤5 s, delete the credential (on vault delete failure keep state and keep collectors stopped), apply an empty full observation for the collector name, `Runner.Forget`, then mark removed. Every state change and rejected change is audited; audit failure fails connect, rotate and credential release.
    - _Requirements: 2.3, 2.4, 2.5, 2.6, 2.7, 2.10, 2.11, 5.6, 9.3, 9.7, 9.8, 9.9, 10.1, 14.3, 14.4, 14.5, 14.8_

  - [x] 5.4 Implement Auth_Config service
    - Exactly one immutable default Auth_Config per connector (no built-in app secret in any response); custom configs (name 1–40 unique, required settings present, only scopes in the manifest's read-only scope set, max 10 per connector) with app secrets stored in the vault. Creation or deletion failing at any vault step leaves no orphan secret and no partial config. Deleting a config in use is rejected with the exact count of using connections.
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9_

  - [x] 5.5 Implement the `Supervisor` and credential refresh scheduler
    - One goroutine per ACTIVE connection started within 5 s and stopped within 5 s on any transition out of ACTIVE; interval 1 min–24 h; failure backoff `min(1m·2^(n-1), 15m)` reset on success; run through `Runner.RunOnce`; HTTP 401 → EXPIRED and 403 → ERROR without retry while keeping last graph data; network errors retried up to 3 times with increasing delay then data marked stale; manual sync returns `run_in_progress` for a concurrent run; permission re-check every 24 h (retry within 1 h when the provider is unreachable, retain state, audit); write permission found suspends collection within 60 s and sets ERROR. Session refresh at `expiry − 300 s` (immediately if less remains), three retries then EXPIRED with in-memory credentials dropped; derived `expiresSoon` flag when fewer than 7 days remain.
    - _Requirements: 5.5, 5.6, 5.7, 7.1, 7.2, 7.5, 7.11, 10.2, 10.3, 14.3, 14.6, 14.7, 4.9, 4.10_

  - [x]* 5.6 Write property test for audit completeness and fail-closed
    - **Property 11: Audit completeness and fail-closed**
    - **Validates: Requirements 9.1, 9.2, 9.3**

  - [x]* 5.7 Write property test for Auth_Config validation and lifecycle
    - **Property 15: Auth_Config validation and lifecycle** (inject vault failures at every step)
    - **Validates: Requirements 13.2, 13.3, 13.4, 13.6, 13.7, 13.8, 13.9**

  - [x]* 5.8 Write property test for full-observation semantics
    - **Property 29: Full-observation semantics** (real `facade` engine; failed or timed-out runs leave entities unchanged; empty observation removes all)
    - **Validates: Requirements 2.7, 7.3, 7.5**

  - [x]* 5.9 Write property test for failure backoff
    - **Property 30: Failure backoff** (fake clock)
    - **Validates: Requirements 7.5**

  - [x]* 5.10 Write property test for excess permission classification
    - **Property 20: Excess permission classification**
    - **Validates: Requirements 2.5, 3.8, 3.9, 4.5, 5.6**

  - [x]* 5.11 Write property test for typed verification errors
    - **Property 34: Typed verification errors**
    - **Validates: Requirements 10.1**

  - [x]* 5.12 Write property test for rotation and reconnect outcomes
    - **Property 35: Rotation and reconnect outcomes**
    - **Validates: Requirements 9.8, 9.9, 14.4, 14.5**

  - [x]* 5.13 Write property test for credential refresh schedule
    - **Property 24: Credential refresh schedule**
    - **Validates: Requirements 3.4, 4.10, 14.6**

- [x] 6. Checkpoint: Go core
  - From `services/bellud`, run `go build ./...`, `go vet ./...` and `go test ./internal/connectors/... ./internal/collectors/... ./internal/bellugraph/...`. Ensure all tests pass, ask the user if questions arise.

- [x] 7. AWS provider
  - [x] 7.1 Implement the AWS wrapper client and auth
    - Add pinned `service/iam`, `service/s3`, `service/lambda`, `service/rds`, `credentials` modules. `aws/client.go` is the only file importing `aws-sdk-go-v2`; it exposes the typed `Client` interface (`Identity`, `SimulateWrites`, `Instances`, `Buckets`, `SecurityGroups`, `VPCs`, `Roles`, `Functions`, `DBInstances`, region listing) returning typed projections only. The SDK is built on `broker.HTTPClient` and the operation resolver from task 1.1.
    - `aws/auth.go`: AssumeRole with external ID in every call (source identity `ambient` or `vault`, used only for `sts:AssumeRole`/`GetCallerIdentity`, class `auth`), `DurationSeconds ≤ 3600`, `aws.CredentialsCache` refresh at `expiry − 300 s`, three retries with backoff then report expired, memory-only session credentials; static keys via a vault-backed provider; "Detect principal" via `GetCallerIdentity` converting session ARNs to role ARNs. SSO is not implemented (shown disabled in the UI).
    - _Requirements: 3.1, 3.3, 3.4, 3.5, 3.7, 3.8, 3.10, 3.12, 14.6, 14.7_

  - [x] 7.2 Implement external ID generation and trust templates
    - `aws/templates.go`: external ID from `crypto/rand` (32 random bytes, base32, prefix `BELLU-`, ≥32 characters, unique per connection); CloudFormation YAML and Terraform snippets embedding the external ID, trust principal, `ReadOnlyAccess`/`SecurityAudit` (with the custom-policy note) and an inline statement allowing `iam:SimulatePrincipalPolicy` on the role itself.
    - _Requirements: 3.2, 3.6_

  - [x] 7.3 Implement the AWS manifest and `Provider` (verify and test)
    - Built-in manifest: hosts `sts.<r>`, `iam`, `ec2.<r>`, `s3.<r>`, `*.s3.<r>`, `lambda.<r>`, `rds.<r>` for selected regions only (≥1 region required); read operations `ec2:Describe{Instances,SecurityGroups,Vpcs,Regions}`, `s3:ListBuckets|GetBucketLocation`, `iam:ListRoles|SimulatePrincipalPolicy`, `lambda:ListFunctions`, `rds:DescribeDBInstances`, `sts:GetCallerIdentity`; class `auth` `sts:AssumeRole`. Register through the registry; it must validate against the JSON Schema. SSO method listed as disabled.
    - Verify: `GetCallerIdentity` (reject `arn:aws*:iam::<12 digits>:root` and discard the credential), `SimulatePrincipalPolicy` for the fixed write list, plus a separate non-blocking `data_read` warning list; `AccessDenied` on the simulation maps to `insufficient_permission`. Strict rule: any allowed write action means no activation (acknowledging the warning only precedes fixing the role and Reconnect).
    - _Requirements: 3.1, 3.8, 3.9, 3.10, 3.11, 3.12, 2.4, 2.5, 5.5_

  - [x] 7.4 Implement the AWS collector
    - `aws/collector.go` imports only the `Client` interface, never an SDK or `net/http`. Collect account, EC2 instances, security groups, VPCs, S3 buckets, IAM roles, Lambda functions, RDS instances for selected regions only; relations `owned_by`, `attached_to`, `runs_on`; every entity has `source = "connector:aws:<connection_id>"` and the connection in its identity; metadata only (no object contents, env var values, secrets). A failing resource type does not stop others and is reported via `PartialError`. Name the collector `connector:aws:<connection_id>`; implement `Timeout()` returning 120 s.
    - _Requirements: 3.11, 7.1, 7.3, 7.8, 7.13, 10.4_

  - [x]* 7.5 Write property test for AWS root identity rejection
    - **Property 21: AWS root identity rejected**
    - **Validates: Requirements 3.10**

  - [x]* 7.6 Write property test for external ID and trust templates
    - **Property 23: External ID and trust templates** (≥32 chars and distinct; YAML/HCL parse with the external ID embedded; every `AssumeRole` across refreshes carries the external ID)
    - **Validates: Requirements 3.2, 3.3**

  - [x]* 7.7 Write property tests for AWS collector output
    - **Property 28: Collector output hygiene** (AWS fixtures)
    - **Property 32: Selection confinement** (regions)
    - **Property 33: Partial failure isolation**
    - **Validates: Requirements 7.8, 7.13, 3.11, 10.4**

- [x] 8. GitHub provider (fine-grained PAT only)
  - [x] 8.1 Implement the GitHub wrapper client and PAT auth
    - `github/client.go` (plain `net/http` through `broker.HTTPClient`, typed projections: user, installation repositories, org, repo, pulls, workflows, code-scanning, Dependabot and secret-scanning alerts, issue counts). `github/auth.go`: enforce the `github_pat_` prefix before anything is stored (classic tokens rejected with a message that they cannot be limited to read-only permissions or specific repositories; nothing stored, no connection created or changed). Token expiry from the response header is recorded when present. No GitHub App or device-flow code.
    - _Requirements: 4.2, 4.3, 4.9, 4.12_

  - [x] 8.2 Implement the GitHub manifest and `Provider`
    - Built-in manifest: hosts `api.github.com` and the validated GHES host (https only); GET read operations from the design (secret-scanning with `StripKeys: ["secret"]`; issues count only); `POST /graphql` only if the body parses to a `query` operation (via `gqlparser`). Auth methods list App and device flow as disabled ("Available in a later release"), PAT enabled, keeping the Requirement 4.1 order.
    - Verify: `/user`, accessible repositories list; set `permission_check = "unverifiable"` with the message "Permissions can't be verified; write requests are still blocked by the allowlist"; connection may become ACTIVE. Repository selection stored on the connection (≥1 required after a selection event).
    - _Requirements: 4.1, 4.3, 4.4, 4.5, 4.11, 4.12, 5.1_

  - [x] 8.3 Implement the GitHub collector
    - `github/collector.go` imports only the typed `Client`. Collect org, repos, workflows, open PRs, code-scanning, Dependabot and secret-scanning alert metadata for selected repositories only; relations `owned_by`; attributes avoid secret-name fragments (`detector`, never `secret_type`); the alert `secret` field is never mapped. Name `connector:github:<connection_id>`; `Timeout()` 120 s; partial failures reported via `PartialError`. Bodies of PRs and issues and file or commit contents are not ingested.
    - _Requirements: 4.11, 7.1, 7.3, 7.8, 7.13, 10.4_

  - [x]* 8.4 Write property test for GitHub token prefix
    - **Property 22: GitHub token prefix**
    - **Validates: Requirements 4.2**

  - [x]* 8.5 Write property tests for GitHub collector output
    - **Property 28: Collector output hygiene** (GitHub fixtures, including a secret-scanning response carrying a `secret` value)
    - **Property 32: Selection confinement** (repositories)
    - **Property 33: Partial failure isolation**
    - **Validates: Requirements 7.8, 7.13, 4.11, 10.4**

- [x] 9. Checkpoint: providers
  - From `services/bellud`, run `go build ./...`, `go vet ./...` and `go test ./internal/connectors/...`. Ensure all tests pass, ask the user if questions arise.

- [x] 10. Service assembly, MCP, HTTP API, route table, protocol and client
  - [x] 10.1 Assemble `connectors.Service`
    - `internal/connectors/service.go`: when `Enabled`, select the key source, open vault, audit, store, registry (register AWS and GitHub manifests), redactor, broker, manager and supervisor, and build a dedicated `collectors.Runner` with `WithGuard(redactor.Guard(redact.New()))`. Start supervisors for connections persisted as ACTIVE. When disabled, nothing is constructed, the vault is not opened and no goroutine starts. Expose a `Close` that stops supervisors and drops cached keys. Expose a status method (key source name, persistent flag, warnings).
    - _Requirements: 11.5, 6.3, 6.5, 6.7, 7.1, 7.6_

  - [x] 10.2 Implement Session_Scope and the `connector_read` MCP endpoint
    - `Scope` store (principal `agent`, connectors, connections, operations each ⊆ the connector's read allowlist; invalid operation rejected naming it, previous scope kept). Default empty scope denies every Proxy_Request. `internal/api/connectors/mcp.go` serves `/api/experimental/connectors/mcp` with its own per-start bearer token (separate from graph tokens) and one tool `connector_read` (`connection`, `operation`, `params`) that calls `broker.Do` with caller `agent:<principal>`; decision is scope ∧ live-read flag ∧ allowlist, denial audits principal, connection, operation and reason; responses redacted, projected, capped at 64 KiB. Changes to scope or the live-read flag take effect within 5 s through an atomic snapshot re-checked before dialing.
    - _Requirements: 16.5, 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7_

  - [x] 10.3 Write property test for the scope decision
    - **Property 19: Scope decision** (required security property)
    - **Validates: Requirements 16.5, 17.1, 17.2, 17.3, 17.4**

  - [x] 10.4 Implement the HTTP API group core and request guards
    - `internal/api/connectors`: router, middleware (1 MiB body limit before parsing, schema validation before any other processing, field-naming validation errors that never echo values, loopback `RemoteAddr`, `Host` allowlist, `Sec-Fetch-Site != cross-site`, required `X-Bellucode-Client` header for credential-bearing writes, audit on rejection), credential-option detection (query, header, body field, `debug`) that is ignored and audited with the caller role, and the routes `status`, `catalog`, `listConnections`, `createConnection`, `getConnection`, `updateConnection`, `deleteConnection` returning masked metadata only (last 4, created, expiry).
    - Typed error mapping to `settings.connectors.error.<code>` codes; no route returns a credential, wrapped key or Master_Key.
    - _Requirements: 1.3, 1.12, 6.13, 6.14, 6.15, 11.5, 11.6, 11.10, 11.11, 11.12, 15.1, 15.2, 15.3, 15.4_

  - [x] 10.5 Implement the remaining MVP routes
    - `testConnection`, `syncConnection` (409 when running), `pauseConnection`, `resumeConnection`, `reconnectConnection`, `rotateCredential`, `listAudit` (cursor, 50 per page), `listAuthConfigs`, `createAuthConfig`, `deleteAuthConfig`, `awsSetup` (external ID + CloudFormation + Terraform + detected principal), `listGithubRepos`, `getScope`, `putScope`, `unlockVault`, `rotateMasterKey`, `forgetAll`. Do not implement the plugin, device-flow, or App routes. Disconnect confirmation data and the provider revocation link come from the catalog entry.
    - _Requirements: 2.4, 2.6, 3.2, 4.4, 7.11, 9.4, 9.7, 9.8, 13.2, 13.5, 6.17, 6.19, 17.1_

  - [x]* 10.6 Write property tests for credential write authorization and body validation
    - **Property 17: Credential write authorization**
    - **Property 18: Request body validation**
    - **Validates: Requirements 6.14, 6.15, 11.10, 11.11, 11.12**

  - [x] 10.7 Write the no-token-export route scan and planted-credential scan
    - **Property 16: No token export across routes**
    - Plant a random credential in a connection, call every registered connector route with valid, invalid and credential-requesting inputs, assert no body or header contains a substring longer than 4 characters, only last 4/created/expiry are returned, and an audit entry exists for each credential-requesting option. Enumerate the router and fail when a registered route is not exercised.
    - Add the scan test of Requirement 12.5 for AWS and GitHub fakes: run connect, test, collect and failure flows, then scan `state.json`, `vault.json`, audit files, captured logs, every API response and the bytes sent to the TS child for each planted value; zero hits. Assert a Proxy_Request result, error and audit entry for a collector and for `connector_read` contain no planted value.
    - **Validates: Requirements 6.13, 12.5, 15.1, 15.2, 15.3, 15.4, 15.6, 15.7, 16.9**

  - [x] 10.8 Wire bellud, the route table and the TS child
    - `cmd/bellud/main.go`: after `openGraph`, build `connectors.Service` when enabled; `goHandler` mounts `/api/experimental/connectors/` on a top-level mux before the graph `roleMiddleware`; `graphGoAuth` adds a bearer-only authorizer for the connector MCP path only (graph tokens and the child credential are not accepted on connector routes, the connector token opens only the MCP route).
    - `server/routes/generate.go`: add `/api/experimental/connectors/` to `goOwnedPrefixes` and the MCP route to the extra routes; regenerate `routes.yaml` and `testdata/operations.json` and run the route tests.
    - `tschild`: add `CREDENTIALS_DIRECTORY`, `BELLUCODE_MASTER_KEY_FILE`, `BELLUCODE_VAULT_PASSPHRASE` to the stripped env list; inject the `bellu-connectors` MCP entry into the child only while the flag is on.
    - Add Go tests for flag-off (no route registered, no vault opened), route ownership, and the stripped env list.
    - _Requirements: 6.12, 11.5, 11.6, 16.1, 17.2_

  - [x] 10.9 Add shared schemas and protocol declarations
    - `packages/schema/src/connectors.ts`: shared Effect schemas for connector routes. `packages/protocol/src/groups/experimental-connectors.ts`: declaration-only group (no TS handler, like `experimental-graph.ts`) with path `/api/experimental/connectors/...`, identifier `experimental.connectors.<name>` and the description suffix "Experimental: may change without compatibility guarantees." for every MVP route in the design's table (excluding plugin and device-flow routes). Register the group in the public HttpApi.
    - Extend `packages/protocol/test/experimental-identifiers.test.ts` with the both-directions check for `/api/experimental/connectors/*` ↔ `experimental.connectors.*`. Run from `packages/protocol` and `packages/schema`: `bun test` and `bun typecheck`.
    - _Requirements: 11.6, 11.7, 11.8_

  - [x] 10.10 Regenerate the client
    - From `packages/client`, run `bun run generate`; do not edit generated files. Run it a second time and confirm there is no diff. Run `bun typecheck` in `packages/client` and `packages/sdk` if they consume the generated types.
    - _Requirements: 11.9_

  - [x]* 10.11 Write architecture import-graph tests
    - Using `go/packages`, assert (a) collectors import neither `net/http` clients nor `aws-sdk-go-v2`, (b) `vault.Opener` is used only in `broker`, `lifecycle` and provider `auth` files, (c) provider clients are built only from `broker.HTTPClient`.
    - _Requirements: 5.4, 16.1, 6.12_

- [x] 11. Checkpoint: API
  - From `services/bellud`, run `go build ./...`, `go vet ./...` and `go test ./...`. From `packages/protocol` run `bun test` and `bun typecheck`. From the repo root run `bun run check`. Ensure all tests pass, ask the user if questions arise.

- [x] 12. Settings → Connectors UI
  - [x] 12.1 Add `ConnectorIcon` and the `plug` icon
    - `packages/ui/src/components`: monochrome `currentColor` SVGs for the 11 services (Cloudflare, AWS, GitHub, GitLab, Sentry, MongoDB, Railway, Azure, Google Cloud, Render, Supabase). Add `plug` to the UI icon set if missing. No hex colors.
    - _Requirements: 1.3, 1.4, 1.11_

  - [x] 12.2 Add English i18n keys
    - Add all `settings.connectors.*` strings (labels, buttons, badges, states, dialog text, warnings including key-file/passphrase warnings and the PAT "Permissions can't be verified…" message, typed error messages, assistive-technology labels, "Coming soon", "Available in a later release") to `packages/app/src/runtime/i18n/en.ts` only. Add a test asserting no non-English catalog defines a `settings.connectors.` key and that a missing key falls back to English.
    - _Requirements: 11.1, 11.2, 11.3_

  - [x] 12.3 Implement `machine.ts` (pure logic)
    - `packages/app/src/settings/connectors/machine.ts`: `cardState()` (ACTIVE→Connected, INITIATED/VERIFYING→Connecting, EXPIRED/ERROR→Needs attention, PAUSED→Paused; Coming soon for unimplemented connectors; Available otherwise), catalog list builder (one card per catalog connector and plugin, no duplicates), alias validation (1–40, unique per connector), offline state machine (5 s probe timeout, clear within 10 s of recovery), credential-field clearing helper, "expires soon" and rotation-reminder derivation.
    - _Requirements: 1.3, 1.4, 1.5, 1.13, 10.6, 14.2, 4.10, 9.10_

  - [x]* 12.4 Write test for card state mapping
    - **Property 36: Card state mapping (TypeScript)**; use `fast-check` if already a dev dependency of `packages/app`, otherwise an exhaustive generated table. Run from `packages/app` with `bun test`.
    - **Validates: Requirements 1.3, 1.4, 1.5, 2.1, 14.2**

  - [x] 12.5 Implement the data layer
    - Hooks over the regenerated client (`client.experimental.connectors.*`): catalog, connections, status polling every 5 s with a 5 s timeout, mutations, audit paging. Credentials are held only in local component state, `type="password"`, `autocomplete="off"`, cleared in a `finally` within 1 s of the response, never in stores, URL, localStorage or logs.
    - _Requirements: 2.2, 2.9, 10.6, 11.1_

  - [x] 12.6 Implement the Connectors page and cards
    - `connectors.tsx`, `connector-card.tsx`, `connectors.css`: header, vault status banner (active key source by name, warning for key file and passphrase, "lost on restart" notice for memory-only), offline banner that disables Connect, card grid with icon, name, ≤120-char description, read-only badge, exactly one state, Connection count, Connected details (account label, last sync or "Never synced" with 0 entities), Needs attention with sanitized reason and "Reconnect". Each card is a `<section>` with accessible name `"<service>, <state>"`, an `aria-live="polite"` region announcing state changes within 1 s, keyboard-operable buttons with the shared focus ring, and semantic tokens only (square-cut `--radius-*`, brand tokens for the primary action).
    - _Requirements: 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.14, 6.5, 6.7, 10.6_

  - [x] 12.7 Implement the connection list and actions
    - `connection-list.tsx`: rows with alias (editable with uniqueness errors), account label, status, last sync, entities, expiry (with "Expires soon" warning and Reconnect), rotation reminder, and actions Test (identity, granted permissions, accessible repositories, offender names), Sync now, Pause/Resume, Reconnect, Rotate credential, Disconnect (confirmation stating that revoking at the provider is a separate step with a provider revocation link; Retry on vault delete failure), Audit and agent live reads. Import into `connectors.tsx`.
    - _Requirements: 1.14, 1.15, 2.4, 2.5, 2.6, 2.8, 2.9, 2.11, 4.4, 4.9, 4.10, 9.7, 9.8, 9.9, 9.10, 14.4, 14.5_

  - [x] 12.8 Implement the connect dialog shell
    - `connect-dialog.tsx`: lists every auth method, every read permission and every egress host from the manifest and nothing else; Account_Alias input; Auth_Config select (default preselected) and custom Auth_Config creation (scopes limited to the read-only set, at least one required); hosts and permissions come only from the catalog payload. Failures keep the dialog open, retain non-secret fields and empty every credential input. Wire into the Connect action on `connectors.tsx`.
    - _Requirements: 2.1, 2.2, 2.9, 13.2, 13.3, 13.5, 13.7, 1.13_

  - [x] 12.9 Implement the AWS connect panel
    - `aws-connect.tsx`: SSO option disabled "Available in a later release" but listed first with the recommended mark, AssumeRole (generated external ID, copyable CloudFormation and Terraform tabs, `ReadOnlyAccess` and `SecurityAudit` guidance with narrower-policy note, role ARN, region multi-select requiring ≥1, "Detect principal"), static keys (warning before saving and optional 90-day rotation reminder). Root-credential and write-permission errors name the offenders.
    - _Requirements: 3.1, 3.2, 3.6, 3.7, 3.9, 3.10, 3.11_

  - [x] 12.10 Implement the GitHub connect panel
    - `github-connect.tsx`: GitHub App and device flow entries disabled "Available in a later release" in the Requirement 4.1 order; fine-grained PAT input rejecting a non-`github_pat_` prefix with the classic-token message; "Permissions can't be verified; write requests are still blocked by the allowlist" notice; repository picker whose save is disabled with a message only after a selection event leaves it empty (not on initial load); optional GHES host.
    - _Requirements: 4.1, 4.2, 4.11, 4.12_

  - [x] 12.11 Implement the audit dialog
    - `audit-dialog.tsx`: newest first, 50 per page, rows with timestamp, event type, outcome and actor; retention setting (1–365 days) with range error message.
    - _Requirements: 9.4, 9.6_

  - [x] 12.12 Implement the scope panel
    - `scope-panel.tsx`: per-connection "Allow agent live reads" toggle (default off), scope editor limited to the connector's read operations, validation errors naming the offending operation, and a note that scope is empty by default.
    - _Requirements: 17.1, 17.2, 17.3, 17.6_

  - [x] 12.13 Integrate into Settings navigation and search
    - Add `connectors` to `SettingsRootTab` in `route.ts`, `pages.ts` (icon `plug`), `shell.tsx` (nav item and `Tabs.Content`) and `search-catalog.ts` (keywords "connectors aws github integrations"). Render only when the resolved TS flag is on and the `status` probe succeeds (404 means disabled); when disabled, no nav entry, no search result and no page or dialog.
    - _Requirements: 1.1, 1.2, 11.5_

  - [ ]* 12.14 Write component and e2e tests for the Connectors UI
    - Component tests for cards and dialogs and Playwright e2e (`packages/app/e2e`) for keyboard operation, flag off, offline banner and re-enable within 10 s, and credential inputs cleared after both success and failure. Follow the `component-tests` and `app-e2e-tests` skills.
    - _Requirements: 1.2, 1.9, 1.10, 2.2, 2.9, 10.6_

- [x] 13. Checkpoint: UI
  - From `packages/app` run `bun test` and `bun typecheck`; from the repo root run `bun run check`. Ensure all tests pass, ask the user if questions arise.

- [x] 14. Ops
  - [x] 14.1 Add the vault init script and systemd unit changes
    - New `services/bellud/ops/bellucode-vault-init.sh` (run with sudo): install `/etc/bellucode` (0755), generate 32 random bytes through `systemd-creds encrypt --name=bellucode-master-key` to `/etc/bellucode/master-key.cred` (0600), idempotent and with a clear failure message when systemd < 250.
    - Update `services/bellud/ops/bellucode.service`: `LoadCredentialEncrypted=bellucode-master-key:/etc/bellucode/master-key.cred` and `NoNewPrivileges=yes`; document the `BELLUCODE_MASTER_KEY_FILE` fallback (32 raw bytes, owner `ubuntu`, mode 0400, outside `~/.local/share/bellucode`) in the script's usage text.
    - _Requirements: 6.3, 6.4, 6.8_

- [x] 15. Final checkpoint
  - From `services/bellud` run `go build ./...`, `go vet ./...`, `go test ./...`. From `packages/protocol`, `packages/schema`, `packages/app` run `bun test` and `bun typecheck`. From `packages/client` rerun `bun run generate` and confirm no diff. From the repo root run `bun run check`. Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP. The security-critical property tests are required (no `*`): P1 and P2 (vault round trip, tamper and AAD), P5 (redaction), P6 (leaking batches), P7 (policy allowlist, pure and broker), P10 (lifecycle transitions), P16 (no-token-export route scan) and P19 (scope default-deny).
- Each property test uses `pgregory.net/rapid`, at least 100 iterations, and the tag `// Feature: cloud-connectors, Property N: <title>`.
- Property 25 (GitHub device-flow polling) and Property 37 (plugin capability and pinning) are not tasks because their features are outside the MVP.
- Each task references specific requirement numbers for traceability; checkpoints validate incrementally.
- Not tasks (Phase 2): AWS IAM Identity Center (SSO device flow) and organization scope; GitHub OAuth device flow and GitHub App installation; per-session and per-named-token Session_Scopes; declarative plugin install flow (manifest preview, confirmation, pinning, update re-confirmation); signature verification; passphrase unlock UI polish; migration of the legacy `credential` table (Req 6.21, separate item).
- Not tasks (Phase 3): plugin sandbox runtime (process isolation, filesystem and network confinement, capability tokens ≤5 min; Req 8.6, 8.7); implementations of the remaining catalog connectors (Cloudflare, GitLab, Sentry, MongoDB, Railway, Azure, Google Cloud, Render, Supabase); GitHub Enterprise polish.
- Requirements 8.4–8.13 (plugin install, sandbox, signing, pinning) and 4.6–4.8 (device flow, App) are deferred with the phases above; the MVP keeps those entries disabled in the UI.
- Open point 5 of the design (Go cannot see `experimental.connectors` set only in config files) is handled by requiring both the resolved TS flag and a successful `status` probe; no task passes the TS flag to bellud at spawn time.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "2.1", "2.2", "2.3", "3.1", "3.3", "4.1", "4.5"] },
    { "id": 1, "tasks": ["2.4", "2.5", "2.6", "3.2", "3.4", "3.5", "4.2", "4.3", "4.6", "7.2"] },
    { "id": 2, "tasks": ["2.7", "3.6", "3.7", "3.8", "3.9", "4.4", "4.7", "5.1"] },
    { "id": 3, "tasks": ["3.10", "4.8", "4.9", "5.2", "5.3", "5.4"] },
    { "id": 4, "tasks": ["5.5", "5.6", "5.7", "5.10", "5.11", "5.12", "7.1", "8.1"] },
    { "id": 5, "tasks": ["5.8", "5.9", "5.13", "7.3", "7.4", "7.6", "8.2", "8.3", "8.4"] },
    { "id": 6, "tasks": ["7.5", "7.7", "8.5"] },
    { "id": 7, "tasks": ["10.1", "10.2", "10.9"] },
    { "id": 8, "tasks": ["10.3", "10.4", "10.10", "10.11", "12.1", "12.2", "12.3"] },
    { "id": 9, "tasks": ["10.5", "10.6", "10.8", "12.4", "12.5"] },
    { "id": 10, "tasks": ["10.7", "12.6", "12.9", "12.10", "12.11", "12.12"] },
    { "id": 11, "tasks": ["12.7", "14.1"] },
    { "id": 12, "tasks": ["12.8", "12.13"] },
    { "id": 13, "tasks": ["12.14"] }
  ]
}
```
