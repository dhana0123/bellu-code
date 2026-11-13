# Requirements Document

## Introduction

Cloud Connectors adds a "Connectors" section to Bellu Code Settings. Each connector is a card for an external service that the user connects with read-only access. Connected services feed observations into the Bellu Graph (through Go collectors in `bellud`) so the agent can reason about the user's real infrastructure and code hosting.

The first implemented connectors are AWS and GitHub. Cloudflare, GitLab, Sentry, MongoDB, Railway, Azure, Google Cloud, Render and Supabase appear as catalog cards ("Coming soon") and arrive in later phases. A manifest-driven extension path lets people add their own connectors.

Design inputs from the reference project `bellu-ai-cyber`:
- A `Source` contract (`Name`, `Collect` streaming events plus non-fatal errors, with per-table progress reporting) maps onto the existing `Collector` interface in `bellud`.
- A connection lifecycle state machine (PENDING, VERIFYING, CONNECTED, DISCOVERY_RUNNING, COMPLETE, ERROR) with explicit events and a provider registry.
- AWS via a customer-deployed IAM role (CloudFormation, Terraform or manual); GitHub via a GitHub App that mints short-lived installation tokens; AES-256-GCM credential encryption with a random nonce per value; a redaction package.

Security posture, based on current guidance:
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html): centralize secrets, apply least privilege, rotate, revoke, expire and audit.
- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html): use temporary credentials through roles or federation instead of long-lived keys.
- [AWS confused deputy guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html): an external ID in the role trust policy.
- [GitHub PAT documentation](https://docs.github.com/github/authenticating-to-github/creating-a-personal-access-token): prefer fine-grained tokens over classic tokens.
- [GitHub Apps versus OAuth apps](https://docs.github.com/en/enterprise-cloud@latest/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps): fine-grained permissions and short-lived tokens.
- [Electron safeStorage](https://github.com/electron/electron/blob/main/docs/api/safe-storage.md): the OS key store (Keychain, DPAPI, libsecret) protects against other users and apps.

Design reference: Composio. The Composio documentation on [authentication](https://docs.composio.dev/docs/authentication), [auth configs](https://docs.composio.dev/reference/api-reference/auth-configs) and [connected accounts](https://docs.composio.dev/reference/api-reference/connected-accounts) is a design reference only. Bellu Code has no dependency on Composio Cloud or its runtime, and every Credential stays in Bellud on the user's machine. Adopted ideas:
- One auth config blueprint per Connector (auth method, scopes, which app credentials are used).
- One connected account per user and service, with several accounts allowed per Connector and a user-set alias for each.
- No way to export tokens, because the platform injects credentials server-side and executes calls through a proxy.
- A connected account lifecycle that includes ACTIVE and EXPIRED, with a reconnect link.
- Scoped access, so a caller sees only the accounts and operations it was granted.

Deliberately not adopted: cloud custody of credentials, write actions, and a closed hosted runtime.

Today, provider credentials in the `credential` table of `bellucode-local.db` are stored as plaintext JSON protected only by file mode 0600. Connector credentials must not use that path.

## Glossary

- **Bellu_Code**: The product, comprising the web app, the TypeScript server and the Go server.
- **Settings_UI**: The Settings pages of the Bellu Code web app.
- **Connectors_Page**: The Settings page that lists connector cards.
- **Connector**: A definition of an external service integration (id, name, auth methods, scopes, collectors).
- **Connector_Manifest**: A declarative document describing a Connector: id, version, auth methods, requested permissions, egress hosts and collectors.
- **Connection**: A user's configured instance of a Connector, with a lifecycle status. A Connection is the Connected_Account of the design reference; both terms name the same thing and this document uses Connection.
- **Connected_Account**: Synonym of Connection, used only when referring to the design reference.
- **Account_Alias**: A user-set label of 1 to 40 characters that identifies a Connection among the Connections of one Connector (for example "work" or "prod-eu").
- **Auth_Config**: A per-Connector blueprint that states the auth method, the read scopes, and which app credentials are used: the built-in default app or a user-supplied own OAuth app, GitHub App or AWS role settings.
- **Connection_Status**: One of INITIATED, VERIFYING, ACTIVE, EXPIRED, PAUSED, ERROR. The card states map as Connected = ACTIVE, Connecting = INITIATED or VERIFYING, Needs attention = EXPIRED or ERROR, Paused = PAUSED.
- **Proxy_Request**: A provider call made by Bellud on behalf of a caller, in which the Connector_Service injects the Credential server-side, applies the Read_Only_Policy, Egress_Allowlist and rate limits, and returns only the provider response.
- **Session_Scope**: The set of Connections and read operations that an agent session or MCP token may use.
- **Bellud**: The Go front-door server in `services/bellud`.
- **Connector_Service**: The Bellud component that owns Connections, credentials, testing and collection.
- **Credential_Vault**: The Connector_Service component that encrypts, stores and releases credentials.
- **Master_Key**: The 256-bit key that wraps credential data encryption keys, held in the OS key store or an equivalent protected source.
- **Credential**: A secret (token, key, private key, refresh token, session material) used by a Connection.
- **Secret_Redactor**: The component that removes Credential values from logs, errors, events, graph batches and API responses.
- **Graph_Engine**: The Bellu Graph Engine, which receives collector batches.
- **Connector_Collector**: A Bellud collector that reads from a connected service and returns a graph batch.
- **Audit_Log**: The append-only record of Connector security events.
- **TS_Server**: The TypeScript server (`packages/server`, `packages/core`).
- **Agent_Tools**: The MCP tools and model-visible context exposed to the agent.
- **Plugin_Connector**: A third-party Connector loaded from a Connector_Manifest.
- **Read_Only_Policy**: The policy that allows only read operations against external services.
- **Egress_Allowlist**: The set of hostnames a Connector may contact.
- **Connectors_Flag**: The feature flag guarding all Connector behavior.

## Requirements

### Requirement 1: Connectors Catalog

**User Story:** As a user, I want a Connectors section in Settings with a card per service, so that I can see what I can connect and what is connected.

#### Acceptance Criteria

1. WHERE the Connectors_Flag is enabled, THE Settings_UI SHALL show a "Connectors" entry in the Settings navigation and SHALL return that entry as a result in Settings search for queries matching "connectors" (case-insensitive).
2. IF the Connectors_Flag is disabled, THEN THE Settings_UI SHALL NOT show the "Connectors" entry in the Settings navigation or in Settings search results, and SHALL NOT render the Connectors_Page.
3. WHEN the Connectors_Page opens, THE Settings_UI SHALL show exactly one card for each of Cloudflare, AWS, GitHub, GitLab, Sentry, MongoDB, Railway, Azure, Google Cloud, Render and Supabase, plus exactly one card for each installed Plugin_Connector, and SHALL NOT show duplicate cards for the same Connector.
4. THE Settings_UI SHALL display each card with the service icon, the service name, a one-line description of at most 120 characters, a "read-only" badge and exactly one of these states: Available, Coming soon, Connecting, Connected, Paused, Needs attention.
5. THE Settings_UI SHALL show the state "Coming soon" with the connect action disabled on the card of every Connector other than AWS and GitHub, excluding Plugin_Connectors, whose state is determined by their Connection status. THE Settings_UI SHALL show the AWS and GitHub cards in the Available state until a Connection is created for them, and then in the states driven by Connection_Status.
6. WHILE a Connection is in the Connected state, THE Settings_UI SHALL show on its card the account label, the time of the last successful sync, and the count of ingested entities as a non-negative integer.
7. WHILE a Connection is in the Connected state and has not yet completed a sync, THE Settings_UI SHALL show a "Never synced" placeholder for the last successful sync time and a count of 0.
8. WHILE a Connection is in the Needs attention state (Connection_Status EXPIRED or ERROR), THE Settings_UI SHALL show on its card the sanitized error reason, containing no credentials or tokens, and an enabled "Reconnect" action.
9. THE Settings_UI SHALL make every card and each of its enabled actions reachable and operable using the keyboard alone (Tab to focus, Enter or Space to activate), with a visible focus indicator.
10. THE Settings_UI SHALL expose for each card its service name and current state to assistive technology as the accessible name and state, and SHALL announce a change of state within 1 second of the change.
11. THE Settings_UI SHALL use semantic theme tokens for all card colors and SHALL NOT use hard-coded color values on cards.
12. THE Connector_Service SHALL allow more than one Connection per Connector (for example two AWS accounts, or a personal and a work GitHub account).
13. WHEN a Connection is created, THE Settings_UI SHALL require an Account_Alias of 1 to 40 characters, and THE Connector_Service SHALL reject an Account_Alias that duplicates another Connection's Account_Alias for the same Connector, with an error naming the alias field.
14. THE Settings_UI SHALL show on each card the count of its Connections as a non-negative integer, and SHALL list each Connection with its Account_Alias, account label and Connection_Status.
15. WHEN the user edits an Account_Alias, THE Connector_Service SHALL apply the uniqueness and length rules of criterion 13 and SHALL keep the previous Account_Alias if the new one is rejected.

### Requirement 2: Connect, Test and Disconnect Flows

**User Story:** As a user, I want guided connect, test and disconnect flows, so that I can manage access without handling secrets unsafely.

#### Acceptance Criteria

1. WHEN the user selects "Connect" on a card in the Available state, THE Settings_UI SHALL open a dialog listing every auth method the Connector supports, every read permission named in the Connector_Manifest, and every hostname on the Connector's Egress_Allowlist, and SHALL NOT list any permission or hostname absent from the Connector_Manifest.
2. WHEN the user submits credentials, THE Settings_UI SHALL send them only to Bellud over an authenticated local request, and SHALL clear every credential input field within 1 second of receiving the response, whether the response is a success or a failure.
3. WHEN the Connector_Service receives a Connection submission, THE Connector_Service SHALL set the Connection to INITIATED on receipt, set it to VERIFYING when verification starts, and then set it to ACTIVE if verification succeeds and no write-capable permission is found, or to ERROR otherwise.
4. WHEN the user selects "Test connection", THE Connector_Service SHALL perform a read-only identity check and a permission check, and SHALL return the account identity and the list of granted permissions within 30 seconds.
5. IF the permission check finds a write-capable permission, THEN THE Connector_Service SHALL set the Connection to ERROR with an excess permission error, SHALL NOT start any Connector_Collector for it, and SHALL delete any Credential stored for it, and THE Settings_UI SHALL show the name of each offending permission.
6. WHEN the user selects "Disconnect", THE Settings_UI SHALL ask for confirmation, and WHEN the user confirms, THE Connector_Service SHALL stop the Connector_Collectors within 5 seconds, then delete the Credential from the Credential_Vault, then mark the Connection as removed.
7. WHEN a Connection is marked as removed, THE Connector_Service SHALL remove from the Graph_Engine every entity carrying that Connection's source tag within one collection interval, measured with the interval configured for that Connection at the time of removal.
8. WHEN the Disconnect confirmation is shown, THE Settings_UI SHALL state that revoking the token or role at the provider is a separate step the user must perform, and SHALL show a link to the provider's revocation page.
9. IF a connect, test or disconnect request fails, THEN THE Settings_UI SHALL show a localized message that names the typed error category and contains no Credential value, SHALL keep the dialog open with the non-secret fields retained, and SHALL leave every credential input field empty.
10. IF verification or a connection test does not complete within 30 seconds, THEN THE Connector_Service SHALL cancel the pending provider calls, set a Connection being verified to ERROR with a network error, and return the same error for a test, without changing the stored Credential.
11. IF the Credential_Vault fails to delete the Credential during Disconnect, THEN THE Connector_Service SHALL keep the Connection in its current state without marking it removed, SHALL keep the Connector_Collectors stopped, and THE Settings_UI SHALL show a localized failure message with a "Retry" action.

### Requirement 3: AWS Connector

**User Story:** As a user, I want to connect AWS with short-lived, read-only access, so that the agent can see my cloud resources without long-lived keys.

#### Acceptance Criteria

1. THE Settings_UI SHALL offer exactly these AWS auth methods, listed in this order of preference: IAM Identity Center (SSO) profile, AssumeRole with an external ID, and static IAM user access keys, and SHALL mark the first as recommended.
2. WHEN the user chooses AssumeRole, THE Connector_Service SHALL generate an external ID of at least 32 characters from a cryptographically secure random source, unique per Connection, and display it together with a CloudFormation template and a Terraform snippet that each embed that external ID and the role trust configuration.
3. WHILE a Connection uses AssumeRole, THE AWS Connector SHALL send the Connection's external ID in every `AssumeRole` call.
4. THE AWS Connector SHALL request STS session credentials with a duration of at most 3600 seconds, SHALL refresh them at least 300 seconds before expiry, and SHALL keep them in Bellud process memory only, never writing them to disk, the Audit_Log, or any API response.
5. IF refreshing session credentials fails, THEN THE AWS Connector SHALL retry up to 3 times with increasing delay, and if all retries fail, SHALL set the Connection to EXPIRED, stop collection, and show the failure reason and a "Reconnect" action in the Settings_UI without retaining the expired credentials.
6. THE Settings_UI SHALL show in the AWS setup instructions the AWS managed policies `ReadOnlyAccess` and `SecurityAudit`, and a note that a narrower custom read-only policy may be used instead.
7. WHERE the user selects static access keys, THE Settings_UI SHALL show a warning that long-lived keys are discouraged before the keys are saved, and SHALL offer an optional rotation reminder that, when enabled, is shown 90 days after the keys were saved.
8. WHEN the user tests an AWS Connection, THE Connector_Service SHALL call `sts:GetCallerIdentity`, run a policy simulation against a fixed set of write actions, and report within 30 seconds either success or the list of write actions that are allowed.
9. IF the policy simulation or equivalent write-permission check detects at least one allowed write action, THEN THE Connector_Service SHALL mark the test as failed with a warning listing the allowed write actions, and SHALL keep the Connection from being activated until the user confirms the warning or fixes the permissions.
10. IF the `sts:GetCallerIdentity` result identifies the AWS account root user, THEN THE Connector_Service SHALL reject the Connection, SHALL show an error stating that root credentials are not allowed, and SHALL discard the supplied Credential.
11. THE AWS Connector SHALL let the user restrict collection to a selected subset of AWS regions (at least 1) and, in the organization scope, to a selected subset of accounts (at least 1), and SHALL collect only from the selected regions and accounts.
12. THE AWS Connector SHALL send requests only to AWS API hostnames of the selected regions plus the SSO and STS endpoints, and IF a request targets any other hostname, THEN THE Connector_Service SHALL block it and record the blocked hostname in the Audit_Log. Only blocks caused by targeting a non-allowlisted hostname require an Audit_Log entry under this criterion; other blocks are governed by other criteria.

### Requirement 4: GitHub Connector

**User Story:** As a user, I want to connect GitHub with scoped read-only access, so that the agent can see repositories and security signals.

#### Acceptance Criteria

1. WHERE the Connectors_Flag is enabled, THE Settings_UI SHALL offer these GitHub auth methods in this order of preference: GitHub App installation with read-only permissions, OAuth device flow, and fine-grained personal access token.
2. IF the user submits a personal access token that does not start with `github_pat_`, THEN THE Connector_Service SHALL reject the token, SHALL NOT store it in the Credential_Vault, SHALL NOT create or change a Connection, and THE Settings_UI SHALL show an error stating that classic tokens are not supported because they cannot be limited to read-only permissions and specific repositories.
3. THE GitHub Connector SHALL request only these permissions, each at read-only level: Metadata, Contents, Pull requests, Issues, Actions, Dependabot alerts, Code scanning alerts and Secret scanning alerts.
4. WHEN the user tests a GitHub Connection, THE Connector_Service SHALL return the list of granted permissions with their access levels and the list of accessible repositories, and THE Settings_UI SHALL display both lists.
5. IF any granted permission has a write or admin access level when the user tests a GitHub Connection, THEN THE Connector_Service SHALL set the Connection to ERROR, SHALL NOT run any Connector_Collector for it, and THE Settings_UI SHALL show an error naming each permission with write or admin access.
6. WHEN the user chooses OAuth device flow, THE Settings_UI SHALL show the verification URL and the user code returned by GitHub, and THE Connector_Service SHALL poll for authorization at the interval GitHub specifies, increasing the interval as GitHub instructs when it returns a slow-down response.
7. IF the device code expires or the user denies authorization during OAuth device flow, THEN THE Connector_Service SHALL stop polling, SHALL NOT create a Connection, and THE Settings_UI SHALL show an error indicating expiry or denial together with a "Try again" action.
8. WHERE the GitHub App method is used, THE Connector_Service SHALL mint installation tokens on demand, SHALL hold them in memory only and SHALL NOT write them to disk, and SHALL store only the App private key in the Credential_Vault.
9. WHILE a GitHub Connection's token has an expiry date, THE Settings_UI SHALL show that expiry date on the Connection.
10. WHILE a GitHub Connection's token has fewer than 7 days remaining before expiry, THE Settings_UI SHALL show an "Expires soon" warning and a "Reconnect" action on that Connection, and the Connection SHALL remain ACTIVE until the token expires.
11. WHEN the user selects repositories for a GitHub Connection, THE Connector_Service SHALL collect data only from the selected repositories, and IF no repository is selected after the user has interacted with repository selection (a selection event), THEN THE Settings_UI SHALL disable saving the selection and show a message that at least one repository is required. This disabling and message do not apply on initial load.
12. THE GitHub Connector SHALL send requests only to `api.github.com`, `github.com` (device flow only) and the GitHub Enterprise host configured on the Connection, and THE Connector_Service SHALL block any request to another host.

### Requirement 5: Read-Only Enforcement

**User Story:** As a user, I want a guarantee that connectors cannot change my services, so that connecting them carries no risk of damage.

#### Acceptance Criteria

1. WHEN a Connector sends a request to an external service, THE Connector_Service SHALL permit only HTTP GET, HEAD and OPTIONS requests, and POST requests whose operation is listed as a read-only query in that Connector's Connector_Manifest (such as GraphQL queries and AWS `Describe*`, `List*` and `Get*` calls).
2. IF a Connector attempts an operation that is not on its read-operation allowlist, THEN THE Connector_Service SHALL block the call before any request leaves Bellud, write an Audit_Log entry containing the Connection identifier, the attempted operation name and a timestamp, set the Connection to ERROR, and return an error to the caller indicating the operation was blocked by the Read_Only_Policy.
3. THE Connector_Service SHALL NOT expose any Credential-using write operation to Agent_Tools.
4. THE Connector_Collector SHALL read provider data only through the Connector_Service client wrapper and SHALL NOT import or call a provider SDK directly.
5. WHEN 24 hours have elapsed since a Connection's last permission check, or WHEN the Connection is first connected, THE Connector_Service SHALL re-run the permission check for that Connection.
6. IF a permission check finds that the Credential grants any write permission, THEN THE Connector_Service SHALL suspend collection for that Connection within 60 seconds, write an Audit_Log entry, set the Connection to ERROR, and keep the stored Connection configuration and previously ingested graph data unchanged.
7. IF a permission check cannot complete because the provider is unreachable or returns an error, THEN THE Connector_Service SHALL retain the Connection's current state, write an Audit_Log entry recording the failure, and retry the check within 1 hour.
8. IF a Connector_Manifest lists an operation that is a write operation under the Read_Only_Policy as read-only, THEN THE Connector_Service SHALL reject the Connector_Manifest at load time, not enable the Connector, and report an error identifying the offending operation.

### Requirement 6: Credential Storage and Isolation

**User Story:** As a user, I want my cloud keys protected from every other process and component, so that connecting a service does not widen my attack surface.

#### Acceptance Criteria

1. WHEN the Credential_Vault stores a Credential, THE Credential_Vault SHALL encrypt it with AES-256-GCM using a unique 256-bit data key and a unique random 96-bit nonce, and SHALL bind the Connection id and Connector id as authenticated data.
2. WHEN the Credential_Vault decrypts a Credential and the Connection id or Connector id differs from the bound authenticated data, THE Credential_Vault SHALL fail decryption, SHALL release no plaintext, and SHALL record an Audit_Log entry.
3. THE Credential_Vault SHALL obtain the Master_Key from the first available source in this order: (a) the OS key store (macOS Keychain, Windows DPAPI or Credential Manager, Linux Secret Service), (b) a systemd encrypted credential (LoadCredentialEncrypted, protected by TPM2 or the host key), (c) a key file with mode 0400 owned by the Bellud user and located outside the directory that holds the encrypted Credentials, (d) a user-supplied passphrase.
4. THE Credential_Vault SHALL NOT store the Master_Key in the same database, file or directory as the encrypted Credentials.
5. IF the Master_Key source is a key file or a passphrase, THEN THE Credential_Vault SHALL show a security warning in the Settings_UI stating that protection is lower than an OS key store, and SHALL show the active key source by name.
6. IF the Master_Key source is a user-supplied passphrase, THEN THE Credential_Vault SHALL derive the Master_Key with Argon2id using a random salt of at least 16 bytes, a memory cost of at least 64 MiB, and at least 3 iterations, and SHALL reject passphrases shorter than 12 characters with an error indicating the minimum length.
7. IF no Master_Key source is available, THEN THE Connector_Service SHALL refuse to persist Credentials, SHALL keep them in memory only until the Bellud process exits, and SHALL show a notice in the Settings_UI that Credentials will be lost on restart.
8. WHEN Bellud starts, THE Credential_Vault SHALL verify that the encrypted Credential store has mode 0600, that its containing directory has mode 0700, and that the key file (if used) has mode 0400.
9. IF any mode verified at startup does not match, THEN THE Credential_Vault SHALL attempt to set the expected mode once, and IF the mode still does not match, THEN THE Credential_Vault SHALL refuse to load Credentials, SHALL report an error indicating the affected path class (store, directory or key file), and SHALL leave stored data unchanged.
10. THE Credential_Vault SHALL NOT write Credentials to the existing plaintext `credential` table, environment variables, command-line arguments, config files, temporary files or logs.
11. WHEN the Connector_Collector requests a Credential, THE Credential_Vault SHALL release the plaintext only to the Connector_Collector inside the Bellud process, and SHALL zero the buffer within 1 second after the request completes wherever the Go runtime allows.
12. THE Bellud SHALL NOT pass Credentials to the TS_Server, the web client, Agent_Tools, model prompts, child processes or Plugin_Connectors.
13. WHEN the Settings_UI requests a Connection, THE Connector_Service SHALL return only masked metadata consisting of at most the last 4 characters of the Credential, the creation time and the expiry time, and SHALL NOT return the Credential.
14. WHEN a Credential write request arrives, THE Connector_Service SHALL accept it only if the request is authenticated, originates from the local machine, and comes from the Bellu Code client.
15. IF a Credential write request carries the agent or MCP token role, or is unauthenticated, or is not local, THEN THE Connector_Service SHALL reject it with an authorization error, SHALL store nothing, and SHALL record an Audit_Log entry.
16. THE Secret_Redactor SHALL remove Credential values and known token patterns from logs, error messages, graph batches, Audit_Log entries, crash reports and API responses before they are written or returned.
17. WHEN a Master_Key rotation is requested, THE Credential_Vault SHALL re-wrap every data key under the new Master_Key without writing plaintext Credentials to disk.
18. IF a Master_Key rotation fails before completion, THEN THE Credential_Vault SHALL keep every data key wrapped under the previous Master_Key, SHALL leave all Credentials decryptable, and SHALL report an error indicating the rotation failed.
19. WHEN the user locks the app or runs "Forget all connectors", THE Credential_Vault SHALL delete all stored Credentials and wrapped keys, SHALL discard in-memory Credentials and the cached Master_Key, and SHALL confirm completion within 5 seconds.
20. THE Connector_Service SHALL exclude Credentials and wrapped keys from exports, session sharing, telemetry and backups made by Bellu Code.
21. WHERE the existing provider credentials in the `credential` table are in scope for follow-up, THE Bellu_Code project SHALL record a separate migration item to move them to the Credential_Vault.

### Requirement 7: Data Ingestion into the Graph

**User Story:** As a user, I want connected services to appear in the graph, so that the agent can answer questions about my infrastructure and code.

#### Acceptance Criteria

1. WHEN a Connection becomes ACTIVE, THE Connector_Service SHALL start one Connector_Collector for that Connection within 5 seconds, and the Connector_Collector SHALL implement the `Collector` interface of Bellud.
2. WHEN a Connection leaves ACTIVE, THE Connector_Service SHALL stop its Connector_Collector within 5 seconds and SHALL start no further collection runs for it.
3. WHEN a collection run completes successfully, THE Connector_Collector SHALL return the full current observation of the Connection, so that the Graph_Engine derives added, changed and removed entities. An entity present in the previous observation and absent from the new one SHALL be treated as removed.
4. THE Connector_Service SHALL abort each collection run that exceeds a timeout of 120 seconds and SHALL record the run with status timeout.
5. IF a collection run fails or times out, THEN THE Connector_Service SHALL retry with exponential backoff starting at 1 minute, doubling after each consecutive failure, capped at 15 minutes, and SHALL reset the backoff to 1 minute after a successful run. A failed or timed-out run SHALL NOT change the entities already in the Graph_Engine.
6. WHEN a Connector_Collector returns a batch, THE Connector_Service SHALL pass the batch through the Secret_Redactor and the existing no-secret guard before the batch reaches the Graph_Engine, and no batch SHALL reach the Graph_Engine without passing both.
7. IF a batch contains a Credential value of any Connection or matches a secret pattern of the no-secret guard, THEN THE Connector_Service SHALL discard the whole batch, SHALL keep the previously ingested entities unchanged, SHALL record status leak for the Connector in `collector_status`, and SHALL NOT include the matched value in `collector_status`, logs or events.
8. THE Connector_Collector SHALL ingest metadata and configuration only (for example resources, repositories, alerts) and SHALL NOT ingest object contents, file contents, secret values, environment variable values or database records.
9. WHEN a collection run ends, THE Connector_Service SHALL record in `collector_status` for the Connection the status (one of ok, error, timeout, leak) and the run end time, a timestamp greater than or equal to 0 (0 is valid).
10. THE Connector_Service SHALL let the user set the collection interval to a value from 1 minute to 24 hours in 1-minute steps, with a default of 15 minutes, and SHALL reject values outside that range with an error indicating the allowed range while keeping the previous interval.
11. WHEN the user triggers a manual sync for an ACTIVE Connection, THE Connector_Service SHALL start a collection run within 5 seconds. IF a run is already in progress for that Connection, THEN THE Connector_Service SHALL reject the request with an error indicating a run is in progress and SHALL NOT start a second concurrent run.
12. THE Connector_Service SHALL cap API requests to each external service at 10 requests per second per Connection. IF a provider response carries a rate-limit header indicating the limit is exhausted or a retry delay, THEN THE Connector_Service SHALL send no further requests to that provider for that Connection until the indicated time.
13. WHEN the agent queries the graph, THE Agent_Tools SHALL return connector entities that carry only non-secret attributes and a source tag naming the Connection, and SHALL NOT return Credential values.

### Requirement 8: Extensibility and Plugin Connectors

**User Story:** As a developer, I want to add my own connector like a plugin, so that I can bring services that are not in the catalog.

#### Acceptance Criteria

1. THE Connector_Service SHALL load every Connector, built-in or Plugin_Connector, from a single registry and SHALL expose all of them through the same contract, so that no caller can tell the two kinds apart except by a plugin indicator.
2. THE Connector_Manifest SHALL declare the following fields: id (1 to 64 characters), version (semantic version), display name (1 to 64 characters), icon, auth methods (1 to 5 entries), requested permissions (0 to 50 entries), read-operation allowlist (0 to 200 entries, each limited by method, host and path), Egress_Allowlist (0 to 50 hostnames) and collector entities (1 to 100 entries).
3. IF a Connector_Manifest is missing a required field, has a field outside these bounds, or has an id that duplicates a registered Connector, THEN THE Connector_Service SHALL reject the Plugin_Connector, SHALL NOT register it, and SHALL show an error in the Settings_UI naming the invalid field.
4. WHEN the user starts installing a Plugin_Connector, THE Settings_UI SHALL display every requested permission and every Egress_Allowlist host from the Connector_Manifest, and THE Connector_Service SHALL NOT activate the Plugin_Connector until the user gives explicit confirmation.
5. IF the user cancels or dismisses the confirmation, THEN THE Connector_Service SHALL discard the install and SHALL leave the registry unchanged.
6. WHILE a Plugin_Connector collector runs, THE Connector_Service SHALL confine it to an isolated process or sandbox that denies all filesystem access outside its own working directory and all network access to hosts outside its Egress_Allowlist.
7. WHEN a Plugin_Connector makes a call, THE Connector_Service SHALL give it a scoped capability that expires within 5 minutes of issue or at the end of the call, whichever is first, and SHALL NOT give it the stored Credential in any form.
8. WHERE package signing is available, THE Connector_Service SHALL verify the Plugin_Connector signature and checksum before loading it.
9. IF signature or checksum verification fails, THEN THE Connector_Service SHALL refuse to load the Plugin_Connector and SHALL record an Audit_Log entry.
10. IF a Plugin_Connector is unsigned, THEN THE Settings_UI SHALL show an unsigned warning on its install confirmation and on its Connector card.
11. IF a Plugin_Connector requests a permission not in its manifest, or a host, method or path not on its allowlists, THEN THE Connector_Service SHALL block the request before any network traffic is sent, SHALL return a denial error to the plugin, and SHALL record an Audit_Log entry containing the plugin id, the denied item and a timestamp.
12. THE Connector_Service SHALL pin each installed Plugin_Connector to the exact version confirmed at install and SHALL NOT load any other version.
13. WHEN an update to a Plugin_Connector adds or changes any permission or Egress_Allowlist host, THE Connector_Service SHALL keep the pinned version active, SHALL NOT run the updated version, and SHALL require explicit re-confirmation through the Settings_UI before switching to it.
14. THE Bellu_Code project SHALL publish a Connector SDK contract document and a machine-readable schema for the Connector_Manifest, and THE schema SHALL accept every built-in Connector_Manifest.

### Requirement 9: Auditing and Revocation

**User Story:** As a user, I want an audit trail and quick revocation, so that I can see and stop credential use.

#### Acceptance Criteria

1. WHEN a connect, test, disconnect, credential rotation, credential release, collection run, blocked operation or permission change event occurs, THE Connector_Service SHALL append one Audit_Log entry for that event before the operation's result is returned to the caller.
2. THE Audit_Log entry SHALL contain a UTC timestamp with millisecond precision, Connection id, Connector id, event type, outcome (success, failure or blocked) and actor (user, system or Plugin_Connector id), and SHALL NOT contain Credential values.
3. IF the Connector_Service cannot append an Audit_Log entry, THEN THE Connector_Service SHALL reject the credential release, credential rotation and connect operations that triggered it, SHALL leave the stored Credential unchanged, and SHALL show the user an error indicating that auditing failed.
4. WHEN the user opens the audit view for a Connection, THE Settings_UI SHALL show that Connection's Audit_Log entries newest first, 50 entries per page, with timestamp, event type, outcome and actor on each row.
5. THE Audit_Log SHALL accept only appends from the running application (no update or delete of existing entries through any Bellu_Code interface) and SHALL be stored with file mode 0600.
6. WHEN an Audit_Log entry becomes older than 90 days, THE Connector_Service SHALL remove it, and SHALL allow the user to set the retention period between 1 and 365 days.
7. WHEN the user selects "Pause", THE Connector_Service SHALL stop all Connector_Collector runs for that Connection within 5 seconds, keep the Credential in the Credential_Vault, and set the Connection to PAUSED, shown as the Paused state on the card.
8. WHEN the user selects "Rotate credential", THE Connector_Service SHALL perform the identity check and permission check of Requirement 2 on the new Credential, and SHALL replace the old Credential only if both checks pass.
9. IF the new Credential fails verification, THEN THE Connector_Service SHALL keep the old Credential active, discard the new one, and THE Settings_UI SHALL show an error indicating the verification failure without any Credential value.
10. WHILE a static Credential is older than its configured rotation interval (default 90 days, range 1 to 365 days), THE Settings_UI SHALL show a rotation reminder on the card.

### Requirement 10: Error Handling

**User Story:** As a user, I want clear, safe errors, so that I can fix problems without exposing secrets.

#### Acceptance Criteria

1. IF verification fails, THEN THE Connector_Service SHALL return exactly one typed error from the set {invalid credential, insufficient permission, excess permission, network, rate limited, expired} with a localized message of at most 200 characters, SHALL NOT include the Credential value in the message, and SHALL leave the Connection state and any previously stored Credential unchanged.
2. IF a provider returns HTTP 401 or 403 during collection, THEN THE Connector_Service SHALL stop collection for that Connection within 5 seconds without retrying, set it to EXPIRED for HTTP 401 or to ERROR for HTTP 403, and retain the last good graph data.
3. IF a provider is unreachable (connection refused, DNS failure, or no response within 30 seconds) during collection, THEN THE Connector_Service SHALL retry up to 3 times with increasing delay, and if all retries fail SHALL retain the last good graph data, mark the data as stale, and show the last successful sync time on the card.
4. IF a collection run fails for one resource type, THEN THE Connector_Collector SHALL continue with the remaining resource types and, when the run ends, report a partial failure listing each failed resource type, with the Connection remaining ACTIVE.
5. IF the Credential_Vault cannot decrypt a Credential, THEN THE Connector_Service SHALL stop use of that Credential, set the Connection to ERROR with a sanitized reason prompting the user to reconnect, and SHALL NOT write key material, ciphertext or plaintext to logs, error messages or the Audit_Log.
6. IF the Connector_Service does not respond within 5 seconds or is unavailable, THEN THE Settings_UI SHALL show an offline state on the Connectors_Page, disable all connect actions, and WHEN the Connector_Service responds again, SHALL clear the offline state and re-enable connect actions within 10 seconds.

### Requirement 11: Localization, Feature Flag and API Surface

**User Story:** As a maintainer, I want the feature flagged, localized and experimental, so that it can ship safely.

#### Acceptance Criteria

1. THE Settings_UI SHALL define every user-visible Connectors string (labels, buttons, badges, states, dialog text, warnings, error messages and assistive-technology labels) as an English source key in the i18n catalog and SHALL contain no hard-coded user-visible Connectors text in components.
2. THE Bellu_Code project SHALL add Connectors strings to the English catalog only, leaving the keys absent from every non-English catalog so that the English fallback applies.
3. WHEN a non-English locale is active and a Connectors key is absent from that locale's catalog, THE Settings_UI SHALL display the English string for that key.
4. THE Bellu_Code project SHALL define the Connectors_Flag in the shared flag schema (`packages/schema/src/config/flag.ts`), enabled by default in development builds and disabled by default in release builds.
5. WHILE the Connectors_Flag is disabled, THE Bellud and THE TS_Server SHALL NOT register or serve any `/api/experimental/connectors` route, THE Connector_Service SHALL NOT start any Connection, test or Connector_Collector, and THE Settings_UI SHALL NOT render the Connectors entry, the Connectors_Page or any Connector dialog.
6. THE Bellud SHALL serve every Connector route under the path prefix `/api/experimental/connectors`, and each route SHALL have the OpenAPI identifier `experimental.connectors.<name>`, where `<name>` is unique across all Connector routes and `experimental.connectors.` is the identifier prefix.
7. THE Bellu_Code protocol package SHALL declare each Connector route for the API contract only, with the same path and identifier as the Bellud route, the description suffix "Experimental: may change without compatibility guarantees.", and no handler registered in the TS_Server.
8. THE Bellu_Code project SHALL pass the experimental-identifiers test (`packages/protocol/test/experimental-identifiers.test.ts`) extended so that the set of routes whose path starts with `/api/experimental/connectors/` equals the set of operations whose identifier starts with `experimental.connectors.`, in both directions.
9. WHEN the public Protocol or HttpApi changes, THE Bellu_Code project SHALL regenerate the client so that the generated client files contain no difference from the checked-in files when regeneration is run a second time.
10. WHEN the Connector_Service receives a request to a Connector route that has a body, THE Connector_Service SHALL validate the body against that route's schema at the route boundary before any other processing, including the Credential_Vault and any outbound call.
11. IF a Connector route request body fails schema validation, THEN THE Connector_Service SHALL reject the request with a client-error response that names the failing fields without echoing any submitted value, SHALL perform no state change, and SHALL write no submitted Credential value to logs.
12. IF a Connector route request body exceeds 1 MiB, THEN THE Connector_Service SHALL reject the request with a client-error response before parsing the body and SHALL perform no state change.

### Requirement 12: Verification

**User Story:** As a maintainer, I want automated checks of security properties, so that regressions are caught.

#### Acceptance Criteria

1. THE Bellu_Code test suite SHALL include a property test that, for at least 100 generated Credential values of 1 to 65,536 bytes each (including values containing non-ASCII and control characters), encrypts each value and then decrypts it through the Credential_Vault and asserts the decrypted bytes are identical to the original.
2. IF a ciphertext is tampered with (any single-bit flip, truncation, or appended byte in the ciphertext, nonce, or wrapped data encryption key) or the authenticated data differs from the data used at encryption, THEN THE Credential_Vault SHALL fail decryption with an error and return zero bytes of plaintext, and a property test of at least 100 generated cases SHALL assert this.
3. THE Bellu_Code test suite SHALL include a property test that, for at least 100 generated Credential values whose generated length range covers at least 8 to 4,096 characters (a wider range is acceptable), passes each value through log, error, Audit_Log and Graph_Engine batch outputs of the Secret_Redactor and asserts that neither the verbatim value nor its JSON-escaped form appears in any output.
4. IF a call targets an operation outside a Connector's read allowlist, THEN THE Connector_Service SHALL reject the call with an error indicating the operation is not permitted, send zero requests to the external service, and record the rejection in the Audit_Log, and a property test of at least 100 generated operations SHALL assert this.
5. THE Bellu_Code test suite SHALL include a scan test that plants at least one unique Credential value, runs the connect, test, collect and failure flows, then scans the database contents, log output, API responses and TS_Server payloads for each planted value, and passes only if zero occurrences are found.
6. IF any property test or scan test in this requirement fails, THEN THE Bellu_Code test suite SHALL exit with a non-zero status and report the failing test name and the shrunk counterexample, with Credential values redacted in that report.

### Requirement 13: Auth Configs

**User Story:** As a user, I want a reusable auth blueprint per Connector, so that I can use the default app or bring my own app with narrower read scopes.

#### Acceptance Criteria

1. THE Connector_Service SHALL provide each Connector with exactly one default Auth_Config that states the auth method, the read scopes and a reference to the built-in app credentials, SHALL NOT allow that default Auth_Config to be edited or deleted, and SHALL NOT include any built-in app secret value in any API response.
2. WHERE the user creates a custom Auth_Config, THE Connector_Service SHALL accept a name of 1 to 40 characters and user-supplied OAuth app settings, GitHub App settings or AWS role settings, limited to the settings type that the Connector's Connector_Manifest lists as a supported auth method. THE Connector_Service SHALL store every app secret of that Auth_Config in the Credential_Vault, SHALL NOT store any app secret outside the Credential_Vault, and SHALL NOT return any app secret value in any API response after creation.
3. WHERE the user creates a custom Auth_Config, THE Settings_UI SHALL list for selection exactly the scopes of the Connector's read-only scope set (the scopes in the Connector_Manifest that the Read_Only_Policy classifies as read operations), SHALL NOT list any other scope, and SHALL require at least 1 selected scope before enabling the save action.
4. IF a submitted Auth_Config requests one or more scopes outside the Connector's read-only scope set, THEN THE Connector_Service SHALL reject the Auth_Config with an error naming each offending scope, SHALL store nothing in the Credential_Vault or in the Auth_Config list, and SHALL leave any existing Auth_Config unchanged.
5. WHEN the user creates a Connection, THE Settings_UI SHALL let the user choose exactly one Auth_Config of that Connector, with the default Auth_Config preselected.
6. WHEN the user deletes a custom Auth_Config that is in use by at least one Connection, THE Connector_Service SHALL reject the deletion with an error stating the count of Connections that use it, and SHALL keep the Auth_Config and its stored app secrets unchanged.
7. IF a submitted custom Auth_Config has a name that is empty, longer than 40 characters or equal to the name of another Auth_Config of the same Connector, or lacks a required setting, or would raise the number of custom Auth_Configs of that Connector above 10, THEN THE Connector_Service SHALL reject it with an error naming each invalid field (or the limit), SHALL store nothing, and THE Settings_UI SHALL keep the dialog open with the non-secret fields retained.
8. IF the Credential_Vault fails to store an app secret while a custom Auth_Config is being created, THEN THE Connector_Service SHALL reject the creation with an error indicating a storage failure, SHALL remove any app secret already stored for that Auth_Config, SHALL NOT create the Auth_Config, and SHALL NOT include any secret value in the error.
9. WHEN the user deletes a custom Auth_Config that is in use by no Connection, THE Connector_Service SHALL delete its app secrets from the Credential_Vault and then remove the Auth_Config, and IF the Credential_Vault fails to delete them, THEN THE Connector_Service SHALL keep the Auth_Config and return an error indicating a storage failure.

### Requirement 14: Connection Lifecycle and Automatic Refresh

**User Story:** As a user, I want clear connection states and automatic token refresh, so that connections stay healthy and I know when to reconnect.

#### Acceptance Criteria

1. THE Connector_Service SHALL keep each Connection in exactly one Connection_Status of INITIATED, VERIFYING, ACTIVE, EXPIRED, PAUSED or ERROR at any time.
2. THE Settings_UI SHALL show the card state derived from Connection_Status as defined in the Glossary: ACTIVE as Connected, INITIATED or VERIFYING as Connecting, EXPIRED or ERROR as Needs attention, and PAUSED as Paused, and SHALL update the card state within 1 second of a Connection_Status change.
3. WHEN the provider reports that the token or refresh credential of a Connection is revoked or expired, THE Connector_Service SHALL set the Connection to EXPIRED, stop its Connector_Collectors within 5 seconds, and delete the expired Credential material held in memory, and THE Settings_UI SHALL show an enabled "Reconnect" action on the Connection.
4. WHEN the user completes "Reconnect" for an EXPIRED or ERROR Connection, THE Connector_Service SHALL set the Connection to VERIFYING, verify the new Credential within 30 seconds, and, if verification succeeds and no write-capable permission is found, SHALL set the same Connection to ACTIVE, keeping its Connection identifier, Account_Alias and graph source tag.
5. IF verification of the new Credential fails or does not complete within 30 seconds after "Reconnect", THEN THE Connector_Service SHALL set the Connection to ERROR with a typed error category, SHALL keep the previously ingested graph data unchanged, and THE Settings_UI SHALL show the sanitized error reason, containing no Credential value, and an enabled "Reconnect" action.
6. WHEN an OAuth, GitHub App or AWS session credential of an ACTIVE Connection has 300 seconds or less before expiry, THE Connector_Service SHALL start a refresh and complete it before the expiry time.
7. IF a credential refresh fails after the retries defined for that Connector, THEN THE Connector_Service SHALL set the Connection to EXPIRED, stop its Connector_Collectors within 5 seconds, and THE Settings_UI SHALL show the sanitized failure reason and an enabled "Reconnect" action.
8. WHEN a Connection changes Connection_Status, THE Connector_Service SHALL append an Audit_Log entry containing the Connection identifier, the previous Connection_Status, the new Connection_Status and a timestamp, and the entry SHALL contain no Credential value.
9. IF a requested Connection_Status change is not on the allowed transition list (INITIATED to VERIFYING; VERIFYING to ACTIVE or ERROR; ACTIVE to EXPIRED, PAUSED or ERROR; PAUSED to ACTIVE or ERROR; EXPIRED to VERIFYING; ERROR to VERIFYING), THEN THE Connector_Service SHALL reject the change, SHALL keep the current Connection_Status, and SHALL append an Audit_Log entry recording the rejected transition.

### Requirement 15: No Token Export

**User Story:** As a user, I want a guarantee that no interface hands out my tokens, so that a compromised caller cannot steal them.

#### Acceptance Criteria

1. THE Connector_Service SHALL NOT expose any endpoint, including read, list, debug and export endpoints, whose response contains a Credential value, a wrapped data key or the Master_Key, for any caller role, including the web client, the TS_Server, Agent_Tools and MCP tokens.
2. WHEN the Connector_Service returns a response for a Connection, THE Connector_Service SHALL replace every Credential field with the masked metadata defined in Requirement 6, criterion 13 (at most the last 4 characters of the Credential, the creation time and the expiry time).
3. IF a request asks for a Credential through any query parameter, header, request body field or debug option, THEN THE Connector_Service SHALL ignore the option, SHALL return the same masked response as for a request without it, SHALL NOT return the Credential, and SHALL append an Audit_Log entry containing the Connection identifier, the caller role and a timestamp, and containing no Credential value.
4. IF a Connector route returns an error response, THEN THE Connector_Service SHALL return an error body that contains no Credential value and no part of a Credential longer than 4 characters.
5. WHEN a Proxy_Request completes, THE Connector_Service SHALL return only the provider response, with the Credential and any provider-echoed Credential value removed by the Secret_Redactor.
6. THE Bellu_Code test suite SHALL include a test that plants a unique Credential value in a Connection, calls every registered Connector route with valid, invalid and Credential-requesting inputs (including the parameters, headers and debug options of criterion 3), and fails if any response body, response header or Audit_Log entry contains the planted value or any substring of it longer than 4 characters.
7. THE Bellu_Code test suite SHALL fail if a Connector route exists that the test of criterion 6 does not call.

### Requirement 16: Proxy Execution

**User Story:** As a user, I want every provider call to go through Bellud, so that no caller ever holds my credentials.

#### Acceptance Criteria

1. THE Connector_Service SHALL send every provider call of the built-in Connector_Collectors, the Plugin_Connectors and the Agent_Tools through a Proxy_Request, and SHALL NOT send any provider call by another path.
2. WHEN the Connector_Service executes a Proxy_Request, THE Connector_Service SHALL inject the Credential server-side, apply the Read_Only_Policy, the Egress_Allowlist and the rate limits of Requirement 7, criterion 12, and return only the provider response to the caller.
3. THE Connector_Service SHALL NOT include the Credential value in any form (plain, encoded or partial) in any request, response, event, log entry or error returned to a caller, including request headers echoed in a response.
4. WHEN a provider response contains a header or body field that echoes the Credential, THE Secret_Redactor SHALL remove that value before the Connector_Service returns the response, and the response SHALL still be returned with the remaining provider content unchanged.
5. WHEN an Agent_Tool issues a Proxy_Request, THE Connector_Service SHALL execute it only if its operation is on the Connector's read-operation allowlist and its Connection is within the Session_Scope of the calling session.
6. IF a Proxy_Request violates the Read_Only_Policy, the Egress_Allowlist or the Session_Scope, THEN THE Connector_Service SHALL send zero requests to the provider, return a denial error that names the violated policy and contains no Credential value, and append an Audit_Log entry containing the Connection identifier, the caller identity, the attempted operation, the violated policy and a timestamp.
7. IF the Credential_Vault cannot release the Credential for a Proxy_Request, THEN THE Connector_Service SHALL send zero requests to the provider, return a typed error to the caller that contains no Credential value, and leave the Connection state and the stored Credential unchanged.
8. IF a Proxy_Request receives no provider response within 30 seconds, THEN THE Connector_Service SHALL cancel the provider call and return a network error to the caller that contains no Credential value.
9. THE Bellu_Code test suite SHALL include a test for each of the built-in Connector_Collectors, a Plugin_Connector and an Agent_Tool that plants a Credential value and asserts that the value appears in no Proxy_Request result, error or Audit_Log entry returned to the caller.

### Requirement 17: Scoped Agent Access

**User Story:** As a user, I want to limit what each agent session can reach, so that agents see only the connections I choose.

#### Acceptance Criteria

1. WHEN the user saves a Session_Scope for an agent session or MCP token, THE Connector_Service SHALL store a subset of Connectors, a subset of Connections and a subset of read operations, each read operation being on the read-operation allowlist of its Connector, and IF the Session_Scope contains an operation outside that allowlist, THEN THE Connector_Service SHALL reject it with a validation error naming the operation and SHALL keep the previous Session_Scope unchanged.
2. WHEN an agent session or MCP token is created without an explicit Session_Scope, THE Connector_Service SHALL give it access to read-only graph data, SHALL give it zero Connections for Proxy_Requests, and SHALL deny every Proxy_Request from it with an authorization error.
3. WHERE the user has enabled "Allow agent live reads" for a Connection, WHEN an agent session or MCP token whose Session_Scope includes that Connection and operation issues a read Proxy_Request for it, THE Connector_Service SHALL execute the Proxy_Request under the Read_Only_Policy, the Egress_Allowlist and the rate limits of Requirement 16, criterion 2.
4. IF an agent session or MCP token issues a Proxy_Request for a Connection, Connector or operation outside its Session_Scope, or for a Connection whose "Allow agent live reads" is disabled, THEN THE Connector_Service SHALL send zero requests to the provider, SHALL return an authorization error, and SHALL append an Audit_Log entry containing the session or token identifier, the Connection, the operation and the reason for denial, and no Credential value.
5. WHEN the user disables "Allow agent live reads" for a Connection, THE Connector_Service SHALL, within 5 seconds, deny every live-read Proxy_Request from agent sessions for that Connection and SHALL cancel any such Proxy_Request not yet sent to the provider.
6. WHEN a Connection is created, THE Connector_Service SHALL store "Allow agent live reads" as disabled and THE Settings_UI SHALL show it as disabled.
7. WHEN the user changes the Session_Scope of an existing agent session or MCP token, THE Connector_Service SHALL apply the new Session_Scope to every Proxy_Request received more than 5 seconds after the change, and SHALL keep the graph data access of criterion 2 unchanged.

## Out of Scope

- Write, remediation or deploy actions against any connected service.
- Implementing Cloudflare, GitLab, Sentry, MongoDB, Railway, Azure, Google Cloud, Render and Supabase connectors (catalog cards only in this phase).
- Migrating existing provider credentials in the `credential` table (tracked separately, see 6.15).
- A hosted plugin marketplace and cross-device credential sync.
- Team or organization shared connections and remote (non-local) Bellud deployments.
- Webhook ingestion and real-time event streaming.
- Ingestion of file contents, secret values or database records.
- Using Composio Cloud or any third-party credential custody service.
