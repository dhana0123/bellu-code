# Requirements Document

## Introduction

Settings > Security > Connectors currently offers GitHub only through a fine-grained personal access token. The dialog lists "GitHub App installation" and "OAuth device flow" as disabled ("Available in a later release"). This feature replaces that with a sign-in flow: the user clicks Connect on GitHub, authorizes the public "Bellu Code" GitHub App on github.com, and returns to Bellu Code connected, without creating a token by hand.

The project owner registers one public GitHub App named "Bellu Code" with read-only permissions (Metadata, Contents, Pull requests, Issues, Actions, Dependabot alerts, Code scanning alerts, Secret scanning alerts). Only its public Client ID ships in the code. No client secret ships in open source code, so open source users never create their own GitHub App.

Bellud runs on a remote host reached through an SSH tunnel, so a browser redirect callback is impractical. The primary mechanism is the GitHub device authorization flow, which needs a Client ID only and no callback URL. The fine-grained personal access token stays as a fallback under an Advanced option.

Scope boundaries:
- Read-only enforcement (policy allowlist), audit logging and the Credential_Vault stay in the Go core and are unchanged in behavior. The new flow only adds a credential source.
- Token refresh with a client secret is out of scope for open source builds. The App is registered with user token expiration disabled. Tokens that do carry an expiry end in an Expired state with a Reconnect action. A hosted refresh endpoint is recorded as an open question for the design.
- The feature remains behind the existing `connectors` flag.
- The design must let contributors add a device-flow sign-in for another connector by supplying a manifest entry and a small provider adapter, without changing the dialog shell or the lifecycle manager.

## Glossary

- **Bellu_App**: The public GitHub App named "Bellu Code" registered by the project owner, identified by its public Client_ID.
- **Client_ID**: The public identifier of the Bellu_App, compiled into bellud as a constant. It is not a secret.
- **Client_Secret**: The Bellu_App secret held by the project owner. It never appears in the repository, release artifacts, logs, API responses or the browser.
- **Device_Flow**: The GitHub device authorization grant: bellud requests a device code and user code, the user enters the user code on github.com, and bellud polls GitHub until authorization completes.
- **Device_Authorization**: One in-progress Device_Flow attempt, holding the device code, user code, verification URL, polling interval and expiry.
- **User_Code**: The short code the user types on the verification page.
- **Verification_URL**: The GitHub page where the user enters the User_Code.
- **User_Token**: The GitHub App user access token returned by a completed Device_Flow.
- **Installation**: The Bellu_App installed on a GitHub user or organization account, granting access to selected repositories.
- **Connection**: A stored link between Bellu Code and one provider account, as defined by the cloud-connectors spec.
- **Credential_Vault**: The encrypted store in bellud that holds credentials (the `vault` package).
- **Connectors_Service**: The bellud service that owns lifecycle, broker, policy, audit and vault for connectors.
- **Broker**: The bellud component that injects credentials into outbound requests and enforces the read-only policy.
- **Sign_In_Machine**: The explicit state machine in `packages/app` that models the GitHub sign-in dialog phases.
- **Advanced_Option**: A collapsed section of the GitHub connect dialog containing the fine-grained personal access token form.
- **Memory_Only_Mode**: The Credential_Vault mode used when no master key source is configured, where credentials live only in process memory and are lost on restart.
- **Expiring_Token**: A User_Token whose GitHub response includes an expiry.

## Requirements

### Requirement 1: Sign in with GitHub from the Connect dialog

**User Story:** As a user, I want to click Connect on GitHub and authorize Bellu Code on github.com, so that I connect without creating a token by hand.

#### Acceptance Criteria

1. WHEN the user opens the Connect dialog for GitHub, THE Connect_Dialog SHALL show exactly one primary "Sign in with GitHub" action, enabled when the Account_Alias is valid and unused by another GitHub Connection, and positioned above the Advanced_Option.
2. WHEN the user opens the Connect dialog for GitHub, THE Connect_Dialog SHALL NOT show the "GitHub App installation" row or the "OAuth device flow" row, and SHALL NOT show any row marked "Available in a later release".
3. WHEN the user opens the Connect dialog for GitHub, THE Connect_Dialog SHALL show the fine-grained personal access token form only inside the Advanced_Option, collapsed by default and hidden from view until the user expands it.
4. WHEN the user activates "Sign in with GitHub" with a valid Account_Alias, THE Connectors_Service SHALL start exactly one Device_Authorization using the Client_ID, even if the action is activated multiple times within 5 seconds.
5. WHILE a Device_Authorization is starting, THE Connect_Dialog SHALL disable "Sign in with GitHub" and show a Loader until the Device_Authorization starts successfully or fails.
6. IF the Account_Alias is empty, longer than 64 characters, contains characters outside the allowed alias format, or matches the alias of an existing GitHub Connection, THEN THE Connect_Dialog SHALL keep "Sign in with GitHub" disabled and show an alias error indicating the reason, without starting a Device_Authorization.
7. IF starting the Device_Authorization fails or does not complete within 15 seconds, THEN THE Connect_Dialog SHALL hide the Loader, re-enable "Sign in with GitHub", show an error indicating the failure reason, and preserve the entered Account_Alias.

### Requirement 2: Device authorization prompt

**User Story:** As a user, I want clear instructions and a code to enter on GitHub, so that I can authorize Bellu Code even when my browser is on another machine.

#### Acceptance Criteria

1. WHEN GitHub returns a Device_Authorization, THE Connect_Dialog SHALL display the User_Code, the Verification_URL and the time remaining before the code expires in minutes and seconds (MM:SS), updating the displayed value every 1 second.
2. WHEN GitHub returns a Device_Authorization, THE Connect_Dialog SHALL offer an "Open GitHub" action that opens the Verification_URL in a new browser tab with `rel="noopener noreferrer"`.
3. WHEN the user activates the "Copy code" action, THE Connect_Dialog SHALL copy the User_Code to the clipboard and display a confirmation that the code was copied for 2 seconds.
4. IF the browser clipboard API is unavailable or the copy attempt fails, THEN THE Connect_Dialog SHALL keep the User_Code displayed as selectable visible text and display an error indication that the copy failed.
5. WHILE the Device_Authorization is pending, THE Connect_Dialog SHALL show a waiting indicator using Loader and a "Cancel" action.
6. WHILE the Device_Authorization is pending, THE Connect_Dialog SHALL announce each change of state (code displayed, code copied, code expired, authorization denied, authorization completed) through an `aria-live="polite"` region, and SHALL NOT announce the per-second countdown updates.
7. THE Connect_Dialog SHALL NOT display the device code at any time.
8. THE Connectors_Service SHALL send only the User_Code, the Verification_URL and the code expiry time to the browser, and SHALL keep the device code inside bellud.
9. IF the time remaining before the code expires reaches 0 seconds, THEN THE Connect_Dialog SHALL stop the waiting indicator, display an error indication that the code has expired, disable the "Open GitHub" and "Copy code" actions, and offer a "Try again" action that requests a new Device_Authorization.
10. WHEN the user activates the "Cancel" action, THE Connect_Dialog SHALL stop waiting for authorization, discard the displayed User_Code and close the dialog without creating a connection.
11. IF GitHub denies the authorization or the Device_Authorization request fails, THEN THE Connect_Dialog SHALL stop the waiting indicator, display an error indication stating the reason for the failure, retain no connection, and offer a "Try again" action.

### Requirement 3: Server-side polling

**User Story:** As a user, I want Bellu Code to detect my authorization automatically, so that I return to a connected state without further steps.

#### Acceptance Criteria

1. WHILE a Device_Authorization is pending, THE Connectors_Service SHALL poll GitHub no more often than once per interval returned by GitHub, and SHALL use 5 seconds as the interval when GitHub returns none.
2. WHEN GitHub answers `slow_down`, THE Connectors_Service SHALL increase the polling interval by the number of seconds GitHub specifies, or by 5 seconds when none is specified, and SHALL apply the new interval to all subsequent polls of that Device_Authorization.
3. WHEN GitHub answers `authorization_pending`, THE Connectors_Service SHALL continue polling at the current interval without changing the interval or reporting an error.
4. WHEN GitHub returns a User_Token, THE Connectors_Service SHALL stop polling, create the Connection, and report success to the Connect_Dialog.
5. WHEN GitHub answers `expired_token`, THE Connectors_Service SHALL stop polling, discard the Device_Authorization, and report a typed `device_code_expired` error.
6. WHEN GitHub answers `access_denied`, THE Connectors_Service SHALL stop polling, discard the Device_Authorization, and report a typed `authorization_denied` error.
7. WHEN the user cancels, THE Connectors_Service SHALL stop polling within 5 seconds, discard the Device_Authorization, and create no Connection, including when a poll response is received after cancellation.
8. IF a Device_Authorization is already pending for a connector and Account_Alias, THEN THE Connectors_Service SHALL reject a request to start another for the same connector and Account_Alias with an error indicating an authorization is already pending, and SHALL leave the existing Device_Authorization unchanged.
9. IF bellud cannot reach GitHub during polling, THEN THE Connectors_Service SHALL retry with a delay that increases after each consecutive failure, starting at the current polling interval and not exceeding 60 seconds, until the Device_Authorization expires, and SHALL report a typed `network` error when it expires. WHEN a poll succeeds after a failure, THE Connectors_Service SHALL reset the retry delay to the current polling interval.
10. WHEN the Connect dialog closes or the user navigates away, THE Connectors_Service SHALL stop polling for that Device_Authorization within 5 seconds and discard it.
11. WHILE the Connect_Dialog is awaiting the outcome of a pending Device_Authorization, THE Connect_Dialog SHALL request the status route every 2 seconds, with each request timing out after 5 seconds.
12. IF a status request from the Connect_Dialog times out or fails, THEN THE Connect_Dialog SHALL keep the Device_Authorization pending, continue requesting every 2 seconds, and leave the polling performed by the Connectors_Service unaffected.

### Requirement 4: Public client, no secret in the repository

**User Story:** As an open source maintainer, I want the shipped code to contain only the public Client_ID, so that nobody needs a secret or a GitHub App of their own.

#### Acceptance Criteria

1. THE Connectors_Service SHALL read the compiled Client_ID from exactly one constant definition in the source code.
2. IF the environment variable `BELLUCODE_GITHUB_CLIENT_ID` is set to a non-empty value at Connectors_Service startup, THEN THE Connectors_Service SHALL use that value, with leading and trailing whitespace removed, instead of the compiled Client_ID.
3. IF the environment variable `BELLUCODE_GITHUB_CLIENT_ID` is unset or empty, THEN THE Connectors_Service SHALL use the compiled Client_ID.
4. WHEN a user starts GitHub sign-in, THE Connectors_Service SHALL complete Device_Flow, token verification and collection by sending only the Client_ID and no Client_Secret in every request to GitHub.
5. THE repository, the built bellud binary and every release artifact SHALL NOT contain the Client_Secret.
6. IF a Client_Secret is supplied through configuration, an environment variable, a request parameter or the Connect_Dialog, THEN THE Connectors_Service SHALL ignore it and SHALL NOT persist it in any file, database or log.
7. IF the effective Client_ID is empty after applying the environment override, THEN THE Connectors_Service SHALL report GitHub sign-in as unavailable and THE Connect_Dialog SHALL show the Advanced_Option expanded with a text explaining that no Client_ID is configured and how to provide one.
8. THE project documentation SHALL describe the steps to register a custom GitHub App with Device_Flow enabled, and to set `BELLUCODE_GITHUB_CLIENT_ID` to its Client_ID for forks.

### Requirement 5: Installation and repository selection

**User Story:** As a user, I want to choose which repositories Bellu Code reads, so that access stays limited to what I intend.

#### Acceptance Criteria

1. WHEN a User_Token is obtained, THE Connectors_Service SHALL list the Installations of the Bellu_App that the user can access, within 10 seconds.
2. IF the user has no Installation, THEN THE Connect_Dialog SHALL show an "Install Bellu Code on GitHub" action that opens the Bellu_App installation page, and a "Check again" action.
3. WHEN the user activates "Check again", THE Connectors_Service SHALL list Installations again and THE Connect_Dialog SHALL replace the no-Installation view with the repository list if at least one Installation is returned.
4. WHEN at least one Installation exists, THE Connect_Dialog SHALL list the repositories reachable through all of the user's Installations, show each repository's full name, and let the user select between 1 and 500 repositories.
5. WHEN the user saves a repository selection of at least one repository, THE Connectors_Service SHALL store the selection on the Connection and THE collector SHALL read only the selected repositories.
6. IF the user changes the selection so that zero repositories are selected, THEN THE Connect_Dialog SHALL show the "select at least one repository" message and keep Save disabled, and THE Connectors_Service SHALL keep the previously stored selection unchanged.
7. WHILE the user has not changed the selection since the Connect_Dialog opened, THE Connect_Dialog SHALL NOT show the "select at least one repository" message.
8. IF listing Installations or repositories fails or exceeds 10 seconds, THEN THE Connect_Dialog SHALL show an error indication of the failure and a retry action, and THE Connectors_Service SHALL keep the Connection and its stored selection unchanged.
9. WHEN the user activates the retry action, THE Connectors_Service SHALL repeat the failed listing request.

### Requirement 6: Connection creation and verification

**User Story:** As a user, I want the connection verified before it becomes active, so that I know it works.

#### Acceptance Criteria

1. WHEN GitHub returns a User_Token, THE Connectors_Service SHALL store it in the Credential_Vault, create the Connection with method `device`, and move it through the existing lifecycle states.
2. WHEN the Connection is verified, THE Connectors_Service SHALL record the GitHub login as the account label, and the recorded label SHALL equal the login returned by GitHub for the User_Token.
3. WHEN the Connection is verified, THE Connectors_Service SHALL record the Connection `permission_check` as `unverifiable` with the message "Permissions can't be verified; write requests are still blocked by the allowlist".
4. IF verification fails with an authentication error, THEN THE Connectors_Service SHALL set the Connection to ERROR with typed error `invalid_credential`, delete the stored User_Token from the Credential_Vault, and make no further verification attempt for that User_Token.
5. IF verification fails with a non-authentication error (network failure, timeout of 30 seconds, or GitHub service error), THEN THE Connectors_Service SHALL set the Connection to ERROR with a typed error indicating the failure cause and delete the stored User_Token.
6. WHEN the user cancels after the User_Token is stored but before the repository selection is saved, THE Connectors_Service SHALL delete the Connection and the stored User_Token, and no Connection or User_Token for that attempt SHALL remain afterwards.
7. WHEN the Connect dialog is closed after the User_Token is stored but before the repository selection is saved, THE Connectors_Service SHALL delete the Connection and the stored User_Token, and no Connection or User_Token for that attempt SHALL remain afterwards.
8. WHEN a Device_Authorization starts, succeeds, is denied, expires or is cancelled, THE Connectors_Service SHALL append one audit entry naming the connector, alias, event type and outcome, and the entry SHALL NOT contain the User_Token, device code or any other credential.
9. IF the audit entry cannot be written, THEN THE Connectors_Service SHALL fail the connect with an error indicating the audit failure, release no credential to any caller, delete any stored User_Token and Connection created for that attempt, and report the failure to the user.

### Requirement 7: Token handling and secrecy

**User Story:** As a security-minded user, I want authorization tokens kept inside bellud, so that they cannot leak through the browser or logs.

#### Acceptance Criteria

1. THE Connectors_Service SHALL keep the User_Token, the device code and any refresh token only inside the bellud process, and SHALL persist them only in the Credential_Vault.
2. WHEN the Connectors_Service obtains a User_Token or device code, THE Connectors_Service SHALL register that value with the redactor before any outbound request uses it.
3. THE Connectors_Service SHALL NOT include the User_Token, device code or refresh token in logs, audit entries, error messages, API responses, graph batches or the TS child process environment, arguments and standard input.
4. WHEN a GitHub request is sent, THE Broker SHALL inject the User_Token into that request, and no collector or client SHALL read the User_Token.
5. WHEN a client calls a connector API route that returns token information, THE Connectors_Service SHALL return only the last 4 characters of the User_Token, its creation time and its expiry time.
6. WHEN the Connect_Dialog finishes, fails or closes, THE Connect_Dialog SHALL hold zero credential values in any store, URL, local storage, session storage or log.
7. IF the Credential_Vault write for a User_Token, device code or refresh token fails, THEN THE Connectors_Service SHALL discard the value from memory, return an error indicating the credential could not be stored without including the credential value, and leave any previously stored credential unchanged.
8. FOR ALL registered credentials planted during a device flow test run, scanning `state.json`, `vault.json`, audit files, captured logs and every API response SHALL find zero occurrences of the plaintext credential value, except that `vault.json` may contain the value only in its encrypted form.

### Requirement 8: Read-only enforcement is unchanged

**User Story:** As a user, I want Bellu Code to only read from GitHub, so that authorizing the app cannot change my repositories.

#### Acceptance Criteria

1. WHEN the Broker receives a request carrying a User_Token, THE Broker SHALL apply the existing GitHub read allowlist and forward the request only if its HTTP method is GET, HEAD or OPTIONS, or it is a GraphQL query containing no mutation or subscription operation, and its destination host is an allowlisted host.
2. IF a request carrying a User_Token uses a method other than GET, HEAD or OPTIONS, contains a GraphQL mutation or subscription, or targets a host that is not allowlisted, THEN THE Broker SHALL send zero bytes to the destination, append one audit entry recording the rejection, and return a typed policy error to the caller.
3. IF a request carrying a User_Token cannot be classified as allowed or denied (for example, an unparseable GraphQL body or a body larger than the Broker's inspection limit), THEN THE Broker SHALL treat it as not on the allowlist and apply criterion 2.
4. WHEN the lifecycle caller invokes a github.com device-flow endpoint under a manifest operation of class `auth`, THE Broker SHALL forward the request.
5. IF a caller other than the lifecycle caller, or a request outside a manifest operation of class `auth`, targets a github.com device-flow endpoint, THEN THE Broker SHALL send zero bytes, append one audit entry, and return a typed policy error.
6. THE manifest for GitHub SHALL list the github.com device-flow paths in its egress hosts and as class `auth` operations.
7. WHEN the connect dialog is displayed for GitHub, THE connect dialog SHALL list the github.com device-flow hosts in the same list as the other egress hosts from the manifest.
8. THE Bellu_App registration SHALL request exactly these read-only permissions and no others: Metadata, Contents, Pull requests, Issues, Actions, Dependabot alerts, Code scanning alerts and Secret scanning alerts, each at read-only access level.
9. THE collector SHALL NOT ingest pull request bodies, issue bodies, file contents or commit contents, as already specified for the GitHub collector.

### Requirement 9: Token expiry

**User Story:** As a user, I want to know when my GitHub authorization stops working, so that I can reconnect.

#### Acceptance Criteria

1. THE project documentation SHALL state that the Bellu_App is registered with user token expiration disabled.
2. WHERE GitHub returns an expiry timestamp with the User_Token, THE Connectors_Service SHALL record the expiry timestamp on the Connection.
3. WHILE an Expiring_Token has more than 0 and fewer than 7 days (168 hours) remaining, THE Connect_Dialog connection list SHALL show an "Expires soon" warning and a Reconnect action for the Connection.
4. WHEN an Expiring_Token reaches its recorded expiry time, THE Connectors_Service SHALL set the Connection to EXPIRED, retain the last collected graph data unchanged, and stop all collection requests for the Connection within 60 seconds.
5. WHEN the user reconnects an EXPIRED Connection through Sign in with GitHub and authorization succeeds, THE Connectors_Service SHALL keep the Connection id, alias and source tag, replace the stored User_Token, and set the Connection status to a non-EXPIRED active state.
6. IF GitHub answers HTTP 401 to a collection request, THEN THE Connectors_Service SHALL set the Connection to EXPIRED, retain the last collected graph data unchanged, make 0 retries of that request, and stop further collection for the Connection.
7. THE Connectors_Service SHALL NOT attempt a token refresh that requires the Client_Secret.
8. IF reconnecting an EXPIRED Connection fails or the user cancels Sign in with GitHub, THEN THE Connectors_Service SHALL keep the Connection in EXPIRED status with its existing id, alias, source tag, stored User_Token and graph data unchanged, and THE Connect_Dialog SHALL show an error indicating the reconnect did not complete.
9. WHILE a Connection is EXPIRED, THE Connect_Dialog connection list SHALL show an "Expired" indicator and a Reconnect action for the Connection.

### Requirement 10: Disconnect and revocation

**User Story:** As a user, I want disconnecting to remove the token from Bellu Code and tell me how to revoke access at GitHub, so that I stay in control.

#### Acceptance Criteria

1. WHEN the user confirms disconnecting a GitHub Connection created with Sign in with GitHub, THE Connectors_Service SHALL delete the stored User_Token, stop all collectors for that Connection within 5 seconds and remove the Connection's graph entities within 30 seconds.
2. WHEN the user opens the disconnect confirmation for a GitHub Connection, THE disconnect confirmation SHALL display text stating that revoking access at GitHub is a separate step that Bellu Code does not perform, and SHALL display a link to the GitHub page for authorized GitHub Apps.
3. IF deleting the stored User_Token fails, THEN THE Connectors_Service SHALL keep the Connection in its current state, keep the Connection's collectors stopped, retain the Connection's graph entities, display an error indicating the token could not be deleted and display a Retry action.
4. WHEN the user selects the Retry action after a failed User_Token deletion, THE Connectors_Service SHALL repeat the disconnect sequence from deleting the stored User_Token.
5. IF the user cancels the disconnect confirmation, THEN THE Connectors_Service SHALL leave the Connection, the stored User_Token, the running collectors and the graph entities unchanged.

### Requirement 11: Advanced fallback with a fine-grained personal access token

**User Story:** As a user who cannot use the GitHub App, I want to keep using a fine-grained personal access token, so that I can still connect.

#### Acceptance Criteria

1. WHEN the user expands the Advanced_Option, THE Connect_Dialog SHALL show the existing token field, the optional GitHub Enterprise Server host field and the existing prefix and permissions notices.
2. IF the user submits a token that does not start with `github_pat_`, THEN THE Connectors_Service SHALL reject the submission, store no token, create no Connection, and THE Connect_Dialog SHALL show an error indicating the token prefix is invalid while retaining the values entered in the token and host fields.
3. WHEN the user submits a token that starts with `github_pat_`, THE Connectors_Service SHALL create the Connection with method `pat` and otherwise behave as it does today.
4. WHILE a Device_Authorization is pending, THE Connect_Dialog SHALL disable the Advanced_Option submit action.
5. WHILE a PAT connect request is running, THE Connect_Dialog SHALL disable "Sign in with GitHub" and SHALL re-enable it within 1 second after the request succeeds or fails.
6. IF a PAT connect request fails for a reason other than an invalid prefix, THEN THE Connectors_Service SHALL store no token and create no Connection, and THE Connect_Dialog SHALL show an error indicating the failure while retaining the values entered in the token and host fields.

### Requirement 12: GitHub Enterprise Server

**User Story:** As a user on GitHub Enterprise Server, I want to know what is supported, so that I choose the right method.

#### Acceptance Criteria

1. WHEN the user enters a host in the Connect_Dialog host field that is not "github.com" (case-insensitive), THE Connect_Dialog SHALL hide the "Sign in with GitHub" control and display the Advanced_Option token form within 200 ms of the field value changing.
2. WHEN the user changes the host field value back to "github.com" (case-insensitive), THE Connect_Dialog SHALL show the "Sign in with GitHub" control again and retain any text already entered in the Advanced_Option token form.
3. WHILE the host field value is not "github.com" (case-insensitive), THE Connect_Dialog SHALL display a note stating that sign-in with the Bellu_App is available for github.com only.
4. IF the user submits the Advanced_Option token form with an empty token or a token that the GitHub Enterprise Server host rejects, THEN THE Connect_Dialog SHALL keep the dialog open, preserve the entered host and token values, and display an error indicating that the token was missing or rejected.
5. IF the entered GitHub Enterprise Server host is unreachable within 30 seconds of submission, THEN THE Connect_Dialog SHALL keep the dialog open, preserve the entered host and token values, and display an error indicating that the host could not be reached.

### Requirement 13: Error handling and recovery

**User Story:** As a user, I want clear errors and a way to retry, so that a failed sign-in does not leave the dialog stuck.

#### Acceptance Criteria

1. IF the Device_Authorization code expires before the user completes authorization, THEN THE Connect_Dialog SHALL show the "code expired" message and a "Try again" action that starts a new Device_Authorization, and THE Connect_Dialog SHALL remain open and interactive.
2. IF the user denies authorization on GitHub, THEN THE Connect_Dialog SHALL stop polling, show the "authorization denied" message and a "Try again" action, and store no token.
3. IF bellud cannot start the Device_Flow because the device flow is disabled for the Bellu_App, THEN THE Connect_Dialog SHALL show the typed `device_flow_disabled` message, keep the Advanced_Option available, and not show a "Try again" action.
4. IF GitHub rate-limits the device endpoints, THEN THE Connectors_Service SHALL return a typed `rate_limited` error that includes the retry time in whole seconds (0 to 3600), and THE Connect_Dialog SHALL show the error message with that retry time and a "Try again" action.
5. WHEN the user activates "Try again", THE Sign_In_Machine SHALL discard the previous error and Device_Authorization and start a new attempt within 1 second, ending in the pending state with a new user code, or in a new error state if the attempt fails.
6. IF the Connectors_Service returns a typed error code with no matching i18n key, THEN THE Connect_Dialog SHALL show the English text of the `settings.connectors.error.unknown` key.
7. THE Connect_Dialog SHALL map every typed error code to an English i18n key under `settings.connectors.error.<code>`.
8. WHEN a pending phase ends, THE Sign_In_Machine SHALL transition to exactly one terminal state (success, error, expiry, cancel or dispose) within 1 second, and SHALL stop all polling timers for that attempt.

### Requirement 14: Credential vault limitation

**User Story:** As a user, I want to know when my sign-in will not survive a restart, so that I can set up persistent storage.

#### Acceptance Criteria

1. WHILE the Credential_Vault is in Memory_Only_Mode, THE Connect_Dialog SHALL display a notice, visible before the user can start sign-in, stating that the GitHub authorization is lost when bellud restarts.
2. WHILE the Credential_Vault is in Memory_Only_Mode, THE Connectors_Service SHALL allow the user to start and complete GitHub sign-in, and SHALL keep the resulting credential in memory until bellud stops.
3. WHEN bellud starts in Memory_Only_Mode, THE Connectors_Service SHALL set the status of every GitHub Connection that has no stored credential to EXPIRED within 5 seconds of startup completing.
4. WHILE a GitHub Connection has status EXPIRED, THE connection list SHALL show a Reconnect action for that Connection.
5. IF the Credential_Vault is not in Memory_Only_Mode, THEN THE Connect_Dialog SHALL NOT display the Memory_Only_Mode notice.
6. THE project documentation SHALL describe master key setup as the way to persist GitHub authorization across bellud restarts, including the steps required to configure the master key.

### Requirement 15: Sign-in state machine

**User Story:** As a developer, I want the sign-in phases modelled as an explicit state machine, so that stale results, double clicks and hung requests cannot leave the UI stuck.

#### Acceptance Criteria

1. THE Sign_In_Machine SHALL model the dialog as one discriminated union with exactly six phases, `idle`, `starting`, `awaiting`, `installing`, `repositories` and `failed`, discriminated by a single `phase` field, and every state value SHALL belong to exactly one phase.
2. THE Sign_In_Machine SHALL expose a pure `transition(state, event)` over a closed event union, SHALL return a state for every combination of phase and event without throwing, and SHALL perform no I/O, timer, signal or clock reads inside `transition`.
3. IF an event does not apply to the current state, THEN THE Sign_In_Machine SHALL return the same state object (reference equality) and SHALL NOT mutate the input state.
4. WHEN the user activates "Sign in with GitHub" in `idle`, THE Sign_In_Machine SHALL return a `starting` state with a new attempt id from `transition` for that single event, and THE driver SHALL start exactly one device authorization request for that event.
5. WHEN the user activates "Sign in with GitHub" in any phase other than `idle` and `failed`, THE Sign_In_Machine SHALL return the same state object and THE driver SHALL NOT start a request, so that a double click starts at most one request.
6. THE Sign_In_Machine SHALL carry an attempt id in each non-`idle` phase and in each result event, and IF a result event's attempt id is not equal to the current state's attempt id, THEN THE Sign_In_Machine SHALL return the same state object.
7. WHEN the user activates "Sign in with GitHub" in `failed`, THE Sign_In_Machine SHALL move to `starting` with a new attempt id different from every earlier attempt id in that dialog, and results carrying earlier attempt ids SHALL be ignored.
8. WHEN an `expired` event carrying the current attempt id is dispatched after the Device_Authorization expiry time, THE Sign_In_Machine SHALL move `awaiting` to `failed` with error code `device_code_expired`, and THE driver SHALL dispatch that event no later than 1 second after the expiry time.
9. IF a request in `starting`, `awaiting` or `installing` receives no result within 30 seconds, THEN THE driver SHALL abort the request and dispatch a failure event with the current attempt id, and THE Sign_In_Machine SHALL move to `failed` with error code `request_timeout`.
10. THE Sign_In_Machine SHALL expose pure selectors for disabled, busy, error and visible panel, each a function of state only, and components SHALL read dialog status only through those selectors and SHALL NOT read the `phase` field or other state fields directly.
11. THE Sign_In_Machine selectors SHALL return busy true for `starting` and `installing`, disabled true for `starting`, `awaiting` and `installing`, a non-empty error only for `failed`, and exactly one visible panel for each phase.
12. WHEN the dialog owner is disposed, THE driver SHALL dispatch a `disposed` event, abort all pending requests and clear all timers within 100 milliseconds, and SHALL dispatch no further events afterwards.
13. IF a result arrives after the `disposed` event, THEN THE Sign_In_Machine SHALL ignore it, and THE driver SHALL NOT update component state.
14. THE existing `github-machine.ts` repository-selection phases SHALL be reused or composed by the `repositories` phase, and THE Sign_In_Machine SHALL NOT define a second copy of those phases, events or transitions.

### Requirement 16: Extensibility for other connectors

**User Story:** As a contributor, I want to add device-flow sign-in to another connector without touching the core flow, so that the connector catalog can grow.

#### Acceptance Criteria

1. THE Connectors_Service SHALL define a provider-neutral device-authorization interface that a provider implements by supplying exactly these five inputs: device-code endpoint, token endpoint, client id, requested scopes (0 to 20 entries) and a token verification call.
2. THE manifest schema SHALL describe a `device` auth method that declares the device-code endpoint, token endpoint, client id and requested scopes, so that the Connect_Dialog can render the prompt from the catalog payload.
3. IF a manifest declares a `device` auth method with a missing or empty device-code endpoint, token endpoint or client id, THEN THE Connectors_Service SHALL reject the manifest at load time, omit that connector from the catalog payload, and report an error identifying the connector and the missing field.
4. WHEN the Connect_Dialog opens a connector whose auth method is `device`, THE Connect_Dialog SHALL render the user code, the verification URL and the polling status using only the catalog payload and the generic device-authorization routes, with no GitHub-specific code in the dialog shell.
5. THE Connectors_Service SHALL enforce the polling interval, expiry, cancellation, audit and redaction in the generic device-authorization code, so that a provider supplies none of these behaviors and cannot override them.
6. IF a provider performs a device-flow HTTP call other than through the Broker, THEN THE architecture import-graph tests SHALL fail and report the offending provider package and import path.
7. THE contributor documentation SHALL describe the ordered steps to add a device-flow connector, covering the manifest `device` entry, the provider interface implementation, the token verification call, and the tests to run, and SHALL include one complete worked example other than GitHub.

### Requirement 17: API and protocol

**User Story:** As a client developer, I want typed experimental routes for the device flow, so that the UI and other clients use the same contract.

#### Acceptance Criteria

1. THE protocol SHALL declare exactly three routes under `/api/experimental/connectors/`, one each to start a Device_Authorization, read the status of a Device_Authorization, and cancel a Device_Authorization, with identifiers of the form `experimental.connectors.<name>`.
2. WHEN a valid start request is received, THE start route SHALL return the User_Code, Verification_URL, expiry time, polling interval in seconds, and an authorization id, and SHALL NOT include the device code in the response body or headers.
3. WHEN a status request is received for a known authorization id, THE status route SHALL return exactly one of `pending`, `connected`, `expired`, `denied`, `failed`, and WHEN the value is `connected`, THE status route SHALL also return the Connection metadata.
4. IF a status or cancel request references an authorization id that does not exist or has already been removed, THEN THE route SHALL reject the request with a not-found error and SHALL leave all other Device_Authorizations unchanged.
5. WHEN a cancel request is received for a Device_Authorization in the `pending` state, THE cancel route SHALL stop polling for it, discard its device code, and report success, and subsequent status requests for that id SHALL NOT return `pending`.
6. IF a request to any of the routes lacks the `X-Bellucode-Client` header, comes from a non-loopback address, has a Host header that fails the Host check, or has a body larger than 1 MiB (1,048,576 bytes), THEN THE route SHALL reject the request with an error indicating the failed check and SHALL NOT start, change, or cancel any Device_Authorization.
7. WHEN the protocol changes, THE client SHALL be regenerated by running `bun run generate` from `packages/client`, and the regenerated client SHALL contain a typed method for each of the three routes.
8. WHILE the `connectors` flag is off, THE routes SHALL NOT be registered, and requests to them SHALL be rejected as not found.

### Requirement 18: Localization and accessibility

**User Story:** As a user relying on assistive technology or another language, I want the sign-in flow to be accessible and localizable, so that I can use it.

#### Acceptance Criteria

1. THE Connect_Dialog SHALL read every visible string, label and error message from i18n keys under `settings.connectors.`, with the keys added to the English catalog only and no hard-coded user-visible text in the dialog.
2. IF an i18n key under `settings.connectors.` used by the Connect_Dialog is missing from the active catalog, THEN THE Connect_Dialog SHALL render the English catalog text for that key and SHALL remain functional.
3. THE Connect_Dialog SHALL allow every interactive control to be reached and activated using only the keyboard, in an order that follows the visual order, with no keyboard trap.
4. WHILE a Connect_Dialog action has keyboard focus, THE Connect_Dialog SHALL display a visible focus indicator on that action.
5. WHEN the Connect_Dialog displays a User_Code, THE Connect_Dialog SHALL expose the User_Code to assistive technology as text, with each character announced, within 1 second of display.
6. THE Connect_Dialog SHALL render the User_Code in the code font.
7. WHILE the Connect_Dialog is waiting for authorization, THE Connect_Dialog SHALL show the remaining time as a text label in minutes and seconds and SHALL update the label at least every 5 seconds.
8. WHILE the Connect_Dialog is in any waiting state, THE Connect_Dialog SHALL show the `Loader` indicator and SHALL NOT show any other loading indicator.

### Requirement 19: Documentation and one-time registration

**User Story:** As the project owner, I want a checklist for registering the Bellu_App, so that the shipped Client_ID matches a correctly configured app.

#### Acceptance Criteria

1. THE project documentation SHALL list the following Bellu_App settings as a checklist with one line item per setting: name "Bellu Code", device flow enabled, user token expiration disabled, callback URL left empty, webhook inactive, installation allowed on any account (public), and the eight read-only permissions, each listed by permission name with its access level set to read-only.
2. THE project documentation SHALL state that the Client_Secret is generated only when a documented feature requires it, is held only by the project owner, and is never committed to the repository.
3. THE project documentation SHALL describe how a fork supplies its own Client_ID by setting the `BELLUCODE_GITHUB_CLIENT_ID` environment variable, and SHALL state that the shipped Client_ID is used when the variable is unset or empty.
4. THE project documentation SHALL state that the Client_ID is a public identifier that is safe to ship in source, and that the Client_Secret is not.

## Open Questions for the Design

1. Refresh without a secret: GitHub's refresh grant requires the Client_Secret. This spec assumes user token expiration is disabled on the Bellu_App. If the owner wants expiring tokens, a hosted refresh endpoint holding the secret is needed. That adds a service and a trust boundary, and its requirements would be a follow-up spec.
2. Revocation: revoking a User_Token through the GitHub API also needs the Client_Secret. This spec therefore links to GitHub's authorized apps page instead.
3. Installation scope: a User_Token only reaches repositories where the Bellu_App is installed and the user has access. Organizations may require an owner to approve the installation. The design should decide how the dialog explains a pending approval.
4. Token verification: confirm whether `/user` and `/user/installations` are sufficient with the chosen permissions, since the App has no user-level permissions.
