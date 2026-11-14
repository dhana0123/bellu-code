# Requirements Document

## Introduction

Add six new Sources (connectors in code): Google Cloud, Microsoft Azure, GitLab, Bitbucket, Kubernetes and Cloudflare. Version 1 supports verify and connect only; no data collection. Each Source gets a step-by-step wizard built on one shared wizard component, which AWS and GitHub also adopt. Exact auth method per provider is confirmed in design against provider docs.

## Glossary

- **Source**: User-facing name for a connector. Backend and code keep the name `connectors`.
- **Bellud**: The backend service hosting the connectors packages.
- **Catalog**: The registry of Source manifests in Bellud.
- **Provider**: The `lifecycle.Provider` implementation of a Source, with Verify, CheckPermissions, Refresh and Describe.
- **Broker**: The Bellud component that makes provider calls and enforces read-only access.
- **Vault**: The Bellud credential store.
- **Wizard**: The shared step-by-step UI component (stepper, choose method, create access, paste result, choose scope, Connected screen).
- **App**: The `packages/app` settings UI.
- **Sign-in**: A device flow or OAuth flow that yields a credential without the user pasting a secret.
- **Pasted_Credential**: A read-only token or key the user pastes into the Wizard.
- **Connectors_Flag**: The existing `connectors` feature flag.

## Requirements

### Requirement 1: Six new Sources in the Catalog

**User Story:** As a user, I want to connect Google Cloud, Microsoft Azure, GitLab, Bitbucket, Kubernetes and Cloudflare, so that Bellu can verify access to them.

#### Acceptance Criteria

1. THE Catalog SHALL contain a manifest for each of Google Cloud, Microsoft Azure, GitLab, Bitbucket, Kubernetes and Cloudflare.
2. THE Provider of each new Source SHALL implement Verify, CheckPermissions, Refresh and Describe.
3. THE Provider of each new Source SHALL expose a nil Collector.
4. WHEN the Catalog contains the manifest of a Source, THE App SHALL no longer list that Source in `planned.ts`.
5. WHILE the Connectors_Flag is disabled, THE App SHALL hide the six new Sources.

### Requirement 2: Sign-in and pasted credentials

**User Story:** As a user, I want to sign in where the provider supports it, so that I avoid handling secrets.

#### Acceptance Criteria

1. WHERE a provider offers a usable device or OAuth flow and a public client ID is available, THE Provider SHALL offer Sign-in for GitLab, Bitbucket, Google Cloud and Microsoft Azure.
2. IF a provider has no usable device flow or no public client ID, THEN THE Wizard SHALL offer Pasted_Credential and state that sign-in is unavailable for that provider.
3. THE Provider SHALL accept a Pasted_Credential for Cloudflare and Kubernetes.
4. WHEN a user completes Sign-in, THE Bellud SHALL store the resulting credential in the Vault.
5. WHEN a user submits a Pasted_Credential, THE Bellud SHALL store the credential in the Vault.
6. WHEN a Source is connected, THE Broker SHALL authenticate provider calls using the auth kind the provider requires, including non-bearer schemes.

### Requirement 3: Read-only and secret-safe connections

**User Story:** As a user, I want a connection to be read-only and secret-safe, so that connecting a Source cannot change my systems or leak credentials.

#### Acceptance Criteria

1. THE Broker SHALL reject any provider request that is not read-only.
2. THE Bellud SHALL keep credentials only in the Vault.
3. THE App SHALL receive no credential value from Bellud after submission.
4. THE Bellud SHALL write no credential value to logs.
5. IF Verify or CheckPermissions finds write-capable permissions, THEN THE Provider SHALL report the excess permissions to the user.

### Requirement 4: Shared Wizard

**User Story:** As a user, I want the same simple wizard for every Source, so that connecting is quick and familiar.

#### Acceptance Criteria

1. THE App SHALL provide one shared Wizard component.
2. THE App SHALL render the AWS, GitHub and six new Source wizards using the shared Wizard component.
3. THE Wizard SHALL present a stepper with the steps: choose method, create access, paste result, choose scope, Connected.
4. WHEN a user selects Sign-in, THE Wizard SHALL show a copyable device code and a link to the provider.
5. THE Wizard SHALL show one short instruction and one docs link per step.
6. WHEN verification succeeds, THE Wizard SHALL show the Connected screen with the Describe result.
7. IF verification fails, THEN THE Wizard SHALL show the failure reason and keep the user on the current step.
8. THE App SHALL display the name "Sources" wherever it refers to connectors in user-facing text.

### Requirement 5: AWS and GitHub migration

**User Story:** As a user, I want the AWS and GitHub flows to keep working after migration, so that existing connections are unaffected.

#### Acceptance Criteria

1. WHEN AWS and GitHub migrate to the shared Wizard, THE App SHALL keep every existing step and outcome of both flows.
2. WHEN the client protocol changes, THE build SHALL regenerate the client in `packages/client`.

### Requirement 6: Source logos

**User Story:** As a user, I want a recognizable logo for each Source, so that I can identify it.

#### Acceptance Criteria

1. THE `packages/ui` package SHALL provide a brand logo for each of the six new Sources.
2. WHEN the App lists or shows a Source, THE App SHALL display the logo of that Source.
