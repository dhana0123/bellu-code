export * as Connectors from "./connectors.js"

import { Schema } from "effect"
import { optional } from "./schema.js"

// Field names mirror the Go JSON tags in services/bellud/internal/connectors:
// `store` (connection state, camelCase), `manifest` (catalog, snake_case),
// `lifecycle` (typed error codes) and `audit` (audit entries).
// No schema here carries a credential, wrapped key or Master_Key in a response (Req 15).

const Text = Schema.String.check(Schema.isNonEmpty())
const Timestamp = Schema.String.check(Schema.isNonEmpty())

export const ConnectionID = Text.annotate({ identifier: "Connectors.ConnectionID" })
export type ConnectionID = typeof ConnectionID.Type

export const AuthConfigID = Text.annotate({ identifier: "Connectors.AuthConfigID" })
export type AuthConfigID = typeof AuthConfigID.Type

export const ConnectorID = Text.annotate({ identifier: "Connectors.ConnectorID" })
export type ConnectorID = typeof ConnectorID.Type

// lifecycle.Status. "Removed" is a tombstone flag, not a status.
export const Status = Schema.Literals(["INITIATED", "VERIFYING", "ACTIVE", "EXPIRED", "PAUSED", "ERROR"]).annotate({
  identifier: "Connectors.Status",
})
export type Status = typeof Status.Type

// lifecycle.Code: every typed error code.
export const ErrorCode = Schema.Literals([
  "invalid_credential",
  "insufficient_permission",
  "excess_permission",
  "network",
  "rate_limited",
  "expired",
  "alias_invalid",
  "alias_taken",
  "blocked_by_policy",
  "scope_denied",
  "run_in_progress",
  "vault_unavailable",
  "audit_failed",
  "decrypt_failed",
  "transition_rejected",
  "validation_failed",
  "payload_too_large",
  "forbidden",
  "device_code_expired",
  "authorization_denied",
  "device_flow_disabled",
  "already_pending",
]).annotate({ identifier: "Connectors.ErrorCode" })
export type ErrorCode = typeof ErrorCode.Type

// store.PermissionOK / PermissionExcess / PermissionUnverifiable.
export const PermissionCheck = Schema.Literals(["ok", "excess", "unverifiable"]).annotate({
  identifier: "Connectors.PermissionCheck",
})
export type PermissionCheck = typeof PermissionCheck.Type

export const Selection = Schema.Struct({
  regions: Schema.Array(Schema.String),
  repos: Schema.Array(Schema.String),
}).annotate({ identifier: "Connectors.Selection" })
export interface Selection extends Schema.Schema.Type<typeof Selection> {}

export const LastSync = Schema.Struct({
  status: Schema.String,
  endedAt: optional(Timestamp),
  entities: Schema.Int,
  partial: Schema.Array(Schema.String),
}).annotate({ identifier: "Connectors.LastSync" })
export interface LastSync extends Schema.Schema.Type<typeof LastSync> {}

/** Masked connection metadata (store.Connection). Never contains a credential. */
export const Connection = Schema.Struct({
  id: ConnectionID,
  connectorId: ConnectorID,
  alias: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(40)),
  authConfigId: Schema.String,
  method: Schema.String,
  status: Status,
  statusReason: Schema.String,
  accountLabel: Schema.String,
  externalIdRef: optional(Schema.String),
  selection: Selection,
  intervalSec: Schema.Int,
  allowAgentLiveReads: Schema.Boolean,
  rotationIntervalDays: Schema.Int,
  credentialCreatedAt: Schema.NullOr(Timestamp),
  credentialExpiresAt: Schema.NullOr(Timestamp),
  lastPermissionCheck: Schema.NullOr(Timestamp),
  permissionCheck: Schema.String,
  lastSync: optional(LastSync),
  removed: Schema.Boolean,
  createdAt: Timestamp,
}).annotate({ identifier: "Connectors.Connection" })
export interface Connection extends Schema.Schema.Type<typeof Connection> {}

export const ConnectionList = Schema.Struct({
  items: Schema.Array(Connection),
}).annotate({ identifier: "Connectors.ConnectionList" })
export interface ConnectionList extends Schema.Schema.Type<typeof ConnectionList> {}

/** store.AuthConfig. App secrets live in the vault and are never returned. */
export const AuthConfig = Schema.Struct({
  id: AuthConfigID,
  connectorId: ConnectorID,
  name: Schema.String,
  builtin: Schema.Boolean,
  method: Schema.String,
  scopes: Schema.Array(Schema.String),
  settings: Schema.Record(Schema.String, Schema.String),
}).annotate({ identifier: "Connectors.AuthConfig" })
export interface AuthConfig extends Schema.Schema.Type<typeof AuthConfig> {}

export const AuthConfigList = Schema.Struct({
  items: Schema.Array(AuthConfig),
}).annotate({ identifier: "Connectors.AuthConfigList" })
export interface AuthConfigList extends Schema.Schema.Type<typeof AuthConfigList> {}

// manifest.AuthMethod / Permission / Operation (snake_case JSON).
export const ManifestDeviceSpec = Schema.Struct({
  device_code_url: Schema.String,
  token_url: Schema.String,
  client_id: Schema.String,
  scopes: Schema.Array(Schema.String),
}).annotate({ identifier: "Connectors.ManifestDeviceSpec" })
export interface ManifestDeviceSpec extends Schema.Schema.Type<typeof ManifestDeviceSpec> {}
export const ManifestAuthMethod = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  enabled: Schema.Boolean,
  disabled_reason: optional(Schema.String),
  device: optional(ManifestDeviceSpec),
}).annotate({ identifier: "Connectors.ManifestAuthMethod" })
export interface ManifestAuthMethod extends Schema.Schema.Type<typeof ManifestAuthMethod> {}

export const ManifestPermission = Schema.Struct({
  name: Schema.String,
  description: optional(Schema.String),
  read_only: Schema.Boolean,
}).annotate({ identifier: "Connectors.ManifestPermission" })
export interface ManifestPermission extends Schema.Schema.Type<typeof ManifestPermission> {}

export const ManifestOperation = Schema.Struct({
  name: Schema.String,
  class: Schema.Literals(["read", "auth"]),
  method: optional(Schema.String),
  host: Schema.String,
  path: optional(Schema.String),
  query: optional(Schema.Boolean),
  strip_keys: optional(Schema.Array(Schema.String)),
  max_bytes: optional(Schema.Int),
  issues_credential: optional(Schema.Boolean),
}).annotate({ identifier: "Connectors.ManifestOperation" })
export interface ManifestOperation extends Schema.Schema.Type<typeof ManifestOperation> {}

export const Manifest = Schema.Struct({
  id: ConnectorID,
  version: Schema.String,
  name: Schema.String,
  icon: Schema.String,
  auth_methods: Schema.Array(ManifestAuthMethod),
  permissions: Schema.Array(ManifestPermission),
  operations: Schema.Array(ManifestOperation),
  egress: Schema.Array(Schema.String),
  entities: Schema.Array(Schema.String),
}).annotate({ identifier: "Connectors.Manifest" })
export interface Manifest extends Schema.Schema.Type<typeof Manifest> {}

export const Catalog = Schema.Struct({
  items: Schema.Array(Manifest),
}).annotate({ identifier: "Connectors.Catalog" })
export interface Catalog extends Schema.Schema.Type<typeof Catalog> {}

/** Flag/offline probe: key source name, persistence and warnings. */
export const ServiceStatus = Schema.Struct({
  enabled: Schema.Boolean,
  offline: Schema.Boolean,
  keySource: Schema.String,
  persistent: Schema.Boolean,
  locked: Schema.Boolean,
  warnings: Schema.Array(Schema.String),
}).annotate({ identifier: "Connectors.ServiceStatus" })
export interface ServiceStatus extends Schema.Schema.Type<typeof ServiceStatus> {}

/**
 * Write-only credential material. Field names depend on the auth method, for example
 * `access_key_id` and `secret_access_key` or `token`. It is accepted on input and never returned.
 */
export const CredentialInput = Schema.Record(Schema.String, Schema.String).annotate({
  identifier: "Connectors.CredentialInput",
  description: "Write-only credential fields for the chosen auth method. Never returned by any route.",
})
export type CredentialInput = typeof CredentialInput.Type

const Alias = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(40)).annotate({
  description: "Connection alias, 1 to 40 characters, unique per connector.",
})
const IntervalSec = Schema.Int.check(Schema.isBetween({ minimum: 60, maximum: 86400 })).annotate({
  description: "Collection interval in seconds: a whole number of minutes from 1 minute to 24 hours.",
})
const RotationDays = Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 365 })).annotate({
  description: "Credential rotation interval in days (1-365).",
})

export const CreateConnectionInput = Schema.Struct({
  alias: Alias,
  connectorId: ConnectorID,
  authConfigId: optional(Schema.String),
  method: Text,
  params: optional(Schema.Record(Schema.String, Schema.String)),
  credential: CredentialInput,
  intervalSec: optional(IntervalSec),
}).annotate({ identifier: "Connectors.CreateConnectionInput" })
export interface CreateConnectionInput extends Schema.Schema.Type<typeof CreateConnectionInput> {}

export const UpdateConnectionInput = Schema.Struct({
  alias: optional(Alias),
  intervalSec: optional(IntervalSec),
  allowAgentLiveReads: optional(Schema.Boolean),
  selection: optional(Selection),
  rotationIntervalDays: optional(RotationDays),
}).annotate({ identifier: "Connectors.UpdateConnectionInput" })
export interface UpdateConnectionInput extends Schema.Schema.Type<typeof UpdateConnectionInput> {}

/** New credential for reconnect or rotate. */
export const ReplaceCredentialInput = Schema.Struct({
  credential: CredentialInput,
}).annotate({ identifier: "Connectors.ReplaceCredentialInput" })
export interface ReplaceCredentialInput extends Schema.Schema.Type<typeof ReplaceCredentialInput> {}

/** Result of a test or verification: identity plus the permission check. */
export const TestResult = Schema.Struct({
  ok: Schema.Boolean,
  accountLabel: Schema.String,
  permissionCheck: PermissionCheck,
  offenders: Schema.Array(Schema.String),
  warnings: Schema.Array(Schema.String),
}).annotate({ identifier: "Connectors.TestResult" })
export interface TestResult extends Schema.Schema.Type<typeof TestResult> {}

export const SyncResult = Schema.Struct({
  started: Schema.Boolean,
  connection: Connection,
}).annotate({ identifier: "Connectors.SyncResult" })
export interface SyncResult extends Schema.Schema.Type<typeof SyncResult> {}

// audit.Entry. `detail` holds non-secret strings only.
export const AuditEntry = Schema.Struct({
  seq: Schema.Int,
  ts: Timestamp,
  connectionId: Schema.String,
  connectorId: Schema.String,
  event: Schema.String,
  outcome: Schema.Literals(["success", "failure", "blocked"]),
  actor: Schema.String,
  detail: optional(Schema.Record(Schema.String, Schema.String)),
  prev: Schema.String,
}).annotate({ identifier: "Connectors.AuditEntry" })
export interface AuditEntry extends Schema.Schema.Type<typeof AuditEntry> {}

export const AuditPage = Schema.Struct({
  items: Schema.Array(AuditEntry),
  nextCursor: optional(Schema.String),
}).annotate({ identifier: "Connectors.AuditPage" })
export interface AuditPage extends Schema.Schema.Type<typeof AuditPage> {}

export const CreateAuthConfigInput = Schema.Struct({
  name: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(80)),
  method: Text,
  scopes: optional(Schema.Array(Schema.String)),
  settings: optional(Schema.Record(Schema.String, Schema.String)),
  secrets: optional(CredentialInput),
}).annotate({ identifier: "Connectors.CreateAuthConfigInput" })
export interface CreateAuthConfigInput extends Schema.Schema.Type<typeof CreateAuthConfigInput> {}

export const AwsSetupInput = Schema.Struct({
  alias: optional(Alias),
}).annotate({ identifier: "Connectors.AwsSetupInput" })
export interface AwsSetupInput extends Schema.Schema.Type<typeof AwsSetupInput> {}

/** External id, IaC templates and the detected principal for the AWS assume-role setup. */
export const AwsSetup = Schema.Struct({
  externalId: Schema.String,
  cloudFormation: Schema.String,
  terraform: Schema.String,
  principal: optional(Schema.String),
  quickCreateUrl: optional(Schema.String),
}).annotate({ identifier: "Connectors.AwsSetup" })
export interface AwsSetup extends Schema.Schema.Type<typeof AwsSetup> {}

export const GithubRepo = Schema.Struct({
  fullName: Schema.String,
  private: Schema.Boolean,
}).annotate({ identifier: "Connectors.GithubRepo" })
export interface GithubRepo extends Schema.Schema.Type<typeof GithubRepo> {}

export const GithubRepoList = Schema.Struct({
  items: Schema.Array(GithubRepo),
  installations: Schema.Int.annotate({ description: "Number of GitHub App installations reachable by the token." }),
  installUrl: optional(Schema.String),
}).annotate({ identifier: "Connectors.GithubRepoList" })
export interface GithubRepoList extends Schema.Schema.Type<typeof GithubRepoList> {}

/** Start of a device authorization. `alias` is required unless `reconnectId` is set. */
export const StartDeviceAuthorizationInput = Schema.Struct({
  connectorId: ConnectorID,
  alias: optional(Alias),
  reconnectId: optional(ConnectionID),
}).annotate({ identifier: "Connectors.StartDeviceAuthorizationInput" })
export interface StartDeviceAuthorizationInput extends Schema.Schema.Type<typeof StartDeviceAuthorizationInput> {}
/** Never carries the device code; the server keeps it. */
export const DeviceAuthorization = Schema.Struct({
  id: Schema.String,
  userCode: Schema.String,
  verificationUri: Schema.String,
  expiresAt: Schema.Int,
  intervalSec: Schema.Int,
}).annotate({ identifier: "Connectors.DeviceAuthorization" })
export interface DeviceAuthorization extends Schema.Schema.Type<typeof DeviceAuthorization> {}
export const DeviceAuthorizationStatusValue = Schema.Literals(["pending", "connected", "expired", "denied", "failed"]).annotate({
  identifier: "Connectors.DeviceAuthorizationStatusValue",
})
export type DeviceAuthorizationStatusValue = typeof DeviceAuthorizationStatusValue.Type
export const DeviceAuthorizationStatus = Schema.Struct({
  status: DeviceAuthorizationStatusValue,
  expiresAt: optional(Schema.Int),
  intervalSec: optional(Schema.Int),
  connection: optional(Connection),
  error: optional(
    Schema.Struct({
      code: ErrorCode,
      retryAfterSec: optional(Schema.Int),
    }),
  ),
}).annotate({ identifier: "Connectors.DeviceAuthorizationStatus" })
export interface DeviceAuthorizationStatus extends Schema.Schema.Type<typeof DeviceAuthorizationStatus> {}
// store.Scope: agent/principal scope entry (Requirement 17).
export const Scope = Schema.Struct({
  principal: Text,
  connectors: Schema.Array(Schema.String),
  connections: Schema.Array(Schema.String),
  operations: Schema.Record(Schema.String, Schema.Array(Schema.String)),
}).annotate({ identifier: "Connectors.Scope" })
export interface Scope extends Schema.Schema.Type<typeof Scope> {}
// PUT body for a scope; the principal comes from the path so it is not repeated here.
export const ScopeInput = Schema.Struct({
  connectors: Scope.fields.connectors,
  connections: Scope.fields.connections,
  operations: Scope.fields.operations,
}).annotate({ identifier: "Connectors.ScopeInput" })
export interface ScopeInput extends Schema.Schema.Type<typeof ScopeInput> {}

export const UnlockVaultInput = Schema.Struct({
  passphrase: Schema.String.check(Schema.isNonEmpty()),
}).annotate({ identifier: "Connectors.UnlockVaultInput" })
export interface UnlockVaultInput extends Schema.Schema.Type<typeof UnlockVaultInput> {}

export const VaultResult = Schema.Struct({
  ok: Schema.Boolean,
}).annotate({ identifier: "Connectors.VaultResult" })
export interface VaultResult extends Schema.Schema.Type<typeof VaultResult> {}
