import { Connectors } from "@bellucode/schema/connectors"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import {
  ConflictError,
  ConnectorError,
  ConnectorForbiddenError,
  ConnectorPayloadTooLargeError,
  NotFoundError,
  ServiceUnavailableError,
} from "../errors.js"

/**
 * Error statuses of every connector route: 400 (typed, credential-free ConnectorError), 403 (refused
 * credential write), 404 (flag off or unknown resource), 409 (collection already running), 413
 * (body over 1 MiB) and 503.
 */
const errors = [
  ConnectorError,
  ConnectorForbiddenError,
  ConnectorPayloadTooLargeError,
  NotFoundError,
  ConflictError,
  ServiceUnavailableError,
] as const

const ConnectionParams = { id: Connectors.ConnectionID }

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.connectors.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.connectors`: routes under /api/experimental/connectors, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 * Plugin, device-flow and MCP routes are not declared here.
 */
export const ExperimentalConnectorsGroup = HttpApiGroup.make("server.connectors")
  .add(
    HttpApiEndpoint.get("status", "/api/experimental/connectors/status", {
      success: Connectors.ServiceStatus,
      error: errors,
    }).annotateMerge(experimental("status", "Get connectors status", "Report the connectors flag, key source and warnings.")),
  )
  .add(
    HttpApiEndpoint.get("catalog", "/api/experimental/connectors/catalog", {
      success: Connectors.Catalog,
      error: errors,
    }).annotateMerge(experimental("catalog", "List connector catalog", "List connector manifests.")),
  )
  .add(
    HttpApiEndpoint.get("listConnections", "/api/experimental/connectors/connections", {
      success: Connectors.ConnectionList,
      error: errors,
    }).annotateMerge(experimental("listConnections", "List connections", "List connections as masked metadata.")),
  )
  .add(
    HttpApiEndpoint.post("createConnection", "/api/experimental/connectors/connections", {
      payload: Connectors.CreateConnectionInput,
      success: Connectors.Connection,
      error: errors,
    }).annotateMerge(experimental("createConnection", "Create connection", "Connect an account with a credential.")),
  )
  .add(
    HttpApiEndpoint.get("getConnection", "/api/experimental/connectors/connections/:id", {
      params: ConnectionParams,
      success: Connectors.Connection,
      error: errors,
    }).annotateMerge(experimental("getConnection", "Get connection", "Get one connection as masked metadata.")),
  )
  .add(
    HttpApiEndpoint.patch("updateConnection", "/api/experimental/connectors/connections/:id", {
      params: ConnectionParams,
      payload: Connectors.UpdateConnectionInput,
      success: Connectors.Connection,
      error: errors,
    }).annotateMerge(experimental("updateConnection", "Update connection", "Change alias, interval, live reads, selection or rotation interval.")),
  )
  .add(
    HttpApiEndpoint.delete("deleteConnection", "/api/experimental/connectors/connections/:id", {
      params: ConnectionParams,
      success: Connectors.VaultResult,
      error: errors,
    }).annotateMerge(experimental("deleteConnection", "Delete connection", "Disconnect and remove the stored credential.")),
  )
  .add(
    HttpApiEndpoint.post("testConnection", "/api/experimental/connectors/connections/:id/test", {
      params: ConnectionParams,
      success: Connectors.TestResult,
      error: errors,
    }).annotateMerge(experimental("testConnection", "Test connection", "Check identity and permissions.")),
  )
  .add(
    HttpApiEndpoint.post("syncConnection", "/api/experimental/connectors/connections/:id/sync", {
      params: ConnectionParams,
      success: Connectors.SyncResult,
      error: errors,
    }).annotateMerge(experimental("syncConnection", "Sync connection", "Start a manual collection run. Fails with 409 while one is running.")),
  )
  .add(
    HttpApiEndpoint.post("pauseConnection", "/api/experimental/connectors/connections/:id/pause", {
      params: ConnectionParams,
      success: Connectors.Connection,
      error: errors,
    }).annotateMerge(experimental("pauseConnection", "Pause connection", "Pause scheduled collection.")),
  )
  .add(
    HttpApiEndpoint.post("resumeConnection", "/api/experimental/connectors/connections/:id/resume", {
      params: ConnectionParams,
      success: Connectors.Connection,
      error: errors,
    }).annotateMerge(experimental("resumeConnection", "Resume connection", "Resume scheduled collection.")),
  )
  .add(
    HttpApiEndpoint.post("reconnectConnection", "/api/experimental/connectors/connections/:id/reconnect", {
      params: ConnectionParams,
      payload: Connectors.ReplaceCredentialInput,
      success: Connectors.Connection,
      error: errors,
    }).annotateMerge(experimental("reconnectConnection", "Reconnect connection", "Supply a new credential and verify it.")),
  )
  .add(
    HttpApiEndpoint.post("rotateCredential", "/api/experimental/connectors/connections/:id/rotate", {
      params: ConnectionParams,
      payload: Connectors.ReplaceCredentialInput,
      success: Connectors.Connection,
      error: errors,
    }).annotateMerge(experimental("rotateCredential", "Rotate credential", "Verify a candidate credential, then replace the stored one.")),
  )
  .add(
    HttpApiEndpoint.get("listAudit", "/api/experimental/connectors/connections/:id/audit", {
      params: ConnectionParams,
      query: { cursor: Schema.optional(Schema.String).annotate({ description: "Cursor from the previous page." }) },
      success: Connectors.AuditPage,
      error: errors,
    }).annotateMerge(experimental("listAudit", "List audit entries", "List audit entries, newest first, 50 per page.")),
  )
  .add(
    HttpApiEndpoint.get("listAuthConfigs", "/api/experimental/connectors/connectors/:cid/auth-configs", {
      params: { cid: Connectors.ConnectorID },
      success: Connectors.AuthConfigList,
      error: errors,
    }).annotateMerge(experimental("listAuthConfigs", "List auth configs", "List auth configurations of a connector.")),
  )
  .add(
    HttpApiEndpoint.post("createAuthConfig", "/api/experimental/connectors/connectors/:cid/auth-configs", {
      params: { cid: Connectors.ConnectorID },
      payload: Connectors.CreateAuthConfigInput,
      success: Connectors.AuthConfig,
      error: errors,
    }).annotateMerge(experimental("createAuthConfig", "Create auth config", "Create an auth configuration for a connector.")),
  )
  .add(
    HttpApiEndpoint.delete("deleteAuthConfig", "/api/experimental/connectors/auth-configs/:id", {
      params: { id: Connectors.AuthConfigID },
      success: Connectors.VaultResult,
      error: errors,
    }).annotateMerge(experimental("deleteAuthConfig", "Delete auth config", "Delete an auth configuration that no connection uses.")),
  )
  .add(
    HttpApiEndpoint.post("awsSetup", "/api/experimental/connectors/aws/setup", {
      payload: Connectors.AwsSetupInput,
      success: Connectors.AwsSetup,
      error: errors,
    }).annotateMerge(experimental("awsSetup", "Prepare AWS setup", "Generate an external id, CloudFormation and Terraform templates.")),
  )
  .add(
    HttpApiEndpoint.get("listGithubRepos", "/api/experimental/connectors/connections/:id/github/repos", {
      params: ConnectionParams,
      success: Connectors.GithubRepoList,
      error: errors,
    }).annotateMerge(experimental("listGithubRepos", "List GitHub repositories", "List repositories the connection can access.")),
  )
  .add(
    HttpApiEndpoint.post("startDeviceAuthorization", "/api/experimental/connectors/device-authorizations", {
      payload: Connectors.StartDeviceAuthorizationInput,
      success: Connectors.DeviceAuthorization,
      error: errors,
    }).annotateMerge(experimental("startDeviceAuthorization", "Start device authorization", "Start a device-flow sign-in. The response never contains the device code.")),
  )
  .add(
    HttpApiEndpoint.get("getDeviceAuthorization", "/api/experimental/connectors/device-authorizations/:id", {
      params: { id: Schema.String },
      success: Connectors.DeviceAuthorizationStatus,
      error: errors,
    }).annotateMerge(experimental("getDeviceAuthorization", "Get device authorization", "Get the status of a device authorization.")),
  )
  .add(
    HttpApiEndpoint.delete("cancelDeviceAuthorization", "/api/experimental/connectors/device-authorizations/:id", {
      params: { id: Schema.String },
      success: Connectors.VaultResult,
      error: errors,
    }).annotateMerge(experimental("cancelDeviceAuthorization", "Cancel device authorization", "Cancel a pending device authorization.")),
  )
  .add(
    HttpApiEndpoint.get("getScope", "/api/experimental/connectors/scopes/:principal", {
      params: { principal: Schema.String },
      success: Connectors.Scope,
      error: errors,
    }).annotateMerge(experimental("getScope", "Get session scope", "Get the connector scope of a principal.")),
  )
  .add(
    HttpApiEndpoint.put("putScope", "/api/experimental/connectors/scopes/:principal", {
      params: { principal: Schema.String },
      payload: Connectors.ScopeInput,
      success: Connectors.Scope,
      error: errors,
    }).annotateMerge(experimental("putScope", "Set session scope", "Replace the connector scope of a principal.")),
  )
  .add(
    HttpApiEndpoint.post("unlockVault", "/api/experimental/connectors/vault/unlock", {
      payload: Connectors.UnlockVaultInput,
      success: Connectors.VaultResult,
      error: errors,
    }).annotateMerge(experimental("unlockVault", "Unlock vault", "Unlock the credential vault with a passphrase.")),
  )
  .add(
    HttpApiEndpoint.post("rotateMasterKey", "/api/experimental/connectors/vault/rotate", {
      success: Connectors.VaultResult,
      error: errors,
    }).annotateMerge(experimental("rotateMasterKey", "Rotate master key", "Re-wrap all credentials under a new master key.")),
  )
  .add(
    HttpApiEndpoint.post("forgetAll", "/api/experimental/connectors/vault/forget", {
      success: Connectors.VaultResult,
      error: errors,
    }).annotateMerge(experimental("forgetAll", "Forget all connectors", "Delete every connection and stored credential.")),
  )
