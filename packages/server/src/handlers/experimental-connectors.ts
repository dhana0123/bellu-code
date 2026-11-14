import { ServiceUnavailableError } from "@bellucode/protocol/errors"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import { Api } from "../api"

// The Go server owns /api/experimental/connectors/*; the gateway routes those requests to it before they
// reach this server. HttpApiBuilder requires a handler for every endpoint, so these stubs exist for
// typing only and are not reached in production.
const notServed = () =>
  Effect.fail(
    new ServiceUnavailableError({ message: "Connector routes are served by the Go server", service: "connectors" }),
  )

export const ExperimentalConnectorsHandler = HttpApiBuilder.group(Api, "server.connectors", (handlers) =>
  handlers
    .handle("status", notServed)
    .handle("catalog", notServed)
    .handle("listConnections", notServed)
    .handle("createConnection", notServed)
    .handle("getConnection", notServed)
    .handle("updateConnection", notServed)
    .handle("deleteConnection", notServed)
    .handle("testConnection", notServed)
    .handle("syncConnection", notServed)
    .handle("pauseConnection", notServed)
    .handle("resumeConnection", notServed)
    .handle("reconnectConnection", notServed)
    .handle("rotateCredential", notServed)
    .handle("listAudit", notServed)
    .handle("listAuthConfigs", notServed)
    .handle("createAuthConfig", notServed)
    .handle("deleteAuthConfig", notServed)
    .handle("awsSetup", notServed)
    .handle("listGithubRepos", notServed)
    .handle("listScopeOptions", notServed)
    .handle("startDeviceAuthorization", notServed)
    .handle("getDeviceAuthorization", notServed)
    .handle("cancelDeviceAuthorization", notServed)
    .handle("getScope", notServed)
    .handle("putScope", notServed)
    .handle("unlockVault", notServed)
    .handle("rotateMasterKey", notServed)
    .handle("forgetAll", notServed),
)
