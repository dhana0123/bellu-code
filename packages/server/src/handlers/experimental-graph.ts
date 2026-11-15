import { ServiceUnavailableError } from "@bellucode/protocol/errors"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import { Api } from "../api"

// The Go server owns /api/experimental/graph/*; the gateway routes those requests to it before they
// reach this server. HttpApiBuilder requires a handler for every endpoint, so these stubs exist for
// typing only and are not reached in production.
const notServed = () =>
  Effect.fail(new ServiceUnavailableError({ message: "Graph routes are served by the Go server", service: "graph" }))

export const ExperimentalGraphHandler = HttpApiBuilder.group(Api, "server.graph", (handlers) =>
  handlers
    .handle("find", notServed)
    .handle("entity", notServed)
    .handle("neighbors", notServed)
    .handle("history", notServed)
    .handle("changes", notServed)
    .handle("diff", notServed)
    .handle("schema", notServed)
    .handle("status", notServed)
    .handle("slice", notServed)
    .handle("overlay", notServed)
    .handle("lenses", notServed)
    .handle("intelStatus", notServed),
)
