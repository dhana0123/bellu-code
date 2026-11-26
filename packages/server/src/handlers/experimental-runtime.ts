import { NotFoundError } from "@bellucode/protocol/errors"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import { Api } from "../api"

// The Go server owns /api/experimental/runtime/*; the gateway routes those requests to it before they
// reach this server. HttpApiBuilder requires a handler for every endpoint, so these stubs exist for
// typing only and are not reached in production.
const notServed = () => Effect.fail(new NotFoundError({ message: "Runtime routes are served by the Go server" }))

export const ExperimentalRuntimeHandler = HttpApiBuilder.group(Api, "server.runtime", (handlers) =>
  handlers.handle("status", notServed).handle("events", notServed).handle("ingest", notServed),
)
