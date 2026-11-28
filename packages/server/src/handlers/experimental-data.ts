import { UnknownError } from "@bellucode/protocol/errors"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import { Api } from "../api"

// The Go server owns /api/experimental/data/*; the gateway routes those requests to it before they
// reach this server. HttpApiBuilder requires a handler for every endpoint, so these stubs exist for
// typing only and are not reached in production.
const notServed = () => Effect.fail(new UnknownError({ message: "Data routes are served by the Go server" }))

export const ExperimentalDataHandler = HttpApiBuilder.group(Api, "server.data", (handlers) =>
  handlers.handle("stores", notServed).handle("store", notServed),
)
