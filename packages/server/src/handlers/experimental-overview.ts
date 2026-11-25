import { ServiceUnavailableError } from "@bellucode/protocol/errors"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import { Api } from "../api"

// The Go server owns /api/experimental/overview/*; the gateway routes those requests to it before they
// reach this server. HttpApiBuilder requires a handler for every endpoint, so this stub exists for
// typing only and is not reached in production.
const notServed = () =>
  Effect.fail(new ServiceUnavailableError({ message: "Overview routes are served by the Go server", service: "overview" }))

export const ExperimentalOverviewHandler = HttpApiBuilder.group(Api, "server.overview", (handlers) =>
  handlers.handle("categories", notServed),
)
