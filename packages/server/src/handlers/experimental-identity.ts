import { NotFoundError } from "@bellucode/protocol/errors"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import { Api } from "../api"
// The Go server owns /api/experimental/identity/*; the gateway routes those requests to it before they
// reach this server. HttpApiBuilder requires a handler for every endpoint, so this stub exists for
// typing only and is not reached in production.
const notServed = () => Effect.fail(new NotFoundError({ message: "Identity routes are served by the Go server" }))
export const ExperimentalIdentityHandler = HttpApiBuilder.group(Api, "server.identity", (handlers) =>
  handlers.handle("paths", notServed),
)
