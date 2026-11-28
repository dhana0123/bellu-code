import { Identity } from "@bellucode/schema/identity"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError, NotFoundError, QueryBudgetExceededError } from "../errors.js"
const errors = [NotFoundError, InvalidRequestError, QueryBudgetExceededError] as const
const positive = Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1))))
/**
 * `server.identity`: routes under /api/experimental/identity, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalIdentityGroup = HttpApiGroup.make("server.identity").add(
  HttpApiEndpoint.get("paths", "/api/experimental/identity/paths", {
    query: {
      from: Schema.String.annotate({ description: "Source identity identifier." }),
      to: Schema.String.annotate({ description: "Target identity or resource identifier." }),
      max_hops: Schema.optional(positive).annotate({ description: "Maximum path length in hops (positive integer, at most 10)." }),
    },
    success: Identity.Paths,
    error: errors,
  }).annotateMerge(
    OpenApi.annotations({
      identifier: "experimental.identity.paths",
      summary: "Find identity paths",
      description:
        "Find paths between two identities within a hop and time limit. A slow search returns an error, never a partial set. Experimental: may change without compatibility guarantees.",
      transform: (operation) => ({ ...operation, tags: ["experimental"] }),
    }),
  ),
)
