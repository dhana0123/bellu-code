import { Data } from "@bellucode/schema/data"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, UnknownError] as const
const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.data.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.data`: routes under /api/experimental/data, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalDataGroup = HttpApiGroup.make("server.data")
  .add(
    HttpApiEndpoint.get("stores", "/api/experimental/data/stores", {
      query: {
        limit: Schema.optional(Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 500 }))))).annotate({ description: "Maximum number of items to return (1-500, default 50)." }),
        cursor: Schema.optional(Schema.String).annotate({ description: "Opaque cursor from a previous page." }),
      },
      success: Data.StorePage,
      error: errors,
    }).annotateMerge(
      experimental(
        "stores",
        "List data stores",
        "List data stores (buckets, database instances and clusters, tables) with protection settings, data classes and open exposure counts.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.get("store", "/api/experimental/data/stores/:id", {
      params: { id: Data.ID },
      success: Data.Store,
      error: errors,
    }).annotateMerge(experimental("store", "Get data store", "Get one data store. Answers 404 when the id is not a data store.")),
  )
