import { Runtime } from "@bellucode/schema/runtime"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/http-api"
import { ForbiddenError, InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, UnknownError] as const
const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.runtime.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.runtime`: routes under /api/experimental/runtime, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalRuntimeGroup = HttpApiGroup.make("server.runtime")
  .add(
    HttpApiEndpoint.get("status", "/api/experimental/runtime/status", {
      success: Runtime.Status,
      error: errors,
    }).annotateMerge(
      experimental("status", "Get runtime sensor status", "List runtime sensors with their health and drop counters. Answers 404 when runtime security is not enabled."),
    ),
  )
  .add(
    HttpApiEndpoint.get("events", "/api/experimental/runtime/events", {
      query: {
        type: Schema.optional(Runtime.EventType).annotate({ description: "Only return events of this type." }),
        limit: Schema.optional(
          Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 500 })))),
        ).annotate({ description: "Maximum number of items to return (1-500, default 50)." }),
        cursor: Schema.optional(Schema.String).annotate({ description: "Opaque cursor from a previous page." }),
      },
      success: Runtime.EventPage,
      error: errors,
    }).annotateMerge(
      experimental("events", "List runtime events", "List runtime events, newest first, optionally filtered by type, with cursor pagination."),
    ),
  )
  .add(
    HttpApiEndpoint.post("ingest", "/api/experimental/runtime/ingest", {
      payload: Runtime.Event,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, ...errors],
    }).annotateMerge(
      experimental("ingest", "Ingest runtime event", "Store one runtime event from a sensor. Answers 204 on success and 403 unless the request carries a verified mTLS client certificate."),
    ),
  )
