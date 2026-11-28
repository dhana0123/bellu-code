import { Ai } from "@bellucode/schema/ai"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError, UnknownError, NotFoundError } from "../errors.js"
const errors = [InvalidRequestError, NotFoundError, UnknownError] as const
const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.ai.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })
/**
 * `server.ai`: routes under /api/experimental/ai, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalAiGroup = HttpApiGroup.make("server.ai")
  .add(
    HttpApiEndpoint.get("entities", "/api/experimental/ai/entities", {
      query: {
        kind: Schema.optional(Schema.String).annotate({ description: "Only return entities of this AI kind." }),
        limit: Schema.optional(
          Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 500 })))),
        ).annotate({ description: "Maximum number of items to return (1-500, default 50)." }),
        cursor: Schema.optional(Schema.String).annotate({ description: "Opaque cursor from a previous page." }),
      },
      success: Ai.Page,
      error: errors,
    }).annotateMerge(
      experimental("entities", "List AI entities", "List AI inventory entities (models, agents, tools, MCP servers, vector stores, services) with cursor pagination."),
    ),
  )
  .add(
    HttpApiEndpoint.get("summary", "/api/experimental/ai/summary", {
      success: Ai.Summary,
      error: errors,
    }).annotateMerge(experimental("summary", "Summarize AI inventory", "Count AI inventory entities in total and per kind.")),
  )
