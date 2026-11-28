import { Overview } from "@bellucode/schema/overview"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { NotFoundError, ServiceUnavailableError, UnknownError } from "../errors.js"

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.overview.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.overview`: routes under /api/experimental/overview, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalOverviewGroup = HttpApiGroup.make("server.overview").add(
  HttpApiEndpoint.get("categories", "/api/experimental/overview/categories", {
    success: Overview.Categories,
    error: [NotFoundError, ServiceUnavailableError, UnknownError],
  }).annotateMerge(
    experimental(
      "categories",
      "List overview categories",
      "Summarize all nine overview categories in one call. The response carries an ETag derived from its revision; send it back as If-None-Match to receive 304 Not Modified. Answers 503 with Retry-After while the service starts.",
    ),
  ),
)
