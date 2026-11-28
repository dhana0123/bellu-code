import { Issues } from "@bellucode/schema/issues"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, UnknownError] as const
const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.issues.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })
const IssueParams = { id: Issues.ID }

/**
 * `server.issues`: routes under /api/experimental/issues, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalIssuesGroup = HttpApiGroup.make("server.issues")
  .add(
    HttpApiEndpoint.get("list", "/api/experimental/issues", {
      query: {
        category: Schema.optional(Schema.ArrayEnsure(Issues.Category)).annotate({
          description: "Only these overview categories. Repeat the parameter to match any of several.",
        }),
        severity: Schema.optional(Schema.ArrayEnsure(Issues.Severity)).annotate({
          description: "Only these severities. Repeat the parameter to match any of several.",
        }),
        status: Schema.optional(Schema.ArrayEnsure(Issues.Status)).annotate({
          description: "Only these statuses. Repeat the parameter to match any of several.",
        }),
        asset: Schema.optional(Schema.String).annotate({ description: "Only issues touching this asset id. Give it at most once." }),
        sort: Schema.optional(Issues.Sort).annotate({
          description: "Sort by risk score; prefix with - for descending. Defaults to -risk_score.",
        }),
        limit: Schema.optional(Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 500 }))))).annotate({ description: "Maximum number of items to return (1-500, default 50)." }),
        cursor: Schema.optional(Schema.String).annotate({
          description: "Opaque cursor from a previous page; valid only with the same filters and sort.",
        }),
      },
      success: Issues.Page,
      error: errors,
    }).annotateMerge(
      experimental(
        "list",
        "List issues",
        "List issues ordered by risk score with filters and cursor pagination. A truncated page means the server time budget ended the query.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.get("get", "/api/experimental/issues/:id", {
      params: IssueParams,
      success: Issues.Detail,
      error: errors,
    }).annotateMerge(experimental("get", "Get issue", "Get one issue with its attack path and member findings.")),
  )
  .add(
    HttpApiEndpoint.post("setStatus", "/api/experimental/issues/:id/status", {
      params: IssueParams,
      payload: Issues.SetStatusInput,
      success: Issues.Detail,
      error: errors,
    }).annotateMerge(
      experimental("setStatus", "Set issue status", "Set the status of one issue to open, resolved or ignored and return it."),
    ),
  )
