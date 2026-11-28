import { Findings } from "@bellucode/schema/findings"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { ConflictError, InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, ConflictError, UnknownError] as const

const FindingParams = { id: Findings.ID }

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.findings.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.findings`: routes under /api/experimental/findings, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalFindingsGroup = HttpApiGroup.make("server.findings")
  .add(
    HttpApiEndpoint.get("list", "/api/experimental/findings", {
      query: {
        category: Schema.optional(Schema.ArrayEnsure(Findings.Category)).annotate({
          description: "Only these overview categories. Repeat the parameter to match any of several.",
        }),
        severity: Schema.optional(Schema.ArrayEnsure(Findings.Severity)).annotate({
          description: "Only these severities. Repeat the parameter to match any of several.",
        }),
        status: Schema.optional(Schema.ArrayEnsure(Findings.Status)).annotate({
          description: "Only these statuses. Repeat the parameter to match any of several.",
        }),
        type: Schema.optional(Schema.ArrayEnsure(Findings.Type)).annotate({
          description: "Only these finding types. Repeat the parameter to match any of several.",
        }),
        asset: Schema.optional(Schema.ArrayEnsure(Schema.String)).annotate({
          description: "Only findings on these asset ids. Repeat the parameter to match any of several.",
        }),
        source: Schema.optional(Schema.ArrayEnsure(Schema.String)).annotate({
          description: "Only findings from these sources. Repeat the parameter to match any of several.",
        }),
        from: Schema.optional(Schema.String).annotate({ description: "RFC 3339 lower bound on last seen." }),
        to: Schema.optional(Schema.String).annotate({ description: "RFC 3339 upper bound on last seen." }),
        sort: Schema.optional(Findings.Sort).annotate({
          description: "One sort field; prefix with - for descending. Defaults to -last_seen.",
        }),
        limit: Schema.optional(
          Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 500 })))),
        ).annotate({ description: "Maximum number of items to return (1-500, default 50)." }),
        cursor: Schema.optional(Schema.String).annotate({
          description: "Opaque cursor from a previous page; valid only with the same filters and sort.",
        }),
      },
      success: Findings.Page,
      error: errors,
    }).annotateMerge(
      experimental(
        "list",
        "List findings",
        "List findings with filters, sorting and cursor pagination. A truncated page means the server time budget ended the query.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.get("get", "/api/experimental/findings/:id", {
      params: FindingParams,
      success: Findings.Detail,
      error: errors,
    }).annotateMerge(experimental("get", "Get finding", "Get one finding with its status history.")),
  )
  .add(
    HttpApiEndpoint.post("setStatus", "/api/experimental/findings/:id/status", {
      params: FindingParams,
      payload: Findings.SetStatusInput,
      success: Findings.Detail,
      error: errors,
    }).annotateMerge(
      experimental(
        "setStatus",
        "Set finding status",
        "Change a finding status and return the updated finding with its history. Answers 409 when the lifecycle does not allow the change.",
      ),
    ),
  )
