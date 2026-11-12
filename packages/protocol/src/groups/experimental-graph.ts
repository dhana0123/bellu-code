import { Graph } from "@opencode/schema/graph"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError, ServiceUnavailableError } from "../errors.js"

const errors = [InvalidRequestError, ServiceUnavailableError] as const

const Limit = Schema.optional(
  Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 1000 })))),
).annotate({ description: "Maximum number of items to return (1-1000)." })

const AsOf = Schema.optional(Schema.String).annotate({
  description: "RFC 3339 timestamp; read the graph as it was valid at this time.",
})

const EntityParams = { id: Graph.EntityID }

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.graph.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.graph`: routes under /api/experimental/graph, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalGraphGroup = HttpApiGroup.make("server.graph")
  .add(
    HttpApiEndpoint.get("find", "/api/experimental/graph/entities", {
      query: {
        type: Schema.optional(Schema.String).annotate({ description: "Filter by entity type." }),
        match: Schema.optional(Schema.String).annotate({ description: "Match against entity id, label, or attributes." }),
        as_of: AsOf,
        limit: Limit,
      },
      success: Graph.EntityPage,
      error: errors,
    }).annotateMerge(experimental("find", "Find graph entities", "Search graph entities by type or text.")),
  )
  .add(
    HttpApiEndpoint.get("entity", "/api/experimental/graph/entities/:id", {
      params: EntityParams,
      query: { as_of: AsOf },
      success: Graph.Entity,
      error: errors,
    }).annotateMerge(experimental("entity", "Get graph entity", "Get one graph entity by id.")),
  )
  .add(
    HttpApiEndpoint.get("neighbors", "/api/experimental/graph/entities/:id/neighbors", {
      params: EntityParams,
      query: {
        direction: Schema.optional(Graph.Direction),
        type: Schema.optional(Schema.String).annotate({ description: "Filter by relation type." }),
        as_of: AsOf,
        limit: Limit,
      },
      success: Graph.EdgePage,
      error: errors,
    }).annotateMerge(experimental("neighbors", "List entity neighbors", "List edges connected to a graph entity.")),
  )
  .add(
    HttpApiEndpoint.get("history", "/api/experimental/graph/entities/:id/history", {
      params: EntityParams,
      query: {
        since: Schema.optional(Schema.String).annotate({ description: "RFC 3339 lower bound (inclusive)." }),
        until: Schema.optional(Schema.String).annotate({ description: "RFC 3339 upper bound (exclusive)." }),
        limit: Limit,
      },
      success: Graph.ChangePage,
      error: errors,
    }).annotateMerge(experimental("history", "Get entity history", "List changes recorded for a graph entity.")),
  )
  .add(
    HttpApiEndpoint.get("changes", "/api/experimental/graph/changes", {
      query: {
        since: Schema.optional(Schema.String).annotate({ description: "RFC 3339 lower bound (inclusive)." }),
        until: Schema.optional(Schema.String).annotate({ description: "RFC 3339 upper bound (exclusive)." }),
        type: Schema.optional(Schema.String).annotate({ description: "Filter by entity or relation type." }),
        limit: Limit,
      },
      success: Graph.ChangePage,
      error: errors,
    }).annotateMerge(experimental("changes", "List graph changes", "List graph changes within a time window.")),
  )
  .add(
    HttpApiEndpoint.get("diff", "/api/experimental/graph/diff", {
      query: {
        from: Schema.String.annotate({ description: "RFC 3339 start timestamp." }),
        to: Schema.String.annotate({ description: "RFC 3339 end timestamp." }),
        type: Schema.optional(Schema.String).annotate({ description: "Filter by entity type." }),
        limit: Limit,
      },
      success: Graph.Diff,
      error: errors,
    }).annotateMerge(experimental("diff", "Diff graph", "Compare the graph between two points in time.")),
  )
  .add(
    HttpApiEndpoint.get("schema", "/api/experimental/graph/schema", {
      success: Graph.SchemaSummary,
      error: errors,
    }).annotateMerge(experimental("schema", "Get graph schema", "Summarize entity and relation types in the graph.")),
  )
  .add(
    HttpApiEndpoint.get("status", "/api/experimental/graph/status", {
      success: Graph.Status,
      error: errors,
    }).annotateMerge(experimental("status", "Get graph status", "Report graph engine and child process state.")),
  )
