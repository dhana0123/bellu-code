import { Graph } from "@bellucode/schema/graph"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/http-api"
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
  .add(
    HttpApiEndpoint.get("lenses", "/api/experimental/graph/lenses", {
      success: Schema.Array(Graph.Lens),
      error: errors,
    }).annotateMerge(experimental("lenses", "List graph lenses", "List the lenses available for graph slices.")),
  )
  .add(
    HttpApiEndpoint.get("slice", "/api/experimental/graph/slice", {
      query: {
        lens: Schema.String.annotate({ description: "Lens id from the lens catalog." }),
        entity: Schema.optional(Schema.String).annotate({ description: "Root entity id for the lens." }),
        target: Schema.optional(Schema.String).annotate({ description: "Target entity id for path lenses." }),
        target_type: Schema.optional(Schema.String).annotate({
          description: "Target resource type for the attack-path lens, for example rds:instance.",
        }),
        collapse_rules: Schema.optional(Schema.Literals(["true", "false"])).annotate({
          description: "Replace security group rule nodes with group-to-peer edges; overrides the lens default.",
        }),
        depth: Schema.optional(
          Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1)))),
        ).annotate({ description: "Traversal depth; clamped by the server." }),
        limit: Schema.optional(
          Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1)))),
        ).annotate({ description: "Maximum number of nodes; clamped by the server." }),
      },
      success: Graph.LensSlice,
      error: errors,
    }).annotateMerge(experimental("slice", "Get lens slice", "Build a bounded graph slice for one lens.")),
  )
  .add(
    HttpApiEndpoint.get("intelStatus", "/api/experimental/graph/intel/status", {
      success: Graph.IntelStatus,
      error: errors,
    }).annotateMerge(experimental("intelStatus", "Get intel status", "Report vulnerability intelligence sync state.")),
  )
  .add(
    HttpApiEndpoint.get("overlay", "/api/experimental/graph/overlay", {
      query: {
        replay: Schema.optional(Schema.String).annotate({ description: "Script id to replay for this connection (for example demo)." }),
      },
      success: HttpApiSchema.StreamSse({ data: Graph.OverlayEvent }),
      error: errors,
    }).annotateMerge(
      experimental("overlay", "Stream agent overlay events", "Subscribe to transient agent overlay events as server-sent events."),
    ),
  )
