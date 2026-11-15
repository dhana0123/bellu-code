export * as Graph from "./graph.js"

import { Schema } from "effect"
import { optional } from "./schema.js"

// Timestamps are RFC 3339 strings produced by the Go engine.
// `observed_at` is valid time and `recorded_at` is transaction time.
const Timestamp = Schema.String.check(Schema.isNonEmpty())

export const EntityID = Schema.String.annotate({ identifier: "Graph.EntityID" }).check(Schema.isNonEmpty())
export type EntityID = typeof EntityID.Type

export const Attributes = Schema.Record(Schema.String, Schema.Json).annotate({ identifier: "Graph.Attributes" })
export type Attributes = typeof Attributes.Type

export const Entity = Schema.Struct({
  id: EntityID,
  type: Schema.String.check(Schema.isNonEmpty()),
  label: optional(Schema.String),
  attributes: Attributes,
  observed_at: Timestamp,
  recorded_at: Timestamp,
}).annotate({ identifier: "Graph.Entity" })
export interface Entity extends Schema.Schema.Type<typeof Entity> {}

export const Direction = Schema.Literals(["out", "in", "both"]).annotate({ identifier: "Graph.Direction" })
export type Direction = typeof Direction.Type

export const Edge = Schema.Struct({
  from: EntityID,
  to: EntityID,
  type: Schema.String.check(Schema.isNonEmpty()),
  direction: Direction,
  hops: Schema.Int.check(Schema.isGreaterThanOrEqualTo(1)),
}).annotate({ identifier: "Graph.Edge" })
export interface Edge extends Schema.Schema.Type<typeof Edge> {}

// Mirrors the engine change taxonomy: derived by diffing observations against the projection.
export const ChangeKind = Schema.Literals(["added", "changed", "removed"]).annotate({
  identifier: "Graph.ChangeKind",
})
export type ChangeKind = typeof ChangeKind.Type

export const ChangeSubject = Schema.Literals(["entity", "relation"]).annotate({ identifier: "Graph.ChangeSubject" })
export type ChangeSubject = typeof ChangeSubject.Type

export const Change = Schema.Struct({
  kind: ChangeKind,
  subject: ChangeSubject,
  entity: optional(EntityID),
  from: optional(EntityID),
  to: optional(EntityID),
  relation_type: optional(Schema.String),
  observed_at: Timestamp,
  recorded_at: Timestamp,
}).annotate({ identifier: "Graph.Change" })
export interface Change extends Schema.Schema.Type<typeof Change> {}

function page<S extends Schema.Top>(item: S, identifier: string) {
  return Schema.Struct({
    items: Schema.Array(item),
    total: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
    truncated: Schema.Boolean,
    limit: Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 1000 })),
  }).annotate({ identifier })
}

export const EntityPage = page(Entity, "Graph.EntityPage")
export type EntityPage = typeof EntityPage.Type

export const EdgePage = page(Edge, "Graph.EdgePage")
export type EdgePage = typeof EdgePage.Type

export const ChangePage = page(Change, "Graph.ChangePage")
export type ChangePage = typeof ChangePage.Type

export const Diff = Schema.Struct({
  from: Timestamp,
  to: Timestamp,
  added: Schema.Array(Entity),
  changed: Schema.Array(Entity),
  removed: Schema.Array(EntityID),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Graph.Diff" })
export interface Diff extends Schema.Schema.Type<typeof Diff> {}

export const SchemaType = Schema.Struct({
  name: Schema.String.check(Schema.isNonEmpty()),
  description: optional(Schema.String),
  count: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
}).annotate({ identifier: "Graph.SchemaType" })
export interface SchemaType extends Schema.Schema.Type<typeof SchemaType> {}

export const SchemaSummary = Schema.Struct({
  entity_types: Schema.Array(SchemaType),
  relation_types: Schema.Array(SchemaType),
}).annotate({ identifier: "Graph.SchemaSummary" })
export interface SchemaSummary extends Schema.Schema.Type<typeof SchemaSummary> {}

export const EngineState = Schema.Literals(["disabled", "starting", "ready", "failed"]).annotate({
  identifier: "Graph.EngineState",
})
export type EngineState = typeof EngineState.Type

export const ChildState = Schema.Literals(["starting", "ready", "restarting", "degraded", "stopped"]).annotate({
  identifier: "Graph.ChildState",
})
export type ChildState = typeof ChildState.Type

export const Status = Schema.Struct({
  engine: EngineState,
  ts_child: ChildState,
  detail: optional(Schema.String),
}).annotate({ identifier: "Graph.Status" })
export interface Status extends Schema.Schema.Type<typeof Status> {}

export const LensParam = Schema.Struct({
  name: Schema.String,
  required: Schema.Boolean,
}).annotate({ identifier: "Graph.LensParam" })
export interface LensParam extends Schema.Schema.Type<typeof LensParam> {}

export const Lens = Schema.Struct({
  id: Schema.String.check(Schema.isNonEmpty()),
  name: Schema.String,
  description: Schema.String,
  layout: Schema.Literals(["force", "radial", "chain"]),
  default: Schema.Boolean,
  params: Schema.Array(LensParam),
}).annotate({ identifier: "Graph.Lens" })
export interface Lens extends Schema.Schema.Type<typeof Lens> {}

export const Confidence = Schema.Literals(["extracted", "inferred"]).annotate({ identifier: "Graph.Confidence" })
export type Confidence = typeof Confidence.Type

export const LensRisk = Schema.Struct({
  score: Schema.Number,
  severity: Schema.String,
  cvss: Schema.Number,
  epss: Schema.Number,
  kev: Schema.Boolean,
  reachable: Schema.NullOr(Schema.Boolean),
}).annotate({ identifier: "Graph.LensRisk" })
export interface LensRisk extends Schema.Schema.Type<typeof LensRisk> {}

export const LensNode = Schema.Struct({
  id: EntityID,
  kind: Schema.String,
  label: Schema.String,
  group: Schema.NullOr(Schema.String),
  hops: Schema.Int,
  attrs: Schema.Record(Schema.String, Schema.String),
  risk: Schema.NullOr(LensRisk),
}).annotate({ identifier: "Graph.LensNode" })
export interface LensNode extends Schema.Schema.Type<typeof LensNode> {}

export const LensEdge = Schema.Struct({
  from: EntityID,
  to: EntityID,
  type: Schema.String,
  confidence: Confidence,
}).annotate({ identifier: "Graph.LensEdge" })
export interface LensEdge extends Schema.Schema.Type<typeof LensEdge> {}

export const LensGroup = Schema.Struct({
  id: Schema.String,
  label: Schema.String,
  members: Schema.Array(EntityID),
}).annotate({ identifier: "Graph.LensGroup" })
export interface LensGroup extends Schema.Schema.Type<typeof LensGroup> {}

export const LensPath = Schema.Struct({
  nodes: Schema.Array(EntityID),
  confidence: Confidence,
}).annotate({ identifier: "Graph.LensPath" })
export interface LensPath extends Schema.Schema.Type<typeof LensPath> {}

export const LensSlice = Schema.Struct({
  lens: Schema.String,
  generated_at: Timestamp,
  truncated: Schema.Boolean,
  counts: Schema.Struct({
    nodes: Schema.Int,
    edges: Schema.Int,
    omitted_nodes: Schema.Int,
  }),
  nodes: Schema.Array(LensNode),
  edges: Schema.Array(LensEdge),
  groups: Schema.Array(LensGroup),
  paths: optional(Schema.Array(LensPath)),
}).annotate({ identifier: "Graph.LensSlice" })
export interface LensSlice extends Schema.Schema.Type<typeof LensSlice> {}

export const IntelState = Schema.Literals(["not_configured", "disabled", "idle", "syncing", "ok", "error"]).annotate({
  identifier: "Graph.IntelState",
})
export type IntelState = typeof IntelState.Type

// Unset strings are empty, never absent.
export const IntelStatus = Schema.Struct({
  state: IntelState,
  version: Schema.String,
  records: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
  last_synced_at: Schema.String,
  last_error: Schema.String,
}).annotate({ identifier: "Graph.IntelStatus" })
export interface IntelStatus extends Schema.Schema.Type<typeof IntelStatus> {}

export const OverlayAction = Schema.Literals(["focus_node", "walk_path", "proposed_change"]).annotate({
  identifier: "Graph.OverlayAction",
})
export type OverlayAction = typeof OverlayAction.Type

// Transient agent instruction. Never stored and never a graph fact.
export const OverlayEvent = Schema.Struct({
  seq: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
  entity: EntityID,
  action: OverlayAction,
  path: optional(Schema.Array(EntityID)),
  explanation: Schema.String,
}).annotate({ identifier: "Graph.OverlayEvent" })
export interface OverlayEvent extends Schema.Schema.Type<typeof OverlayEvent> {}
