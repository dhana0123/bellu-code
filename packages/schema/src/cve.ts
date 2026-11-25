export * as Cve from "./cve.js"
import { Schema } from "effect"
import { optional } from "./schema.js"
// Mirrors services/bellud/internal/api/cve. Timestamps are RFC 3339 strings produced by the Go server.
export const Mode = Schema.Literals(["db", "graph", "both"]).annotate({ identifier: "Cve.Mode" })
export type Mode = typeof Mode.Type
export const ID = Schema.String.annotate({ identifier: "Cve.ID" }).check(Schema.isNonEmpty(), Schema.isMaxLength(256))
export type ID = typeof ID.Type
export const Gap = Schema.Struct({
  kind: Schema.String,
  cause: Schema.String,
}).annotate({ identifier: "Cve.Gap" })
export interface Gap extends Schema.Schema.Type<typeof Gap> {}
export const Warning = Schema.Struct({
  code: Schema.String,
  message: Schema.String,
}).annotate({ identifier: "Cve.Warning" })
export interface Warning extends Schema.Schema.Type<typeof Warning> {}
export const Range = Schema.Struct({
  introduced: Schema.String,
  fixed: Schema.String,
}).annotate({ identifier: "Cve.Range" })
export interface Range extends Schema.Schema.Type<typeof Range> {}
export const Vuln = Schema.Struct({
  id: Schema.String,
  aliases: Schema.Array(Schema.String),
  summary: Schema.String,
  severity: Schema.String,
  cvssScore: Schema.Number,
  cvssVector: optional(Schema.String),
  cvssVersion: optional(Schema.String),
  ranges: Schema.Array(Range),
  fixedVersions: Schema.Array(Schema.String),
  kev: Schema.Boolean,
  epss: Schema.Number,
  published: optional(Schema.String),
  modified: optional(Schema.String),
  affectedState: optional(Schema.String),
  origin: Schema.String,
}).annotate({ identifier: "Cve.Vuln" })
export interface Vuln extends Schema.Schema.Type<typeof Vuln> {}
export const Ref = Schema.Struct({
  id: Schema.String,
  type: Schema.String,
  key: Schema.String,
  label: Schema.String,
}).annotate({ identifier: "Cve.Ref" })
export interface Ref extends Schema.Schema.Type<typeof Ref> {}
// Fields shared by lookup, detail and graph responses.
const meta = {
  gaps: Schema.Array(Gap),
  warnings: Schema.Array(Warning),
  fieldFrom: Schema.Record(Schema.String, Schema.String),
  truncated: Schema.Boolean,
}
export const LookupResult = Schema.Struct({
  vulns: Schema.Array(Vuln),
  ...meta,
}).annotate({ identifier: "Cve.LookupResult" })
export interface LookupResult extends Schema.Schema.Type<typeof LookupResult> {}
// The Go Conflict struct has no JSON tags, so its keys are `DB` and `Graph`.
export const Conflict = Schema.Struct({
  DB: Schema.Unknown,
  Graph: Schema.Unknown,
}).annotate({ identifier: "Cve.Conflict" })
export interface Conflict extends Schema.Schema.Type<typeof Conflict> {}
export const Detail = Schema.Struct({
  ...Vuln.fields,
  cwes: Schema.Array(Ref),
  exploits: Schema.Array(Ref),
  affected: Schema.Array(Ref),
  related: Schema.Array(Ref),
  conflicts: optional(Schema.Record(Schema.String, Conflict)),
  ...meta,
}).annotate({ identifier: "Cve.Detail" })
export interface Detail extends Schema.Schema.Type<typeof Detail> {}
export const Node = Schema.Struct({
  id: Schema.String,
  type: Schema.String,
  key: Schema.String,
  label: Schema.String,
  properties: optional(Schema.Record(Schema.String, Schema.Unknown)),
}).annotate({ identifier: "Cve.Node" })
export interface Node extends Schema.Schema.Type<typeof Node> {}
export const Edge = Schema.Struct({
  id: Schema.String,
  source: Schema.String,
  target: Schema.String,
  type: Schema.String,
  viewID: optional(Schema.String),
}).annotate({ identifier: "Cve.Edge" })
export interface Edge extends Schema.Schema.Type<typeof Edge> {}
export const Graph = Schema.Struct({
  nodes: Schema.Array(Node),
  edges: Schema.Array(Edge),
  ...meta,
}).annotate({ identifier: "Cve.Graph" })
export interface Graph extends Schema.Schema.Type<typeof Graph> {}
export const Status = Schema.Struct({
  mode: Mode,
  dbInstalled: Schema.Boolean,
  dataAgeHours: Schema.Int,
  stale: Schema.Boolean,
  staleLimitHours: Schema.Int,
  bskgReachable: Schema.Boolean,
  graphEnabled: Schema.Boolean,
  lastGap: Schema.NullOr(Gap),
}).annotate({ identifier: "Cve.Status" })
export interface Status extends Schema.Schema.Type<typeof Status> {}
export const ModeInput = Schema.Struct({
  mode: Mode,
}).annotate({ identifier: "Cve.ModeInput" })
export interface ModeInput extends Schema.Schema.Type<typeof ModeInput> {}
export const ModeResult = Schema.Struct({
  mode: Mode,
}).annotate({ identifier: "Cve.ModeResult" })
export interface ModeResult extends Schema.Schema.Type<typeof ModeResult> {}
