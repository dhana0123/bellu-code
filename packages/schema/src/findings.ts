export * as Findings from "./findings.js"
import { Schema } from "effect"
import { Overview } from "./overview.js"
import { optional } from "./schema.js"

// Mirrors services/bellud/internal/api/findings. Timestamps are RFC 3339 strings produced by the Go server.
export const ID = Schema.String.annotate({ identifier: "Findings.ID" }).check(Schema.isNonEmpty(), Schema.isMaxLength(128))
export type ID = typeof ID.Type

export const Severity = Overview.Severity
export type Severity = Overview.Severity

export const Category = Overview.Category
export type Category = Overview.Category

export const Status = Schema.Literals(["open", "in_progress", "resolved", "ignored", "accepted_risk"]).annotate({
  identifier: "Findings.Status",
})
export type Status = typeof Status.Type

export const Type = Schema.Literals([
  "vulnerability",
  "misconfiguration",
  "secret",
  "license",
  "malware",
  "runtime_threat",
  "ai_risk",
  "data_exposure",
  "identity_risk",
]).annotate({ identifier: "Findings.Type" })
export type Type = typeof Type.Type

export const Sort = Schema.Literals([
  "last_seen",
  "-last_seen",
  "first_seen",
  "-first_seen",
  "severity",
  "-severity",
  "risk_score",
  "-risk_score",
]).annotate({ identifier: "Findings.Sort" })
export type Sort = typeof Sort.Type

export const Evidence = Schema.Struct({
  kind: Schema.String,
  ref: Schema.String,
  line: optional(Schema.Int),
  excerpt: optional(Schema.String),
}).annotate({ identifier: "Findings.Evidence" })
export interface Evidence extends Schema.Schema.Type<typeof Evidence> {}

export const Finding = Schema.Struct({
  id: ID,
  ruleId: Schema.String,
  title: Schema.String,
  description: Schema.String,
  category: Category,
  type: Type,
  severity: Severity,
  status: Status,
  assetId: Schema.String,
  evidence: Schema.Array(Evidence),
  firstSeen: Schema.String,
  lastSeen: Schema.String,
  resolvedAt: optional(Schema.String),
  source: Schema.String,
  sourceRevision: optional(Schema.String),
  rulePackVersion: optional(Schema.String),
  occurrences: Schema.Int,
  riskScore: optional(Schema.Number),
  unmappedSeverity: optional(Schema.Boolean),
  details: optional(Schema.Json),
}).annotate({ identifier: "Findings.Finding" })
export interface Finding extends Schema.Schema.Type<typeof Finding> {}

export const Event = Schema.Struct({
  seq: Schema.Int,
  at: Schema.String,
  actor: Schema.String,
  prevStatus: optional(Status),
  newStatus: Status,
  reason: optional(Schema.String),
}).annotate({ identifier: "Findings.Event" })
export interface Event extends Schema.Schema.Type<typeof Event> {}

export const Detail = Schema.Struct({
  ...Finding.fields,
  events: Schema.Array(Event),
}).annotate({ identifier: "Findings.Detail" })
export interface Detail extends Schema.Schema.Type<typeof Detail> {}

export const Page = Schema.Struct({
  items: Schema.Array(Finding),
  nextCursor: optional(Schema.String),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Findings.Page" })
export interface Page extends Schema.Schema.Type<typeof Page> {}

export const SetStatusInput = Schema.Struct({
  status: Status,
  reason: optional(Schema.String.check(Schema.isMaxLength(1024))),
  until: optional(Schema.String),
}).annotate({ identifier: "Findings.SetStatusInput" })
export interface SetStatusInput extends Schema.Schema.Type<typeof SetStatusInput> {}
