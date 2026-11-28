export * as Issues from "./issues.js"
import { Schema } from "effect"
import { Overview } from "./overview.js"
import { optional } from "./schema.js"

// Mirrors services/bellud/internal/api/issues. Timestamps are RFC 3339 strings produced by the Go server.
export const ID = Schema.String.annotate({ identifier: "Issues.ID" }).check(Schema.isNonEmpty(), Schema.isMaxLength(128))
export type ID = typeof ID.Type

export const Severity = Overview.Severity
export type Severity = Overview.Severity

export const Category = Overview.Category
export type Category = Overview.Category

export const Status = Schema.Literals(["open", "resolved", "ignored"]).annotate({ identifier: "Issues.Status" })
export type Status = typeof Status.Type

export const Sort = Schema.Literals(["risk_score", "-risk_score"]).annotate({ identifier: "Issues.Sort" })
export type Sort = typeof Sort.Type

export const Hop = Schema.Struct({
  entityId: Schema.String,
  relation: optional(Schema.String),
  evidence: Schema.Array(Schema.String),
  inferred: Schema.Boolean,
}).annotate({ identifier: "Issues.Hop" })
export interface Hop extends Schema.Schema.Type<typeof Hop> {}

export const Issue = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  ruleId: Schema.String,
  severity: Severity,
  riskScore: Schema.Number,
  status: Status,
  category: Category,
  includesInferred: Schema.Boolean,
  findingCount: Schema.Int,
  path: Schema.Array(Hop),
  createdAt: Schema.String,
  updatedAt: Schema.String,
}).annotate({ identifier: "Issues.Issue" })
export interface Issue extends Schema.Schema.Type<typeof Issue> {}

export const Member = Schema.Struct({
  id: Schema.String,
  title: optional(Schema.String),
  ruleId: optional(Schema.String),
  severity: optional(Schema.String),
  status: optional(Schema.String),
  assetId: optional(Schema.String),
}).annotate({ identifier: "Issues.Member" })
export interface Member extends Schema.Schema.Type<typeof Member> {}

export const Detail = Schema.Struct({
  ...Issue.fields,
  findings: Schema.Array(Member),
}).annotate({ identifier: "Issues.Detail" })
export interface Detail extends Schema.Schema.Type<typeof Detail> {}

export const Page = Schema.Struct({
  items: Schema.Array(Issue),
  nextCursor: optional(Schema.String),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Issues.Page" })
export interface Page extends Schema.Schema.Type<typeof Page> {}

export const SetStatusInput = Schema.Struct({
  status: Status,
}).annotate({ identifier: "Issues.SetStatusInput" })
export interface SetStatusInput extends Schema.Schema.Type<typeof SetStatusInput> {}
