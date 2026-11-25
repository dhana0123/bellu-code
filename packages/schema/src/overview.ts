export * as Overview from "./overview.js"
import { Schema } from "effect"
import { optional } from "./schema.js"

// Mirrors services/bellud/internal/api/overview: the nine category summaries served in one call.
export const Category = Schema.Literals([
  "cloud_infrastructure",
  "identity",
  "vulnerabilities",
  "network_exposure",
  "secrets",
  "data_security",
  "code_and_dependencies",
  "runtime",
  "ai_security",
]).annotate({ identifier: "Overview.Category" })
export type Category = typeof Category.Type

export const Severity = Schema.Literals(["critical", "high", "medium", "low", "info"]).annotate({
  identifier: "Overview.Severity",
})
export type Severity = typeof Severity.Type

const Count = Schema.Int.check(Schema.isGreaterThanOrEqualTo(0))

export const SeverityCounts = Schema.Struct({
  critical: Count,
  high: Count,
  medium: Count,
  low: Count,
  info: Count,
}).annotate({ identifier: "Overview.SeverityCounts" })
export interface SeverityCounts extends Schema.Schema.Type<typeof SeverityCounts> {}

export const Issue = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  severity: Severity,
  riskScore: Schema.Number,
}).annotate({ identifier: "Overview.Issue" })
export interface Issue extends Schema.Schema.Type<typeof Issue> {}

export const EmptyState = Schema.Struct({
  missingSource: Schema.String,
  setupLink: Schema.String,
}).annotate({ identifier: "Overview.EmptyState" })
export interface EmptyState extends Schema.Schema.Type<typeof EmptyState> {}

export const CategorySummary = Schema.Struct({
  category: Category,
  title: Schema.String,
  subtitle: Schema.String,
  entityCount: Count,
  severity: SeverityCounts,
  topIssues: Schema.Array(Issue),
  emptyState: optional(EmptyState),
  kinds: Schema.Record(Schema.String, Count),
}).annotate({ identifier: "Overview.CategorySummary" })
export interface CategorySummary extends Schema.Schema.Type<typeof CategorySummary> {}

export const Categories = Schema.Struct({
  revision: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
  categories: Schema.Array(CategorySummary),
}).annotate({ identifier: "Overview.Categories" })
export interface Categories extends Schema.Schema.Type<typeof Categories> {}
