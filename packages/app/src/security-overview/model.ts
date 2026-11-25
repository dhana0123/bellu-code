import { Schema } from "effect"
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
export type Severity = (typeof SEVERITIES)[number]
const SeverityCounts = Schema.Struct({
  critical: Schema.Number,
  high: Schema.Number,
  medium: Schema.Number,
  low: Schema.Number,
  info: Schema.Number,
})
const Category = Schema.Struct({
  category: Schema.String,
  title: Schema.String,
  subtitle: Schema.String,
  entityCount: Schema.Number,
  severity: SeverityCounts,
  topIssues: Schema.Array(
    Schema.Struct({
      id: Schema.String,
      title: Schema.String,
      severity: Schema.Literals(SEVERITIES),
      riskScore: Schema.Union([Schema.Number, Schema.Literals(["Infinity", "-Infinity", "NaN"])]),
    }),
  ),
  emptyState: Schema.optional(Schema.Struct({ missingSource: Schema.String, setupLink: Schema.String })),
  kinds: Schema.Record(Schema.String, Schema.Number),
})
export type OverviewCategory = typeof Category.Type
/** The generated client's response, which is also what the cache stores. */
const Overview = Schema.Struct({ revision: Schema.Number, categories: Schema.Array(Category) })
export type OverviewData = typeof Overview.Type
const decodeCached = Schema.decodeUnknownOption(Schema.fromJsonString(Overview))
export const parseCached = (json: string) => decodeCached(json)
/** The graph lens of a category: `cloud_infrastructure` opens `category-cloud-infrastructure`. */
export const lensOf = (category: string) => `category-${category.replaceAll("_", "-")}`
export const lensPath = (category: string) => `/security/graph?lens=${encodeURIComponent(lensOf(category))}`
/** bellud's weak ETag for a revision, sent back as `If-None-Match`. */
export const etagOf = (revision: number) => `W/"rev-${revision}"`
/** The page shows nothing but the loading marker until a response or the cache fills `categories`. */
export type OverviewStatus = "loading" | "ready" | "error"
export const REQUEST_TIMEOUT_MS = 10_000
export const POLL_INTERVAL_MS = 10_000
