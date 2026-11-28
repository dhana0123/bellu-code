export * as Sbom from "./sbom.js"
import { Schema } from "effect"
import { optional } from "./schema.js"
// Mirrors services/bellud/internal/api/sbom. Timestamps are RFC 3339 strings produced by the Go server.
export const AssetID = Schema.String.annotate({ identifier: "Sbom.AssetID" }).check(
  Schema.isNonEmpty(),
  Schema.isMaxLength(512),
)
export type AssetID = typeof AssetID.Type
export const ExportFormat = Schema.Literals(["cyclonedx", "spdx"]).annotate({ identifier: "Sbom.ExportFormat" })
export type ExportFormat = typeof ExportFormat.Type
export const Summary = Schema.Struct({
  assetId: Schema.String,
  digest: Schema.String,
  packageCount: Schema.Int,
  createdAt: Schema.String,
  ecosystems: Schema.Record(Schema.String, Schema.Int),
  licenses: Schema.Record(Schema.String, Schema.Int),
}).annotate({ identifier: "Sbom.Summary" })
export interface Summary extends Schema.Schema.Type<typeof Summary> {}
export const SummaryList = Schema.Struct({
  items: Schema.Array(Summary),
}).annotate({ identifier: "Sbom.SummaryList" })
export interface SummaryList extends Schema.Schema.Type<typeof SummaryList> {}
export const Package = Schema.Struct({
  type: optional(Schema.String),
  name: Schema.String,
  version: optional(Schema.String),
  purl: optional(Schema.String),
  ecosystem: optional(Schema.String),
  licenses: Schema.Array(Schema.String),
  supplier: optional(Schema.String),
  locations: Schema.Array(Schema.String),
  properties: optional(Schema.Record(Schema.String, Schema.String)),
}).annotate({ identifier: "Sbom.Package" })
export interface Package extends Schema.Schema.Type<typeof Package> {}
export const Detail = Schema.Struct({
  ...Summary.fields,
  subject: optional(Schema.String),
  items: Schema.Array(Package),
  nextCursor: optional(Schema.String),
}).annotate({ identifier: "Sbom.Detail" })
export interface Detail extends Schema.Schema.Type<typeof Detail> {}
