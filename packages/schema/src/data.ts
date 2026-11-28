export * as Data from "./data.js"
import { Schema } from "effect"
import { optional } from "./schema.js"

// Mirrors services/bellud/internal/api/data.
export const ID = Schema.String.annotate({ identifier: "Data.ID" }).check(Schema.isNonEmpty(), Schema.isMaxLength(256))
export type ID = typeof ID.Type

export const Store = Schema.Struct({
  id: Schema.String,
  type: Schema.String,
  name: Schema.String,
  region: optional(Schema.String),
  // Copied from graph entity attributes; null when the attribute is unknown.
  encryptionAtRest: Schema.Json,
  encryptionInTransit: Schema.Json,
  publicAccess: Schema.Json,
  backup: Schema.Json,
  logging: Schema.Json,
  classes: Schema.Array(Schema.String),
  matchCounts: Schema.Record(Schema.String, Schema.Int),
  openExposureCount: Schema.Int,
}).annotate({ identifier: "Data.Store" })
export interface Store extends Schema.Schema.Type<typeof Store> {}

export const StorePage = Schema.Struct({
  items: Schema.Array(Store),
  nextCursor: optional(Schema.String),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Data.StorePage" })
export interface StorePage extends Schema.Schema.Type<typeof StorePage> {}
