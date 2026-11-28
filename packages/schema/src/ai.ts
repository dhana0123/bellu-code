export * as Ai from "./ai.js"
import { Schema } from "effect"
// Mirrors services/bellud/internal/api/ai.
export const Entity = Schema.Struct({
  id: Schema.String,
  kind: Schema.String,
  name: Schema.String,
  attributes: Schema.Record(Schema.String, Schema.Unknown),
}).annotate({ identifier: "Ai.Entity" })
export interface Entity extends Schema.Schema.Type<typeof Entity> {}
export const Page = Schema.Struct({
  items: Schema.Array(Entity),
  nextCursor: Schema.optional(Schema.String),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Ai.Page" })
export interface Page extends Schema.Schema.Type<typeof Page> {}
export const Summary = Schema.Struct({
  total: Schema.Int,
  counts: Schema.Record(Schema.String, Schema.Int),
}).annotate({ identifier: "Ai.Summary" })
export interface Summary extends Schema.Schema.Type<typeof Summary> {}
