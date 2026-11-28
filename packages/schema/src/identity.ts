export * as Identity from "./identity.js"
import { Schema } from "effect"
import { optional } from "./schema.js"
// Mirrors services/bellud/internal/api/identity.
export const Hop = Schema.Struct({
  from: Schema.String,
  to: Schema.String,
  relation: Schema.String,
  evidence: optional(Schema.String),
  inferred: optional(Schema.Boolean),
}).annotate({ identifier: "Identity.Hop" })
export interface Hop extends Schema.Schema.Type<typeof Hop> {}
export const Path = Schema.Struct({
  source: Schema.String,
  target: Schema.String,
  unreachable: Schema.Boolean,
  inferred: optional(Schema.Boolean),
  path: Schema.Array(Hop),
}).annotate({ identifier: "Identity.Path" })
export interface Path extends Schema.Schema.Type<typeof Path> {}
export const Paths = Schema.Struct({
  from: Schema.String,
  to: Schema.String,
  paths: Schema.Array(Path),
}).annotate({ identifier: "Identity.Paths" })
export interface Paths extends Schema.Schema.Type<typeof Paths> {}
