export * as Bom from "./bom.js"
import { Schema } from "effect"
// Mirrors the AI-BOM and Cloud-BOM documents of services/bellud/internal/api/bom.
export const Component = Schema.Struct({
  type: Schema.String,
  name: Schema.String,
  version: Schema.optional(Schema.String),
  licenses: Schema.optional(Schema.Array(Schema.String)),
  locations: Schema.optional(Schema.Array(Schema.String)),
  properties: Schema.optional(Schema.Record(Schema.String, Schema.String)),
}).annotate({ identifier: "Bom.Component" })
export interface Component extends Schema.Schema.Type<typeof Component> {}
export const Gap = Schema.Struct({
  provider: Schema.String,
  cause: Schema.String,
}).annotate({ identifier: "Bom.Gap" })
export interface Gap extends Schema.Schema.Type<typeof Gap> {}
export const Finding = Schema.Struct({
  ID: Schema.String,
  Rule: Schema.String,
  Severity: Schema.String,
  Component: Schema.String,
  Version: Schema.String,
  Message: Schema.String,
}).annotate({ identifier: "Bom.Finding" })
export interface Finding extends Schema.Schema.Type<typeof Finding> {}
export const Document = Schema.Struct({
  kind: Schema.String,
  components: Schema.Array(Component),
  incomplete: Schema.Array(Gap),
  findings: Schema.Array(Finding),
}).annotate({ identifier: "Bom.Document" })
export interface Document extends Schema.Schema.Type<typeof Document> {}
