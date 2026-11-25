export * as Rules from "./rules.js"
import { Schema } from "effect"
import { Overview } from "./overview.js"
import { optional } from "./schema.js"

// Mirrors services/bellud/internal/api/rules.
export const ID = Schema.String.annotate({ identifier: "Rules.ID" }).check(Schema.isNonEmpty(), Schema.isMaxLength(256))
export type ID = typeof ID.Type

export const Severity = Overview.Severity
export type Severity = Overview.Severity

export const Kind = Schema.Literals(["posture", "toxic_combination", "runtime", "identity"]).annotate({
  identifier: "Rules.Kind",
})
export type Kind = typeof Kind.Type

export const ControlStatus = Schema.Literals(["pass", "fail", "not_applicable", "error"]).annotate({
  identifier: "Rules.ControlStatus",
})
export type ControlStatus = typeof ControlStatus.Type

export const Pack = Schema.Struct({
  id: Schema.String,
  version: Schema.String,
  enabled: Schema.Boolean,
  ruleCount: Schema.Int,
}).annotate({ identifier: "Rules.Pack" })
export interface Pack extends Schema.Schema.Type<typeof Pack> {}

export const PackList = Schema.Struct({ items: Schema.Array(Pack) }).annotate({ identifier: "Rules.PackList" })
export interface PackList extends Schema.Schema.Type<typeof PackList> {}

export const Rule = Schema.Struct({
  id: Schema.String,
  packId: Schema.String,
  title: Schema.String,
  description: Schema.String,
  kind: Kind,
  category: Schema.String,
  appliesTo: Schema.Array(Schema.String),
  benchmarks: Schema.Array(Schema.String),
  enabled: Schema.Boolean,
  severity: Severity,
  defaultSeverity: Severity,
}).annotate({ identifier: "Rules.Rule" })
export interface Rule extends Schema.Schema.Type<typeof Rule> {}

export const RuleList = Schema.Struct({ items: Schema.Array(Rule) }).annotate({ identifier: "Rules.RuleList" })
export interface RuleList extends Schema.Schema.Type<typeof RuleList> {}

export const OverrideInput = Schema.Struct({
  packId: ID,
  ruleId: optional(Schema.String.check(Schema.isMaxLength(256))),
  enabled: optional(Schema.Boolean),
  severity: optional(Severity),
}).annotate({ identifier: "Rules.OverrideInput" })
export interface OverrideInput extends Schema.Schema.Type<typeof OverrideInput> {}

/** A pack when the override has no ruleId, otherwise the overridden rule. */
export const OverrideResult = Schema.Union([Pack, Rule]).annotate({ identifier: "Rules.OverrideResult" })
export type OverrideResult = typeof OverrideResult.Type

export const Control = Schema.Struct({
  control: Schema.String,
  status: ControlStatus,
  failingEntities: Schema.Int,
}).annotate({ identifier: "Rules.Control" })
export interface Control extends Schema.Schema.Type<typeof Control> {}

export const BenchmarkList = Schema.Struct({ benchmarks: Schema.Array(Schema.String) }).annotate({
  identifier: "Rules.BenchmarkList",
})
export interface BenchmarkList extends Schema.Schema.Type<typeof BenchmarkList> {}

export const Compliance = Schema.Struct({
  benchmark: Schema.String,
  controls: Schema.Array(Control),
}).annotate({ identifier: "Rules.Compliance" })
export interface Compliance extends Schema.Schema.Type<typeof Compliance> {}

/** The benchmark names when no benchmark is requested, otherwise the controls of that benchmark. */
export const ComplianceResult = Schema.Union([BenchmarkList, Compliance]).annotate({ identifier: "Rules.ComplianceResult" })
export type ComplianceResult = typeof ComplianceResult.Type
