export * as Scans from "./scans.js"
import { Schema } from "effect"
import { optional } from "./schema.js"
// Mirrors services/bellud/internal/api/scans. Timestamps are RFC 3339 strings produced by the Go server.
export const Kind = Schema.Literals([
  "sbom",
  "vulnerability",
  "misconfiguration",
  "secret",
  "posture",
  "data_classification",
  "ai_inventory",
]).annotate({ identifier: "Scans.Kind" })
export type Kind = typeof Kind.Type
export const TargetType = Schema.Literals(["repository", "image", "host", "cloud_account", "cluster"]).annotate({
  identifier: "Scans.TargetType",
})
export type TargetType = typeof TargetType.Type
export const Status = Schema.Literals([
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "skipped_unchanged",
]).annotate({ identifier: "Scans.Status" })
export type Status = typeof Status.Type
export const TargetID = Schema.String.annotate({ identifier: "Scans.TargetID" }).check(
  Schema.isNonEmpty(),
  Schema.isMaxLength(512),
)
export type TargetID = typeof TargetID.Type
export const Job = Schema.Struct({
  id: Schema.String,
  kind: Kind,
  targetType: TargetType,
  targetId: Schema.String,
  status: Status,
  reason: optional(Schema.String),
  queuedAt: Schema.String,
  startedAt: optional(Schema.String),
  endedAt: optional(Schema.String),
  created: Schema.Int,
  updated: Schema.Int,
  resolved: Schema.Int,
  durationMs: optional(Schema.Int),
  scannerVersions: Schema.Record(Schema.String, Schema.String),
}).annotate({ identifier: "Scans.Job" })
export interface Job extends Schema.Schema.Type<typeof Job> {}
export const JobPage = Schema.Struct({
  items: Schema.Array(Job),
  nextCursor: optional(Schema.String),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Scans.JobPage" })
export interface JobPage extends Schema.Schema.Type<typeof JobPage> {}
export const Scanner = Schema.Struct({
  name: Schema.String,
  kind: Kind,
  version: Schema.String,
  license: Schema.String,
  libraries: optional(Schema.Record(Schema.String, Schema.String)),
  lastRun: optional(Job),
}).annotate({ identifier: "Scans.Scanner" })
export interface Scanner extends Schema.Schema.Type<typeof Scanner> {}
export const ScannerPage = Schema.Struct({
  items: Schema.Array(Scanner),
  nextCursor: optional(Schema.String),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Scans.ScannerPage" })
export interface ScannerPage extends Schema.Schema.Type<typeof ScannerPage> {}
export const EnqueueInput = Schema.Struct({
  kind: Kind,
  targetType: TargetType,
  targetId: TargetID,
}).annotate({ identifier: "Scans.EnqueueInput" })
export interface EnqueueInput extends Schema.Schema.Type<typeof EnqueueInput> {}
export const ScheduleInput = Schema.Struct({
  kind: Kind,
  targetType: TargetType,
  intervalSeconds: Schema.Int.check(Schema.isBetween({ minimum: 900, maximum: 2592000 })),
  enabled: Schema.Boolean,
}).annotate({ identifier: "Scans.ScheduleInput" })
export interface ScheduleInput extends Schema.Schema.Type<typeof ScheduleInput> {}
export const Schedule = Schema.Struct({
  kind: Kind,
  targetType: TargetType,
  targetId: Schema.String,
  intervalSeconds: Schema.Int,
  enabled: Schema.Boolean,
}).annotate({ identifier: "Scans.Schedule" })
export interface Schedule extends Schema.Schema.Type<typeof Schedule> {}
