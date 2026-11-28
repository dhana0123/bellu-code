export * as Runtime from "./runtime.js"

import { Schema } from "effect"
import { optional } from "./schema.js"

// Mirrors services/bellud/internal/api/runtime and internal/runtimeevents/wire.
export const EventType = Schema.Literals([
  "process_exec",
  "network_connect",
  "file_write",
  "shell_spawn",
  "privilege_change",
  "container_escape",
]).annotate({ identifier: "Runtime.EventType" })
export type EventType = typeof EventType.Type

export const Event = Schema.Struct({
  ts: Schema.String,
  type: Schema.String,
  node: Schema.String,
  namespace: optional(Schema.String),
  pod: optional(Schema.String),
  container_id: optional(Schema.String),
  process_path: optional(Schema.String),
  args: optional(Schema.String),
  user: optional(Schema.String),
  unavailable: optional(Schema.Array(Schema.String)),
}).annotate({ identifier: "Runtime.Event" })
export interface Event extends Schema.Schema.Type<typeof Event> {}

export const StoredEvent = Schema.Struct({
  seq: Schema.Int,
  ...Event.fields,
}).annotate({ identifier: "Runtime.StoredEvent" })
export interface StoredEvent extends Schema.Schema.Type<typeof StoredEvent> {}

export const EventPage = Schema.Struct({
  items: Schema.Array(StoredEvent),
  nextCursor: optional(Schema.String),
  truncated: Schema.Boolean,
}).annotate({ identifier: "Runtime.EventPage" })
export interface EventPage extends Schema.Schema.Type<typeof EventPage> {}

export const Sensor = Schema.Struct({
  node: Schema.String,
  status: Schema.String,
  reason: optional(Schema.String),
  drops: Schema.Record(Schema.String, Schema.Int),
  rejectedTotal: Schema.Int,
  seenAt: Schema.String,
}).annotate({ identifier: "Runtime.Sensor" })
export interface Sensor extends Schema.Schema.Type<typeof Sensor> {}

export const Status = Schema.Struct({
  sensors: Schema.Array(Sensor),
  rejectedTotal: Schema.Int,
}).annotate({ identifier: "Runtime.Status" })
export interface Status extends Schema.Schema.Type<typeof Status> {}
