import { Scans } from "@bellucode/schema/scans"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/http-api"
import { ConflictError, InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, ConflictError, UnknownError] as const
const IDParams = { id: Scans.TargetID }

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.scans.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.scans`: routes under /api/experimental/scans, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalScansGroup = HttpApiGroup.make("server.scans")
  .add(
    HttpApiEndpoint.post("enqueue", "/api/experimental/scans", {
      payload: Scans.EnqueueInput,
      success: Scans.Job.pipe(HttpApiSchema.status(202)),
      error: errors,
    }).annotateMerge(
      experimental(
        "enqueue",
        "Enqueue scan",
        "Queue a scan of one target and return the queued job. Answers 400 when the kind does not apply to the target or the target is unknown, and 409 when the queue for the target is full.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.get("list", "/api/experimental/scans", {
      query: {
        status: Schema.optional(Scans.Status).annotate({ description: "Only jobs with this status." }),
        kind: Schema.optional(Scans.Kind).annotate({ description: "Only jobs of this scan kind." }),
        limit: Schema.optional(
          Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 500 })))),
        ).annotate({ description: "Maximum number of jobs to return (1-500)." }),
      },
      success: Scans.JobPage,
      error: errors,
    }).annotateMerge(experimental("list", "List scans", "List scan jobs, newest first, optionally filtered by status and kind.")),
  )
  .add(
    HttpApiEndpoint.get("scanners", "/api/experimental/scans/scanners", {
      success: Scans.ScannerPage,
      error: errors,
    }).annotateMerge(
      experimental(
        "scanners",
        "List scanners",
        "List the registered scanner adapters with version, license and the most recent run of each kind.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.get("get", "/api/experimental/scans/:id", {
      params: IDParams,
      success: Scans.Job,
      error: errors,
    }).annotateMerge(experimental("get", "Get scan", "Get one scan job.")),
  )
  .add(
    HttpApiEndpoint.post("cancel", "/api/experimental/scans/:id/cancel", {
      params: IDParams,
      success: Scans.Job,
      error: errors,
    }).annotateMerge(
      experimental(
        "cancel",
        "Cancel scan",
        "Cancel a queued or running scan job and return it. Answers 409 when the job is neither queued nor running.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.put("schedule", "/api/experimental/scans/schedules/:id", {
      params: IDParams,
      payload: Scans.ScheduleInput,
      success: Scans.Schedule,
      error: errors,
    }).annotateMerge(
      experimental(
        "schedule",
        "Set scan schedule",
        "Create or replace the recurring schedule for a target. The path id is the target id; the interval is 900 to 2592000 seconds.",
      ),
    ),
  )
