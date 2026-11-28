import type { Job, Scanner } from "./model"

// Lifecycle of the scanner and job tables. A load shows skeleton rows. A poll reloads in the background and keeps the
// rows. Every load carries an attempt id, and a result for another attempt changes nothing.
export type ScansState =
  | { type: "loading"; attempt: number; scanners: readonly Scanner[]; jobs: readonly Job[] }
  | { type: "ready"; attempt: number; scanners: readonly Scanner[]; jobs: readonly Job[] }
  | { type: "failed"; attempt: number; reason: "unavailable" | "error"; scanners: readonly Scanner[]; jobs: readonly Job[] }
  | { type: "disposed" }

export type ScansEvent =
  | { type: "refresh" }
  | { type: "loaded"; attempt: number; scanners: readonly Scanner[]; jobs: readonly Job[] }
  | { type: "failed"; attempt: number; reason: "unavailable" | "error" }
  | { type: "disposed" }

export const initial: ScansState = { type: "loading", attempt: 1, scanners: [], jobs: [] }

export function transition(state: ScansState, event: ScansEvent): ScansState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "refresh")
    return state.type === "loading" ? state : { type: "loading", attempt: state.attempt + 1, scanners: state.scanners, jobs: state.jobs }
  if (state.type !== "loading" || state.attempt !== event.attempt) return state
  if (event.type === "failed")
    return { type: "failed", attempt: state.attempt, reason: event.reason, scanners: state.scanners, jobs: state.jobs }
  return { type: "ready", attempt: state.attempt, scanners: event.scanners, jobs: event.jobs }
}

export const selectFirstLoad = (state: ScansState) =>
  state.type === "loading" && state.scanners.length === 0 && state.jobs.length === 0
export const selectScanners = (state: ScansState) => (state.type === "disposed" ? [] : state.scanners)
export const selectJobs = (state: ScansState) => (state.type === "disposed" ? [] : state.jobs)
export const selectFailure = (state: ScansState) => (state.type === "failed" ? state.reason : undefined)
/** True while any job is queued or running, which keeps the 5 s poll going. */
export const selectPolling = (state: ScansState) => state.type !== "disposed" && state.jobs.some((job) => job.status === "queued" || job.status === "running")

// Lifecycle of the user's actions: run a scan, cancel a job, save a schedule. One action runs at a time. A 400 or 409
// shows its message inline next to the form that caused it.
export type Action =
  | { name: "enqueue"; kind: string; targetType: string; targetId: string }
  | { name: "cancel"; id: string }
  | { name: "schedule"; kind: string; targetType: string; intervalSeconds: number; enabled: boolean }

export type ActionState =
  | { type: "idle" }
  | { type: "busy"; attempt: number; action: Action }
  | { type: "done"; attempt: number; action: Action["name"] }
  | { type: "rejected"; attempt: number; action: Action["name"]; message: string }
  | { type: "disposed" }

export type ActionEvent =
  | { type: "submit"; action: Action }
  | { type: "succeeded"; attempt: number }
  | { type: "rejected"; attempt: number; message: string }
  | { type: "dismiss" }
  | { type: "disposed" }

export const idle: ActionState = { type: "idle" }

const attemptOf = (state: ActionState) => (state.type === "idle" || state.type === "disposed" ? 0 : state.attempt)

export function transitionAction(state: ActionState, event: ActionEvent): ActionState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "submit") {
    if (state.type === "busy") return state
    return { type: "busy", attempt: attemptOf(state) + 1, action: event.action }
  }
  if (event.type === "dismiss") return state.type === "done" || state.type === "rejected" ? idle : state
  if (state.type !== "busy" || state.attempt !== event.attempt) return state
  if (event.type === "succeeded") return { type: "done", attempt: state.attempt, action: state.action.name }
  return { type: "rejected", attempt: state.attempt, action: state.action.name, message: event.message }
}

export const selectBusy = (state: ActionState) => state.type === "busy"
export const selectCancelling = (state: ActionState, id: string) =>
  state.type === "busy" && state.action.name === "cancel" && state.action.id === id
export const selectMessage = (state: ActionState, name: Action["name"]) =>
  state.type === "rejected" && state.action === name ? state.message : undefined
export const selectSaved = (state: ActionState, name: Action["name"]) => state.type === "done" && state.action === name
