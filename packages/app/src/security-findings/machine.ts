import type { Finding } from "./model"

// Lifecycle of the findings list. A load shows skeleton rows. "Load more" keeps the rows and fetches the next page by
// cursor. Every load carries an attempt id, and a result for another attempt changes nothing.
type Rows = readonly Finding[]

export type FindingsState =
  | { type: "loading"; attempt: number; rows: Rows; cursor?: string }
  | { type: "ready"; attempt: number; rows: Rows; next?: string; truncated: boolean }
  | {
      type: "failed"
      attempt: number
      rows: Rows
      /** `unavailable` means the server does not serve the findings API. */
      reason: "unavailable" | "error"
      cursor?: string
    }
  | { type: "disposed" }

export type FindingsEvent =
  | { type: "refresh" }
  /** The filters or sort changed. The loaded rows and cursor belong to the old query, so the load restarts. */
  | { type: "query" }
  | { type: "more" }
  | { type: "loaded"; attempt: number; rows: Rows; next?: string; truncated: boolean }
  | { type: "failed"; attempt: number; reason: "unavailable" | "error" }
  /** A status change returned the updated finding. */
  | { type: "patched"; finding: Finding }
  | { type: "disposed" }

export const initial: FindingsState = { type: "loading", attempt: 1, rows: [] }

export function transition(state: FindingsState, event: FindingsEvent): FindingsState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "query") return { type: "loading", attempt: state.attempt + 1, rows: [] }
  // A refresh during a load keeps that load, so a double click starts one request.
  if (event.type === "refresh")
    return state.type === "loading" ? state : { type: "loading", attempt: state.attempt + 1, rows: [] }
  if (event.type === "more") {
    const cursor = state.type === "ready" ? state.next : state.type === "failed" ? state.cursor : undefined
    return cursor === undefined ? state : { type: "loading", attempt: state.attempt + 1, rows: state.rows, cursor }
  }
  if (event.type === "patched")
    return state.rows.some((row) => row.id === event.finding.id)
      ? { ...state, rows: state.rows.map((row) => (row.id === event.finding.id ? event.finding : row)) }
      : state
  if (state.type !== "loading" || state.attempt !== event.attempt) return state
  if (event.type === "failed")
    return { type: "failed", attempt: state.attempt, rows: state.rows, reason: event.reason, cursor: state.cursor }
  return {
    type: "ready",
    attempt: state.attempt,
    rows: state.cursor === undefined ? event.rows : [...state.rows, ...event.rows],
    next: event.next,
    truncated: event.truncated,
  }
}

const NONE: Rows = []
/** Skeleton rows show only while the first page loads. */
export const selectLoading = (state: FindingsState) => state.type === "loading" && state.cursor === undefined
export const selectLoadingMore = (state: FindingsState) => state.type === "loading" && state.cursor !== undefined
export const selectRows = (state: FindingsState) => (state.type === "disposed" ? NONE : state.rows)
export const selectHasMore = (state: FindingsState) =>
  (state.type === "ready" && state.next !== undefined) || (state.type === "failed" && state.cursor !== undefined)
export const selectTruncated = (state: FindingsState) => state.type === "ready" && state.truncated
export const selectFailure = (state: FindingsState) => (state.type === "failed" ? state.reason : undefined)
