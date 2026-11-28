import { Schema } from "effect"
import { Persistence } from "@/runtime/persistence/schema"
import { Persist, persisted } from "@/runtime/persistence/storage"

// Lifecycle of the graph page: pick a lens, fetch its slice, draw it. Switching lens keeps the rendered graph until the
// next slice arrives. Every slice request carries an attempt id, and a result for another attempt changes nothing.
export type FailureReason = "webgl" | "layout"
export type GraphState =
  | { type: "loading"; attempt: number; lens: string }
  | {
      type: "ready"
      attempt: number
      lens: string
      pending?: { attempt: number; lens: string }
      error?: "slice"
      follow: boolean
    }
  | { type: "failed"; reason: FailureReason }
  | { type: "disposed" }

export type GraphEvent =
  | { type: "lenses-loaded"; stored: string | undefined; lenses: readonly string[]; defaultLens: string }
  | { type: "select"; lens: string }
  | { type: "loaded"; attempt: number }
  | { type: "slice-failed"; attempt: number }
  | { type: "failed"; reason: FailureReason }
  | { type: "panned" }
  | { type: "follow"; on: boolean }
  | { type: "disposed" }

export type GraphEffect = { type: "fetch-slice"; attempt: number; lens: string } | { type: "persist-lens"; lens: string }

export type GraphTransition = { state: GraphState; effects: readonly GraphEffect[] }

const NONE: readonly GraphEffect[] = Object.freeze([])
const DISPOSED = Object.freeze<GraphState>({ type: "disposed" })
const FAILED: Record<FailureReason, GraphState> = {
  webgl: Object.freeze<GraphState>({ type: "failed", reason: "webgl" }),
  layout: Object.freeze<GraphState>({ type: "failed", reason: "layout" }),
}

/** Waits for the lens list: `lenses-loaded` starts attempt 1. */
export const initial: GraphState = Object.freeze<GraphState>({ type: "loading", attempt: 0, lens: "" })

export function resolveLens(stored: string | undefined, lenses: readonly string[], defaultLens: string) {
  return stored !== undefined && lenses.includes(stored) ? stored : defaultLens
}

/** A result that arrives after the page closed, or for an attempt that is no longer current, changes nothing. */
export function transition(state: GraphState, event: GraphEvent): GraphTransition {
  if (state.type === "disposed") return same(state)
  if (event.type === "disposed") return { state: DISPOSED, effects: NONE }
  if (state.type === "failed") return same(state)

  if (state.type === "loading") {
    if (event.type === "failed") return { state: FAILED[event.reason], effects: NONE }
    if (event.type === "lenses-loaded") {
      if (state.attempt !== 0) return same(state)
      const lens = resolveLens(event.stored, event.lenses, event.defaultLens)
      return {
        state: { type: "loading", attempt: 1, lens },
        effects: [{ type: "fetch-slice", attempt: 1, lens }],
      }
    }
    if (event.type === "loaded") {
      if (event.attempt !== state.attempt) return same(state)
      return {
        state: { type: "ready", attempt: state.attempt, lens: state.lens, follow: false },
        effects: state.lens ? [{ type: "persist-lens", lens: state.lens }] : NONE,
      }
    }
    // The first slice has nothing to fall back to.
    if (event.type === "slice-failed" && event.attempt === state.attempt) {
      return { state: FAILED.layout, effects: NONE }
    }
    return same(state)
  }

  switch (event.type) {
    case "failed":
      return { state: FAILED[event.reason], effects: NONE }
    case "select": {
      if (event.lens === state.lens && !state.pending) return same(state)
      if (state.pending?.lens === event.lens) return same(state)
      const attempt = (state.pending?.attempt ?? state.attempt) + 1
      return {
        state: { ...state, pending: { attempt, lens: event.lens }, error: undefined },
        effects: [{ type: "fetch-slice", attempt, lens: event.lens }],
      }
    }
    case "loaded": {
      if (event.attempt !== state.pending?.attempt) return same(state)
      return {
        state: {
          type: "ready",
          attempt: state.pending.attempt,
          lens: state.pending.lens,
          follow: state.follow,
        },
        effects: [{ type: "persist-lens", lens: state.pending.lens }],
      }
    }
    case "slice-failed": {
      if (event.attempt !== state.pending?.attempt) return same(state)
      return {
        state: { type: "ready", attempt: state.attempt, lens: state.lens, error: "slice", follow: state.follow },
        effects: NONE,
      }
    }
    case "panned":
      if (!state.follow) return same(state)
      return { state: { ...state, follow: false }, effects: NONE }
    case "follow":
      if (state.follow === event.on) return same(state)
      return { state: { ...state, follow: event.on }, effects: NONE }
    default:
      return same(state)
  }
}

function same(state: GraphState): GraphTransition {
  return { state, effects: NONE }
}

export const selectLoading = (state: GraphState) => state.type === "loading"
export const selectFailure = (state: GraphState) => (state.type === "failed" ? state.reason : undefined)
export const selectSwitching = (state: GraphState) => state.type === "ready" && state.pending !== undefined
export const selectSliceError = (state: GraphState) => (state.type === "ready" ? state.error : undefined)
export const selectFollow = (state: GraphState) => state.type === "ready" && state.follow
export const selectActiveLens = (state: GraphState) =>
  state.type === "loading" || state.type === "ready" ? state.lens : undefined

const LensSchema = Persistence.struct({ lens: Persistence.fallback(Schema.String, () => "") })

/** The last lens that rendered, restored on the next visit. An empty string means none. */
export function createLensStorage() {
  return persisted(Persist.global("security-graph.lens"), LensSchema, { lens: "" })
}
