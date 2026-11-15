// Lifecycle of the graph page: the layout runs first, then the canvas is drawn. Nothing else changes the phase.
export type FailureReason = "webgl" | "layout"
export type GraphState =
  | { type: "loading" }
  | { type: "ready" }
  | { type: "failed"; reason: FailureReason }
  | { type: "disposed" }
export type GraphEvent = { type: "loaded" } | { type: "failed"; reason: FailureReason } | { type: "disposed" }

const LOADING = Object.freeze<GraphState>({ type: "loading" })
const READY = Object.freeze<GraphState>({ type: "ready" })
const DISPOSED = Object.freeze<GraphState>({ type: "disposed" })
const FAILED: Record<FailureReason, GraphState> = {
  webgl: Object.freeze<GraphState>({ type: "failed", reason: "webgl" }),
  layout: Object.freeze<GraphState>({ type: "failed", reason: "layout" }),
}

export const initial: GraphState = LOADING

/** A result that arrives after the page closed, or after the first outcome, changes nothing. */
export function transition(state: GraphState, event: GraphEvent): GraphState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return DISPOSED
  if (state.type !== "loading") return state
  if (event.type === "loaded") return READY
  return FAILED[event.reason]
}

export const selectLoading = (state: GraphState) => state.type === "loading"
export const selectFailure = (state: GraphState) => (state.type === "failed" ? state.reason : undefined)
