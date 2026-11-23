// Lifecycle of the findings list: it shows skeleton rows while a load runs, on first open and on every refresh.
// Every load carries an attempt id, and a result for another attempt changes nothing.
export type FindingsState =
  | { type: "loading"; attempt: number }
  | { type: "ready"; attempt: number }
  | { type: "disposed" }

export type FindingsEvent = { type: "refresh" } | { type: "loaded"; attempt: number } | { type: "disposed" }

export const initial: FindingsState = { type: "loading", attempt: 1 }

export function transition(state: FindingsState, event: FindingsEvent): FindingsState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  // A refresh during a load keeps that load, so a double click starts one request.
  if (event.type === "refresh")
    return state.type === "loading" ? state : { type: "loading", attempt: state.attempt + 1 }
  if (state.type === "loading" && state.attempt === event.attempt) return { type: "ready", attempt: state.attempt }
  return state
}

export const selectLoading = (state: FindingsState) => state.type === "loading"
