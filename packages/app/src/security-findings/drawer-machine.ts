import type { Status, StatusEvent } from "./model"

// Lifecycle of the detail drawer: which finding is open, the load of its status history, and a status change in
// flight. Each open carries an attempt id, and a result for another open changes nothing.
export type StatusRequest = { status: Status; reason?: string; until?: string }

export type DrawerState =
  | { type: "closed"; attempt: number }
  | {
      type: "open"
      attempt: number
      id: string
      /** The status the form starts on, for example `ignored` when the row menu asked to ignore. */
      intent?: Status
      history: { type: "loading" } | { type: "ready"; events: readonly StatusEvent[] } | { type: "failed" }
      save:
        | { type: "idle" }
        | { type: "saving"; request: StatusRequest }
        /** The server refused the change. `field` names the parameter of a 400. */
        | { type: "rejected"; field?: string; message: string }
    }

export type DrawerEvent =
  | { type: "open"; id: string; intent?: Status }
  | { type: "close" }
  | { type: "history-loaded"; attempt: number; events: readonly StatusEvent[] }
  | { type: "history-failed"; attempt: number }
  | { type: "save"; request: StatusRequest }
  | { type: "saved"; attempt: number; events: readonly StatusEvent[] }
  | { type: "save-failed"; attempt: number; field?: string; message: string }

export const initial: DrawerState = { type: "closed", attempt: 0 }

export function transition(state: DrawerState, event: DrawerEvent): DrawerState {
  if (event.type === "open")
    return {
      type: "open",
      attempt: state.attempt + 1,
      id: event.id,
      intent: event.intent,
      history: { type: "loading" },
      save: { type: "idle" },
    }
  if (state.type === "closed") return state
  if (event.type === "close") return { type: "closed", attempt: state.attempt }
  // A second submit while one is in flight starts nothing.
  if (event.type === "save")
    return state.save.type === "saving" ? state : { ...state, save: { type: "saving", request: event.request } }
  if (event.attempt !== state.attempt) return state
  if (event.type === "history-loaded") return { ...state, history: { type: "ready", events: event.events } }
  if (event.type === "history-failed") return { ...state, history: { type: "failed" } }
  if (event.type === "saved") return { ...state, history: { type: "ready", events: event.events }, save: { type: "idle" } }
  if (state.save.type !== "saving") return state
  return { ...state, save: { type: "rejected", field: event.field, message: event.message } }
}

export const selectOpenId = (state: DrawerState) => (state.type === "open" ? state.id : undefined)
export const selectSaving = (state: DrawerState) => state.type === "open" && state.save.type === "saving"
