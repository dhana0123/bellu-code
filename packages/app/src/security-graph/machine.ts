// Interaction machine for the Security Graph view. One pure `transition(model, event)` owns the interaction state and
// the back/forward history. The driver (`driver.ts`) turns pointer, key and rAF input into events and runs effects.
//
// Animations: an `animating` state names its run with `attempt`. The expand, collapse and focus effects carry that
// attempt and the driver echoes it in `anim-done`, so the result of a superseded or cancelled run is ignored. The
// state always ends: through `anim-done`, `escape` (which emits `cancel-animation`) or `reset`. The driver must also
// stop its running animation on `reset`.

// A camera target hint (graph coordinates and zoom ratio) the driver may use to place the camera on a focus.
export type Camera = { readonly x: number; readonly y: number; readonly ratio: number }

// A state the user rests in. Pan and drag return to it, so a selection survives a gesture.
export type Resting =
  | { readonly type: "idle" }
  | { readonly type: "hovering"; readonly id: string }
  | { readonly type: "selected"; readonly id: string; readonly hover?: string }
  | { readonly type: "focused"; readonly id: string }

export type State =
  | { readonly type: "idle" }
  | { readonly type: "hovering"; readonly id: string }
  | { readonly type: "panning"; readonly resume: Resting }
  | { readonly type: "dragging"; readonly id: string; readonly resume: Resting }
  | { readonly type: "selected"; readonly id: string; readonly hover?: string }
  | { readonly type: "focused"; readonly id: string }
  | {
      readonly type: "animating"
      readonly kind: "expand" | "collapse" | "focus"
      readonly id: string
      readonly attempt: number
      // The state to enter when the animation completes.
      readonly next: Resting
    }

export type Event =
  | { readonly type: "hover"; readonly id?: string }
  // `badge` marks a click on the count badge. `expanded` is the node's current expansion, so the machine can pick
  // expand or collapse without knowing the projection.
  | { readonly type: "click"; readonly id: string; readonly badge: boolean; readonly expanded: boolean }
  | { readonly type: "dblclick"; readonly id: string; readonly camera?: Camera }
  | { readonly type: "pan-start" }
  | { readonly type: "pan-end" }
  | { readonly type: "drag-start"; readonly id: string }
  | { readonly type: "drag-end" }
  | { readonly type: "anim-done"; readonly attempt: number }
  | { readonly type: "back" }
  | { readonly type: "forward" }
  | { readonly type: "reset" }
  | { readonly type: "fit" }
  | { readonly type: "escape" }

export type Effect =
  | { readonly type: "select"; readonly id: string }
  | { readonly type: "expand"; readonly id: string; readonly attempt: number }
  | { readonly type: "collapse"; readonly id: string; readonly attempt: number }
  | { readonly type: "focus"; readonly id: string; readonly attempt: number; readonly camera?: Camera }
  | { readonly type: "cancel-animation" }
  | { readonly type: "fit" }
  | { readonly type: "reset" }

// One graph context the user can return to.
export type HistoryEntry = { readonly id: string; readonly camera?: Camera }

// `index` is the current entry, or -1 when the history is empty.
export type History = { readonly entries: readonly HistoryEntry[]; readonly index: number }

export type Model = {
  readonly state: State
  readonly history: History
  // The last animation attempt issued. It only grows, so an old attempt never matches a later run.
  readonly attempt: number
}

export type Transition = { readonly model: Model; readonly effects: readonly Effect[] }

const NONE: readonly Effect[] = Object.freeze([])
const FIT: readonly Effect[] = Object.freeze([{ type: "fit" }])
const IDLE: State = Object.freeze({ type: "idle" })

export const INITIAL_MODEL: Model = Object.freeze({
  state: IDLE,
  history: Object.freeze({ entries: Object.freeze([]), index: -1 }),
  attempt: 0,
})

export function transition(model: Model, event: Event): Transition {
  const state = model.state
  switch (event.type) {
    case "hover":
      return hover(model, state, event.id)
    case "click":
      if (!isResting(state)) return unchanged(model)
      return event.badge ? toggle(model, state, event.id, event.expanded) : select(model, state, event.id)
    case "dblclick":
      if (!isResting(state)) return unchanged(model)
      if (state.type === "focused" && state.id === event.id) return unchanged(model)
      return focus(model, event.id, event.camera, pushHistory(model.history, { id: event.id, camera: event.camera }))
    case "pan-start":
      if (!isResting(state)) return unchanged(model)
      return moved(model, { type: "panning", resume: state })
    case "pan-end":
      if (state.type !== "panning") return unchanged(model)
      return moved(model, state.resume)
    case "drag-start":
      if (!isResting(state)) return unchanged(model)
      return moved(model, { type: "dragging", id: event.id, resume: state })
    case "drag-end":
      if (state.type !== "dragging") return unchanged(model)
      return moved(model, state.resume)
    case "anim-done":
      if (state.type !== "animating" || state.attempt !== event.attempt) return unchanged(model)
      return moved(model, state.next)
    case "back":
      return step(model, -1)
    case "forward":
      return step(model, 1)
    case "fit":
      return { model, effects: FIT }
    case "reset":
      return reset(model)
    case "escape":
      return escape(model, state)
  }
}

function isResting(state: State): state is Resting {
  return (
    state.type === "idle" || state.type === "hovering" || state.type === "selected" || state.type === "focused"
  )
}

function unchanged(model: Model): Transition {
  return { model, effects: NONE }
}

function moved(model: Model, state: State, effects: readonly Effect[] = NONE): Transition {
  return { model: { ...model, state }, effects }
}

function hover(model: Model, state: State, id: string | undefined): Transition {
  switch (state.type) {
    case "idle":
      return id === undefined ? unchanged(model) : moved(model, { type: "hovering", id })
    case "hovering":
      if (id === state.id) return unchanged(model)
      return moved(model, id === undefined ? IDLE : { type: "hovering", id })
    case "selected":
      if (id === state.hover) return unchanged(model)
      return moved(model, id === undefined ? { type: "selected", id: state.id } : { type: "selected", id: state.id, hover: id })
    default:
      return unchanged(model)
  }
}

function select(model: Model, state: Resting, id: string): Transition {
  if ((state.type === "selected" || state.type === "focused") && state.id === id) return unchanged(model)
  return moved(model, { type: "selected", id }, [{ type: "select", id }])
}

function toggle(model: Model, state: Resting, id: string, expanded: boolean): Transition {
  const attempt = model.attempt + 1
  const kind = expanded ? "collapse" : "expand"
  // A focus survives an expansion; any other state settles on the toggled node.
  const next: Resting = state.type === "focused" ? state : { type: "selected", id }
  return {
    model: { ...model, attempt, state: { type: "animating", kind, id, attempt, next } },
    effects: [{ type: kind, id, attempt }],
  }
}

function focus(model: Model, id: string, camera: Camera | undefined, history: History): Transition {
  const attempt = model.attempt + 1
  return {
    model: {
      state: { type: "animating", kind: "focus", id, attempt, next: { type: "focused", id } },
      history,
      attempt,
    },
    effects: [{ type: "focus", id, attempt, camera }],
  }
}

function pushHistory(history: History, entry: HistoryEntry): History {
  const current = history.entries[history.index]
  // Focusing the node the history already sits on adds nothing.
  if (current !== undefined && current.id === entry.id) return history
  const entries = [...history.entries.slice(0, history.index + 1), entry]
  return { entries, index: entries.length - 1 }
}

function step(model: Model, delta: -1 | 1): Transition {
  const state = model.state
  if (!isResting(state) && state.type !== "animating") return unchanged(model)
  const index = model.history.index + delta
  const entry = model.history.entries[index]
  if (entry === undefined) return unchanged(model)
  return focus(model, entry.id, entry.camera, { entries: model.history.entries, index })
}

function reset(model: Model): Transition {
  const effects: readonly Effect[] = [{ type: "reset" }]
  if (model.state.type === "idle" && model.history.index === -1) return { model, effects }
  return { model: { ...model, state: IDLE, history: INITIAL_MODEL.history }, effects }
}

function escape(model: Model, state: State): Transition {
  switch (state.type) {
    case "hovering":
    case "selected":
    case "focused":
      return moved(model, IDLE)
    case "animating":
      return moved(model, IDLE, [{ type: "cancel-animation" }])
    default:
      return unchanged(model)
  }
}
