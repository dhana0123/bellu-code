import { describe, expect, test } from "bun:test"
import { INITIAL_MODEL, transition, type Event, type Model } from "./machine"

const run = (events: readonly Event[], from: Model = INITIAL_MODEL) =>
  events.reduce((model, event) => transition(model, event).model, from)

const click = (id: string, badge = false, expanded = false): Event => ({ type: "click", id, badge, expanded })
const dblclick = (id: string): Event => ({ type: "dblclick", id })

// Replays focus sequences with the real attempt numbers.
function focused(...ids: string[]) {
  return ids.reduce((model, id) => {
    const started = transition(model, dblclick(id)).model
    return transition(started, { type: "anim-done", attempt: started.attempt }).model
  }, INITIAL_MODEL)
}

describe("security graph machine", () => {
  test("click selects a node and emits select; clicking it again is a no-op", () => {
    const first = transition(INITIAL_MODEL, click("a"))
    expect(first.model.state).toEqual({ type: "selected", id: "a" })
    expect(first.effects).toEqual([{ type: "select", id: "a" }])

    const again = transition(first.model, click("a"))
    expect(again.model).toBe(first.model)
    expect(again.effects).toEqual([])
  })

  test("badge click expands a collapsed node and collapses an expanded one, then settles on selected", () => {
    const expand = transition(INITIAL_MODEL, click("a", true, false))
    expect(expand.effects).toEqual([{ type: "expand", id: "a", attempt: 1 }])
    expect(expand.model.state).toMatchObject({ type: "animating", kind: "expand", id: "a", attempt: 1 })
    expect(transition(expand.model, { type: "anim-done", attempt: 1 }).model.state).toEqual({
      type: "selected",
      id: "a",
    })

    const collapse = transition(INITIAL_MODEL, click("a", true, true))
    expect(collapse.effects).toEqual([{ type: "collapse", id: "a", attempt: 1 }])
  })

  test("badge click while focused keeps the focus after the animation", () => {
    const model = focused("f")
    const toggled = transition(model, click("x", true, false)).model
    const done = transition(toggled, { type: "anim-done", attempt: toggled.attempt }).model
    expect(done.state).toEqual({ type: "focused", id: "f" })
  })

  test("double click focuses with history push, camera and a new attempt", () => {
    const camera = { x: 1, y: 2, ratio: 0.5 }
    const result = transition(INITIAL_MODEL, { type: "dblclick", id: "a", camera })
    expect(result.effects).toEqual([{ type: "focus", id: "a", attempt: 1, camera }])
    expect(result.model.history).toEqual({ entries: [{ id: "a", camera }], index: 0 })
    expect(result.model.state).toMatchObject({ type: "animating", kind: "focus", next: { type: "focused", id: "a" } })
  })

  test("pan and drag return to the prior resting state", () => {
    const selected = run([click("a")])
    expect(run([{ type: "pan-start" }, { type: "pan-end" }], selected).state).toEqual({ type: "selected", id: "a" })
    expect(run([{ type: "drag-start", id: "n" }, { type: "drag-end" }], selected).state).toEqual({
      type: "selected",
      id: "a",
    })
    const panning = run([{ type: "pan-start" }], selected)
    expect(panning.state).toMatchObject({ type: "panning" })
    // A click during a gesture does not change state.
    expect(transition(panning, click("b")).model).toBe(panning)
  })

  test("anim-done with the current attempt completes; a stale attempt is ignored", () => {
    const animating = transition(INITIAL_MODEL, dblclick("a")).model
    const stale = transition(animating, { type: "anim-done", attempt: animating.attempt - 1 })
    expect(stale.model).toBe(animating)
    expect(stale.effects).toEqual([])
    expect(transition(animating, { type: "anim-done", attempt: animating.attempt }).model.state).toEqual({
      type: "focused",
      id: "a",
    })
  })

  test("a cancelled run's completion cannot finish the newer run", () => {
    const first = transition(INITIAL_MODEL, dblclick("a")).model
    const cancelled = transition(first, { type: "escape" }).model
    const next = transition(cancelled, dblclick("b")).model
    expect(next.attempt).toBeGreaterThan(first.attempt)
    expect(transition(next, { type: "anim-done", attempt: first.attempt }).model).toBe(next)
  })

  test("back and forward restore entries; the ends are no-ops", () => {
    const camera = { x: 3, y: 4, ratio: 2 }
    const start = run([{ type: "dblclick", id: "a", camera }, { type: "anim-done", attempt: 1 }])
    const model = focused("a", "b")
    expect(model.history.index).toBe(1)

    expect(transition(start, { type: "back" }).model).toBe(start)
    expect(transition(model, { type: "forward" }).model).toBe(model)

    const back = transition(model, { type: "back" })
    expect(back.model.history.index).toBe(0)
    expect(back.effects).toEqual([{ type: "focus", id: "a", attempt: back.model.attempt, camera: undefined }])
    const settled = transition(back.model, { type: "anim-done", attempt: back.model.attempt }).model
    expect(settled.state).toEqual({ type: "focused", id: "a" })

    const forward = transition(settled, { type: "forward" })
    expect(forward.model.history.index).toBe(1)
    expect(forward.effects).toMatchObject([{ type: "focus", id: "b" }])
  })

  test("back restores the camera stored with the entry", () => {
    const camera = { x: 3, y: 4, ratio: 2 }
    const a = transition(INITIAL_MODEL, { type: "dblclick", id: "a", camera }).model
    const b = run([{ type: "anim-done", attempt: a.attempt }, dblclick("b"), { type: "anim-done", attempt: 2 }], a)
    expect(transition(b, { type: "back" }).effects).toMatchObject([{ type: "focus", id: "a", camera }])
  })

  test("a new focus after back drops the forward history", () => {
    const model = focused("a", "b")
    const back = run([{ type: "back" }], model)
    const next = transition(run([{ type: "anim-done", attempt: back.attempt }], back), dblclick("c")).model
    expect(next.history.entries.map((entry) => entry.id)).toEqual(["a", "c"])
    expect(next.history.index).toBe(1)
  })

  test("reset clears state and history and emits reset; escape during animation cancels to idle", () => {
    const reset = transition(focused("a", "b"), { type: "reset" })
    expect(reset.model.state).toEqual({ type: "idle" })
    expect(reset.model.history).toEqual({ entries: [], index: -1 })
    expect(reset.effects).toEqual([{ type: "reset" }])

    const animating = transition(INITIAL_MODEL, dblclick("a")).model
    const escaped = transition(animating, { type: "escape" })
    expect(escaped.model.state).toEqual({ type: "idle" })
    expect(escaped.effects).toEqual([{ type: "cancel-animation" }])
  })

  test("fit emits fit without changing the model", () => {
    const model = run([click("a")])
    const result = transition(model, { type: "fit" })
    expect(result.effects).toEqual([{ type: "fit" }])
    expect(result.model).toBe(model)
  })

  test("events that do not apply return the same model", () => {
    const selected = run([click("a")])
    const events: [string, Model, Event][] = [
      ["pan-end while idle", INITIAL_MODEL, { type: "pan-end" }],
      ["drag-end while idle", INITIAL_MODEL, { type: "drag-end" }],
      ["anim-done while idle", INITIAL_MODEL, { type: "anim-done", attempt: 0 }],
      ["hover away while idle", INITIAL_MODEL, { type: "hover" }],
      ["escape while idle", INITIAL_MODEL, { type: "escape" }],
      ["back with empty history", INITIAL_MODEL, { type: "back" }],
      ["forward with empty history", INITIAL_MODEL, { type: "forward" }],
      ["same hover while hovering", run([{ type: "hover", id: "h" }]), { type: "hover", id: "h" }],
      ["dblclick on the focused node", focused("a"), dblclick("a")],
      ["hover while selected without change", selected, { type: "hover" }],
    ]
    for (const [name, model, event] of events) expect([name, transition(model, event).model === model]).toEqual([name, true])
  })
})
