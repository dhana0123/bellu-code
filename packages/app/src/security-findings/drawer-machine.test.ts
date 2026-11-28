import { describe, expect, test } from "bun:test"
import { initial, transition } from "./drawer-machine"

// Validates: Requirements 3.9, 3.10
describe("detail drawer machine", () => {
  const open = transition(initial, { type: "open", id: "f1", intent: "ignored" })

  test("opening starts the history load with the intent", () => {
    expect(open).toMatchObject({ type: "open", attempt: 1, id: "f1", intent: "ignored", history: { type: "loading" } })
  })

  test("a history result for an earlier open changes nothing", () => {
    const reopened = transition(open, { type: "open", id: "f2" })
    expect(transition(reopened, { type: "history-loaded", attempt: 1, events: [] })).toBe(reopened)
  })

  test("a second save while one is in flight starts nothing", () => {
    const saving = transition(open, { type: "save", request: { status: "ignored", reason: "x" } })
    expect(transition(saving, { type: "save", request: { status: "open" } })).toBe(saving)
  })

  test("a refusal names the field and the form can submit again", () => {
    const saving = transition(open, { type: "save", request: { status: "ignored", reason: "" } })
    const rejected = transition(saving, { type: "save-failed", attempt: 1, field: "reason", message: "required" })
    expect(rejected).toMatchObject({ save: { type: "rejected", field: "reason", message: "required" } })
    expect(transition(rejected, { type: "save", request: { status: "ignored", reason: "ok" } })).toMatchObject({
      save: { type: "saving" },
    })
  })

  test("a saved change replaces the history and returns to idle", () => {
    const saving = transition(open, { type: "save", request: { status: "resolved" } })
    const saved = transition(saving, { type: "saved", attempt: 1, events: [] })
    expect(saved).toMatchObject({ history: { type: "ready", events: [] }, save: { type: "idle" } })
  })

  test("a result after close changes nothing", () => {
    const closed = transition(open, { type: "close" })
    expect(transition(closed, { type: "saved", attempt: 1, events: [] })).toBe(closed)
  })
})
