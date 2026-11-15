import { describe, expect, test } from "bun:test"
import { transition, type GraphState } from "./machine"

// Property 18, as an exhaustive generated table: fast-check is not a dependency of packages/app.
// Validates: Requirements 8.2, 8.9
const attempts = [0, 1, 2, 5, 9]
const lenses = ["identity", "exposure"]

function* ready(): Generator<Extract<GraphState, { type: "ready" }>> {
  for (const attempt of attempts)
    for (const lens of lenses)
      for (const follow of [false, true])
        for (const error of [undefined, "slice" as const])
          for (const pending of [undefined, ...attempts.map((a) => ({ attempt: a, lens: "attack-path" }))])
            yield { type: "ready", attempt, lens, follow, error, pending }
}

describe("Property 18: failed or stale slice results never replace the rendered graph", () => {
  test("slice-failed for the pending attempt keeps the lens and sets the error", () => {
    let cases = 0
    for (const state of ready()) {
      if (!state.pending) continue
      const next = transition(state, { type: "slice-failed", attempt: state.pending.attempt })
      expect(next.state).toMatchObject({
        type: "ready",
        attempt: state.attempt,
        lens: state.lens,
        follow: state.follow,
        error: "slice",
      })
      expect((next.state as typeof state).pending).toBeUndefined()
      expect(next.effects).toEqual([])
      cases++
    }
    expect(cases).toBeGreaterThan(100)
  })

  test("loaded or slice-failed for any other attempt returns the same state object", () => {
    let cases = 0
    for (const state of ready()) {
      for (const attempt of [...attempts, 100]) {
        if (attempt === state.pending?.attempt) continue
        for (const type of ["loaded", "slice-failed"] as const) {
          const next = transition(state, { type, attempt })
          expect(next.state).toBe(state)
          expect(next.effects).toEqual([])
          cases++
        }
      }
    }
    expect(cases).toBeGreaterThan(500)
  })

  test("a stale result while loading returns the same state object", () => {
    const state: GraphState = { type: "loading", attempt: 1, lens: "identity" }
    expect(transition(state, { type: "loaded", attempt: 2 }).state).toBe(state)
    expect(transition(state, { type: "slice-failed", attempt: 0 }).state).toBe(state)
  })

  test("a late result from a superseded switch cannot replace the newer pending attempt", () => {
    const ready1: GraphState = { type: "ready", attempt: 1, lens: "identity", follow: false }
    const first = transition(ready1, { type: "select", lens: "exposure" }).state
    const second = transition(first, { type: "select", lens: "attack-path" }).state
    expect(transition(second, { type: "loaded", attempt: 2 }).state).toBe(second)
    expect(transition(second, { type: "slice-failed", attempt: 2 }).state).toBe(second)
    expect(transition(second, { type: "loaded", attempt: 3 }).state).toMatchObject({ lens: "attack-path" })
  })
})
