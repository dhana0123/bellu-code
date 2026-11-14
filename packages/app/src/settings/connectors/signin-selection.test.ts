import { describe, expect, test } from "bun:test"
import { selectRepositoriesRequired, selectSaveDisabled } from "./github-machine"
import { transition, type SignInEvent, type SignInState } from "./signin-machine"

// Property 32 (UI half): the required message and Save-disabled follow the selection count and the touched flag.
// **Validates: Requirements 5.6, 5.7**

const NAMES = ["a/b", "a/c", "a/d"] as const
const MAX_LENGTH = 4
const items = NAMES.map((fullName) => ({ fullName, private: false }))

const installing: SignInState = {
  phase: "installing",
  issued: 1,
  attempt: 1,
  authorizationId: "auth",
  connectionId: "c1",
}

const step = (state: SignInState, event: SignInEvent) => transition(state, event).state

const loaded = step(installing, { type: "repos.loaded", attempt: 1, loadAttempt: 1, items })

function sequences(length: number): string[][] {
  if (length === 0) return [[]]
  return sequences(length - 1).flatMap((prefix) => NAMES.map((name) => [...prefix, name]))
}

describe("sign-in repository selection message", () => {
  test("loaded list starts untouched: no message, Save disabled (5.7)", () => {
    if (loaded.phase !== "repositories") throw new Error("expected repositories phase")
    expect(loaded.github.touched).toBe(false)
    expect(selectRepositoriesRequired(loaded.github)).toBe(false)
    expect(selectSaveDisabled(loaded.github)).toBe(true)
  })

  test("message and Save-disabled follow selection count and touched over every toggle sequence", () => {
    const all = Array.from({ length: MAX_LENGTH + 1 }, (_, length) => sequences(length)).flat()
    expect(all).toHaveLength(1 + 3 + 9 + 27 + 81)
    all.forEach((names) => {
      const state = names.reduce<SignInState>((acc, fullName) => step(acc, { type: "repo.toggled", attempt: 1, fullName }), loaded)
      if (state.phase !== "repositories") throw new Error("expected repositories phase")

      const selected = new Set<string>()
      names.forEach((name) => (selected.has(name) ? selected.delete(name) : selected.add(name)))
      const label = names.join(",") || "(none)"

      expect([label, [...state.github.selected].sort()]).toEqual([label, [...selected].sort()])
      expect([label, selectRepositoriesRequired(state.github)]).toEqual([label, names.length > 0 && selected.size === 0])
      expect([label, selectSaveDisabled(state.github)]).toEqual([label, selected.size === 0])
    })
  })

  test("toggles before the list loads are ignored and show no message", () => {
    expect(step(installing, { type: "repo.toggled", attempt: 1, fullName: "a/b" })).toBe(installing)
  })
})
