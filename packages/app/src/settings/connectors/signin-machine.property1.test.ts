import { describe, expect, test } from "bun:test"
import { INITIAL_SIGNIN_STATE, transition, type SignInEvent, type SignInState } from "./signin-machine"

// Property 1: One activation starts at most one request.
// **Validates: Requirements 1.4, 15.4, 15.5**

const activated: SignInEvent = { type: "signin.activated" }
const reconnect: SignInEvent = { type: "signin.activated", reconnectId: "conn-1" }

// One representative of every member of the closed event union. Attempts 1 and 2 cover a current and a stale or
// future attempt for the first activation.
const EVENTS: readonly SignInEvent[] = [
  activated,
  reconnect,
  { type: "authorization.started", attempt: 1, authorizationId: "a1", userCode: "AAAA-BBBB", verificationUri: "https://github.com/login/device", expiresAt: 1000 },
  { type: "authorization.started", attempt: 2, authorizationId: "a2", userCode: "CCCC-DDDD", verificationUri: "https://github.com/login/device", expiresAt: 2000 },
  { type: "authorization.connected", attempt: 1, connectionId: "c1" },
  { type: "authorization.connected", attempt: 2, connectionId: "c2" },
  { type: "authorization.failed", attempt: 1, error: "network" },
  { type: "request.failed", attempt: 1, error: "request_timeout" },
  { type: "request.failed", attempt: 2, error: "network" },
  { type: "expired", attempt: 1 },
  { type: "repos.loaded", attempt: 1, loadAttempt: 1, items: [] },
  { type: "repos.failed", attempt: 1, loadAttempt: 1 },
  { type: "repos.retried", attempt: 1 },
  { type: "repo.toggled", attempt: 1, fullName: "o/r" },
  { type: "saved", attempt: 1 },
  { type: "cancelled" },
  { type: "disposed" },
]

const MAX_LENGTH = 5

const accepts = (state: SignInState) => state.phase === "idle" || state.phase === "failed"

/** Applies the sequence and checks the property after every step. Returns the number of starts seen. */
function run(sequence: readonly SignInEvent[]) {
  let state = INITIAL_SIGNIN_STATE
  let accepted = 0
  let starts = 0
  for (const event of sequence) {
    const before = state
    const result = transition(before, event)
    const emitted = result.effects.filter((effect) => effect.type === "authorization.start")
    if (event.type === "signin.activated") {
      if (accepts(before)) {
        accepted++
        expect(emitted).toHaveLength(1)
        expect(emitted[0]).toMatchObject({ attempt: before.issued + 1 })
        expect(result.state.phase).toBe("starting")
      } else {
        expect(result.state).toBe(before)
        expect(result.effects).toHaveLength(0)
      }
    } else {
      expect(emitted).toHaveLength(0)
    }
    starts += emitted.length
    state = result.state
  }
  expect(starts).toBe(accepted)
  return { starts, accepted, state }
}

describe("signin machine property 1: one activation starts at most one request", () => {
  test("every event sequence up to length 5 starts exactly one request per accepted activation", () => {
    let count = 0
    let maxStarts = 0
    // Depth-first walk; each node is one distinct sequence, checked incrementally along its prefix.
    const walk = (state: SignInState, depth: number, starts: number, accepted: number) => {
      count++
      if (starts !== accepted) throw new Error(`starts ${starts} != accepted ${accepted}`)
      maxStarts = Math.max(maxStarts, starts)
      if (depth === MAX_LENGTH) return
      for (const event of EVENTS) {
        const result = transition(state, event)
        const emitted = result.effects.filter((effect) => effect.type === "authorization.start").length
        if (event.type === "signin.activated") {
          if (accepts(state)) {
            if (emitted !== 1 || result.state.phase !== "starting") throw new Error(`activation in ${state.phase} did not start once`)
            if (result.state.issued !== state.issued + 1) throw new Error("attempt id not fresh")
          } else if (result.state !== state || result.effects.length !== 0) {
            throw new Error(`activation in ${state.phase} was not ignored`)
          }
        } else if (emitted !== 0) {
          throw new Error(`${event.type} in ${state.phase} emitted a start`)
        }
        walk(result.state, depth + 1, starts + emitted, accepted + (event.type === "signin.activated" && accepts(state) ? 1 : 0))
      }
    }
    walk(INITIAL_SIGNIN_STATE, 0, 0, 0)
    expect(count).toBeGreaterThan(1_000_000)
    // Failure then re-activation is reachable within the bound, so more than one accepted activation is exercised.
    expect(maxStarts).toBeGreaterThanOrEqual(2)
  })

  test("a double activation yields one start", () => {
    for (const second of [activated, reconnect]) {
      const { starts, state } = run([activated, second])
      expect(starts).toBe(1)
      expect(state).toMatchObject({ phase: "starting", attempt: 1, issued: 1 })
    }
  })

  test("an activation outside idle or failed returns the same state with no effects", () => {
    const phases: Record<"starting" | "awaiting" | "installing" | "repositories", readonly SignInEvent[]> = {
      starting: [activated],
      awaiting: [activated, EVENTS[2]!],
      installing: [activated, EVENTS[2]!, EVENTS[4]!],
      repositories: [activated, EVENTS[2]!, EVENTS[4]!, EVENTS[10]!],
    }
    for (const [phase, prefix] of Object.entries(phases) as [SignInState["phase"], readonly SignInEvent[]][]) {
      const state = prefix.reduce((s, e) => transition(s, e).state, INITIAL_SIGNIN_STATE)
      expect(state.phase).toBe(phase)
      for (const event of [activated, reconnect]) {
        const result = transition(state, event)
        expect(result.state).toBe(state)
        expect(result.effects).toHaveLength(0)
      }
    }
  })

  test("an activation after a failure starts exactly one new request with a fresh attempt", () => {
    const { starts, state } = run([activated, { type: "request.failed", attempt: 1, error: "network" }, activated, activated])
    expect(starts).toBe(2)
    expect(state).toMatchObject({ phase: "starting", attempt: 2, issued: 2 })
  })
})
