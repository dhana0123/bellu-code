import { describe, expect, test } from "bun:test"
import { INITIAL_SIGNIN_STATE, transition, type SignInEvent, type SignInState } from "./signin-machine"

/**
 * Property 4: attempt ids are unique and stale results are ignored.
 * **Validates: Requirements 13.5, 15.6, 15.7**
 *
 * Exhaustive walk over every event sequence up to DEPTH from the initial state. At each reached state, every result
 * event carrying a non-current attempt id is replayed and must return the same state object with no effects.
 */
const DEPTH = 6

const started = (attempt: number): SignInEvent => ({
  type: "authorization.started",
  attempt,
  authorizationId: "a1",
  userCode: "ABCD-1234",
  verificationUri: "https://github.com/login/device",
  expiresAt: 10_000,
})

/** Every result event type that carries an attempt id, built for a given id. */
const results = (attempt: number): readonly SignInEvent[] => [
  started(attempt),
  { type: "authorization.connected", attempt, connectionId: "c1" },
  { type: "authorization.failed", attempt, error: "device_code_expired" },
  { type: "request.failed", attempt, error: "request_timeout" },
  { type: "expired", attempt },
  { type: "repos.loaded", attempt, loadAttempt: 1, items: [{ fullName: "a/b", private: false }] },
  { type: "repos.failed", attempt, loadAttempt: 1 },
  { type: "repos.retried", attempt },
  { type: "repo.toggled", attempt, fullName: "a/b" },
  { type: "saved", attempt },
]

const activations: readonly SignInEvent[] = [{ type: "signin.activated" }, { type: "signin.activated", reconnectId: "r1" }]
const exits: readonly SignInEvent[] = [{ type: "cancelled" }, { type: "disposed" }]

/** Events that can advance the machine: activations, exits and every result carrying the current attempt id. */
function fresh(state: SignInState): readonly SignInEvent[] {
  const current = state.phase === "idle" ? [] : results(state.attempt)
  return [...activations, ...exits, ...current]
}

describe("signin-machine Property 4: attempt ids", () => {
  let nodes = 0
  let activationsSeen = 0
  let staleChecks = 0
  let tryAgain = 0

  function visit(state: SignInState, issuedIds: readonly number[], depth: number) {
    nodes++

    // Stale results: any id other than the current one (earlier ids, zero, and a not-yet-issued id).
    const current = state.phase === "idle" ? undefined : state.attempt
    const ids = new Set([0, ...issuedIds, state.issued + 1])
    for (const id of ids) {
      if (id === current) continue
      for (const event of results(id)) {
        const result = transition(state, event)
        staleChecks++
        expect(result.state).toBe(state)
        expect(result.effects).toHaveLength(0)
      }
    }
    if (depth === 0) return

    for (const event of fresh(state)) {
      const result = transition(state, event)
      const started = result.effects.find((effect) => effect.type === "authorization.start")
      if (event.type === "signin.activated" && result.state !== state) {
        activationsSeen++
        // Strictly increasing, unique within the dialog, including after disposed/cancelled/failed.
        expect(started).toBeDefined()
        const attempt = started?.type === "authorization.start" ? started.attempt : -1
        expect(attempt).toBe(state.issued + 1)
        expect(issuedIds.every((id) => id < attempt)).toBe(true)
        expect(result.state).toMatchObject({ phase: "starting", attempt, issued: attempt })
        if (state.phase === "failed") {
          // Try again discards the previous error and Device_Authorization.
          tryAgain++
          expect(Object.keys(result.state).sort()).toEqual(
            event.reconnectId === undefined ? ["attempt", "issued", "phase"] : ["attempt", "issued", "phase", "reconnectId"],
          )
        }
        visit(result.state, [...issuedIds, attempt], depth - 1)
        continue
      }
      // Any other event never issues an attempt id and never lowers the counter.
      expect(started).toBeUndefined()
      expect(result.state.issued).toBe(state.issued)
      if (result.state === state) {
        expect(result.effects).toHaveLength(0)
        continue
      }
      visit(result.state, issuedIds, depth - 1)
    }
  }

  test("ids are unique and increasing, stale results are ignored, Try again starts clean", () => {
    visit(INITIAL_SIGNIN_STATE, [], DEPTH)
    // The walk must actually reach re-activation after each exit and the failed state.
    expect(activationsSeen).toBeGreaterThan(500)
    expect(tryAgain).toBeGreaterThan(100)
    expect(staleChecks).toBeGreaterThan(10_000)
    expect(nodes).toBeGreaterThan(1000)
  })

  test("activating while a dialog attempt is running is ignored", () => {
    const starting = transition(INITIAL_SIGNIN_STATE, { type: "signin.activated" }).state
    const again = transition(starting, { type: "signin.activated" })
    expect(again.state).toBe(starting)
    expect(again.effects).toHaveLength(0)
  })

  test("a failed attempt's late result cannot affect the next attempt", () => {
    const first = transition(INITIAL_SIGNIN_STATE, { type: "signin.activated" }).state
    const failed = transition(first, { type: "request.failed", attempt: 1, error: "request_timeout" }).state
    const second = transition(failed, { type: "signin.activated" }).state
    expect(second).toEqual({ phase: "starting", issued: 2, attempt: 2 })
    const late = transition(second, started(1))
    expect(late.state).toBe(second)
    expect(late.effects).toHaveLength(0)
  })
})
