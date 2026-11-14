import { describe, expect, test } from "bun:test"
import { transition, type SignInEvent, type SignInState } from "./signin-machine"

/**
 * Property 3: transition is total, pure and identity-preserving.
 * **Validates: Requirements 15.1, 15.2, 15.3, 15.13**
 *
 * Exhaustive table over representative states of all six phases and one instance of every event type, with the
 * attempt id both matching and not matching the state's attempt.
 */
const PHASES = ["idle", "starting", "awaiting", "installing", "repositories", "failed"] as const

const repo = { fullName: "a/b", private: false }

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const child of Object.values(value)) deepFreeze(child)
  }
  return value
}

const repositories = (repos: "loading" | "ready" | "failed"): SignInState => ({
  phase: "repositories",
  issued: 3,
  attempt: 3,
  authorizationId: "a1",
  github: {
    status: "repositories",
    connectionId: "c1",
    attempt: 2,
    repos: repos === "ready" ? { phase: "ready", items: [repo] } : { phase: repos },
    selected: repos === "ready" ? ["a/b"] : [],
    touched: repos === "ready",
  },
})

const awaiting = (reconnectId?: string): SignInState => ({
  phase: "awaiting",
  issued: 3,
  attempt: 3,
  ...(reconnectId === undefined ? {} : { reconnectId }),
  authorizationId: "a1",
  userCode: "ABCD-1234",
  verificationUri: "https://github.com/login/device",
  expiresAt: 10_000,
})

const states: readonly SignInState[] = [
  { phase: "idle", issued: 0 },
  { phase: "idle", issued: 5 },
  { phase: "starting", issued: 3, attempt: 3 },
  { phase: "starting", issued: 3, attempt: 3, reconnectId: "r1" },
  awaiting(),
  awaiting("r1"),
  { phase: "installing", issued: 3, attempt: 3, authorizationId: "a1", connectionId: "c1" },
  repositories("loading"),
  repositories("ready"),
  repositories("failed"),
  { phase: "failed", issued: 3, attempt: 3, error: "device_code_expired" },
  { phase: "failed", issued: 3, attempt: 3, error: "rate_limited", retryAfterSec: 30 },
]

const eventsFor = (attempt: number): readonly SignInEvent[] => [
  { type: "signin.activated" },
  { type: "signin.activated", reconnectId: "r1" },
  {
    type: "authorization.started",
    attempt,
    authorizationId: "a2",
    userCode: "WXYZ-9999",
    verificationUri: "https://github.com/login/device",
    expiresAt: 20_000,
  },
  { type: "authorization.connected", attempt, connectionId: "c2" },
  { type: "authorization.failed", attempt, error: "device_flow_disabled" },
  { type: "authorization.failed", attempt, error: "rate_limited", retryAfterSec: 10 },
  { type: "request.failed", attempt, error: "request_timeout" },
  { type: "expired", attempt },
  { type: "repos.loaded", attempt, loadAttempt: 1, items: [repo] },
  { type: "repos.loaded", attempt, loadAttempt: 2, items: [repo] },
  { type: "repos.failed", attempt, loadAttempt: 1 },
  { type: "repos.failed", attempt, loadAttempt: 2 },
  { type: "repos.retried", attempt },
  { type: "repo.toggled", attempt, fullName: "a/b" },
  { type: "saved", attempt },
  { type: "cancelled" },
  { type: "disposed" },
]

const attemptsOf = (state: SignInState) => (state.phase === "idle" ? [1] : [state.attempt, state.attempt + 100])
const pairs = states.flatMap((state) => attemptsOf(state).flatMap((a) => eventsFor(a).map((event) => ({ state, event }))))

const label = (state: SignInState, event: SignInEvent) =>
  `${state.phase} + ${event.type}${"attempt" in event ? `#${event.attempt}` : ""}`

describe("signin-machine property 3: transition is total, pure and identity-preserving", () => {
  test("the table covers all six phases and every event type", () => {
    expect(new Set(states.map((s) => s.phase))).toEqual(new Set(PHASES))
    expect(new Set(pairs.map((p) => p.event.type)).size).toBe(13)
  })

  test("never throws, never mutates frozen inputs, and returns a state of exactly one phase", () => {
    for (const { state, event } of pairs) {
      const frozenState = deepFreeze(structuredClone(state))
      const frozenEvent = deepFreeze(structuredClone(event))
      const before = JSON.stringify([frozenState, frozenEvent])
      let result: ReturnType<typeof transition> | undefined
      expect(() => (result = transition(frozenState, frozenEvent)), label(state, event)).not.toThrow()
      expect(JSON.stringify([frozenState, frozenEvent]), label(state, event)).toBe(before)
      const phase = result!.state.phase
      expect(PHASES.filter((p) => p === phase), label(state, event)).toHaveLength(1)
      expect(Array.isArray(result!.effects)).toBe(true)
    }
  })

  test("a result that keeps the state object has no effects; a changed state is a new object", () => {
    let ignored = 0
    let changed = 0
    for (const { state, event } of pairs) {
      const result = transition(state, event)
      if (result.state === state) {
        ignored++
        expect(result.effects, label(state, event)).toHaveLength(0)
      } else {
        changed++
        expect(result.state, label(state, event)).not.toEqual(state)
      }
    }
    // Both outcomes occur, so the identity branch is exercised.
    expect(ignored).toBeGreaterThan(0)
    expect(changed).toBeGreaterThan(0)
  })

  test("an event carrying another attempt id returns the same state object", () => {
    for (const state of states.filter((s) => s.phase !== "idle")) {
      const stale = eventsFor((state as { attempt: number }).attempt + 100).filter((e) => "attempt" in e)
      for (const event of stale) {
        const result = transition(state, event)
        expect(result.state, label(state, event)).toBe(state)
        expect(result.effects).toHaveLength(0)
      }
    }
  })

  test("after disposed the state is idle, keeps the counter, and every later result event is ignored", () => {
    for (const state of states) {
      const disposed = transition(state, { type: "disposed" }).state
      expect(disposed.phase, state.phase).toBe("idle")
      expect(disposed.issued, state.phase).toBe(state.issued)
      for (const event of eventsFor(1).concat(eventsFor(state.phase === "idle" ? 1 : state.issued))) {
        if (event.type === "signin.activated") continue
        const result = transition(disposed, event)
        expect(result.state, `disposed ${state.phase} + ${event.type}`).toBe(disposed)
        expect(result.effects).toHaveLength(0)
      }
    }
  })
})
