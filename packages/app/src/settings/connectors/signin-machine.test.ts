import { describe, expect, test } from "bun:test"
import {
  INITIAL_SIGNIN_STATE,
  selectBusy,
  selectDisabled,
  selectError,
  selectPanel,
  selectRemaining,
  transition,
  type SignInEvent,
  type SignInState,
} from "./signin-machine"

const started = (attempt: number): SignInEvent => ({
  type: "authorization.started",
  attempt,
  authorizationId: "a1",
  userCode: "ABCD-1234",
  verificationUri: "https://github.com/login/device",
  expiresAt: 10_000,
})
const run = (events: readonly SignInEvent[], from: SignInState = INITIAL_SIGNIN_STATE) =>
  events.reduce((state, event) => transition(state, event).state, from)
const repo = { fullName: "a/b", private: false }
const toRepositories: readonly SignInEvent[] = [
  { type: "signin.activated" },
  started(1),
  { type: "authorization.connected", attempt: 1, connectionId: "c1" },
  { type: "repos.loaded", attempt: 1, loadAttempt: 1, items: [repo] },
]

describe("sign-in machine", () => {
  test("activation leaves idle with exactly one start effect, and a double click is ignored", () => {
    const first = transition(INITIAL_SIGNIN_STATE, { type: "signin.activated" })
    expect(first.state.phase).toBe("starting")
    expect(first.effects).toEqual([{ type: "authorization.start", attempt: 1 }])
    const second = transition(first.state, { type: "signin.activated" })
    expect(second.state).toBe(first.state)
    expect(second.effects).toHaveLength(0)
  })

  test("Try again after failure uses a new attempt id and stale results are ignored", () => {
    const failed = run([{ type: "signin.activated" }, { type: "request.failed", attempt: 1, error: "request_timeout" }])
    expect(selectError(failed)).toEqual({ code: "request_timeout" })
    const retry = transition(failed, { type: "signin.activated" })
    expect(retry.state).toMatchObject({ phase: "starting", attempt: 2 })
    const late = transition(retry.state, started(1))
    expect(late.state).toBe(retry.state)
    expect(transition(retry.state, started(2)).state.phase).toBe("awaiting")
  })

  test("expired moves awaiting to device_code_expired; a stale expired is ignored", () => {
    const awaiting = run([{ type: "signin.activated" }, started(1)])
    expect(transition(awaiting, { type: "expired", attempt: 9 }).state).toBe(awaiting)
    expect(selectError(transition(awaiting, { type: "expired", attempt: 1 }).state)).toEqual({
      code: "device_code_expired",
    })
  })

  test("repositories phase reuses the github machine, including Check again from ready", () => {
    const ready = run(toRepositories)
    expect(ready.phase).toBe("repositories")
    const retried = transition(ready, { type: "repos.retried", attempt: 1 })
    expect(retried.effects).toEqual([{ type: "repos.load", attempt: 1, connectionId: "c1", loadAttempt: 2 }])
    const stale = transition(retried.state, { type: "repos.loaded", attempt: 1, loadAttempt: 1, items: [] })
    expect(stale.state).toBe(retried.state)
    const toggled = run([{ type: "repo.toggled", attempt: 1, fullName: "a/b" }], ready)
    expect(toggled.phase === "repositories" && toggled.github.selected).toEqual(["a/b"])
  })

  test("disposed cancels the authorization and later results are ignored", () => {
    const awaiting = run([{ type: "signin.activated" }, started(1)])
    const out = transition(awaiting, { type: "disposed" })
    expect(out.state.phase).toBe("idle")
    expect(out.effects).toContainEqual({ type: "authorization.cancel", authorizationId: "a1" })
    const late = transition(out.state, { type: "authorization.connected", attempt: 1, connectionId: "c1" })
    expect(late.state).toBe(out.state)
  })

  test("selectors follow the contract", () => {
    const phases = [
      INITIAL_SIGNIN_STATE,
      run([{ type: "signin.activated" }]),
      run([{ type: "signin.activated" }, started(1)]),
      run(toRepositories.slice(0, 3)),
      run(toRepositories),
      run([{ type: "signin.activated" }, { type: "request.failed", attempt: 1, error: "request_timeout" }]),
    ]
    expect(phases.map(selectPanel)).toEqual(["signin", "starting", "prompt", "installing", "repositories", "failed"])
    expect(phases.map(selectBusy)).toEqual([false, true, false, true, false, false])
    expect(phases.map(selectDisabled)).toEqual([false, true, true, true, false, false])
    expect(phases.map((s) => selectError(s) !== undefined)).toEqual([false, false, false, false, false, true])
    expect(selectRemaining(phases[2], 8_500)).toBe(2)
    expect(selectRemaining(phases[2], 20_000)).toBe(0)
  })
})
