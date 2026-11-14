import { describe, expect, test } from "bun:test"
import { transition, type SignInEffect, type SignInEvent, type SignInState } from "./signin-machine"

/**
 * Property 7: a pending phase ends in exactly one terminal outcome.
 * **Validates: Requirements 2.10, 3.10, 13.8**
 *
 * Exhaustive table: every pending phase (starting, awaiting, installing, repositories) against every exit event.
 * Each lands in exactly one outcome, emits `abort` for the attempt when timers or requests exist, and once the
 * outcome is terminal every later result for that attempt is ignored (same state object, no effects).
 */

const A = 3
const repo = { fullName: "a/b", private: false }

const starting: SignInState = { phase: "starting", issued: A, attempt: A }
const awaiting: SignInState = {
  phase: "awaiting",
  issued: A,
  attempt: A,
  authorizationId: "auth1",
  userCode: "ABCD-1234",
  verificationUri: "https://github.com/login/device",
  expiresAt: 1000,
}
const reconnecting: SignInState = { ...awaiting, reconnectId: "conn0" } as SignInState
const installing: SignInState = {
  phase: "installing",
  issued: A,
  attempt: A,
  authorizationId: "auth1",
  connectionId: "c1",
}
const repositories: SignInState = {
  phase: "repositories",
  issued: A,
  attempt: A,
  authorizationId: "auth1",
  github: {
    status: "repositories",
    connectionId: "c1",
    attempt: 1,
    repos: { phase: "ready", items: [repo] },
    selected: ["a/b"],
    touched: false,
  },
}

const abort: SignInEffect = { type: "abort", attempt: A }
const cancel: SignInEffect = { type: "authorization.cancel", authorizationId: "auth1" }

const started: SignInEvent = {
  type: "authorization.started",
  attempt: A,
  authorizationId: "auth1",
  userCode: "ABCD-1234",
  verificationUri: "https://github.com/login/device",
  expiresAt: 1000,
}
const connected: SignInEvent = { type: "authorization.connected", attempt: A, connectionId: "c1" }
const authFailed: SignInEvent = { type: "authorization.failed", attempt: A, error: "device_code_expired" }
const requestFailed: SignInEvent = { type: "request.failed", attempt: A, error: "request_timeout" }
const expired: SignInEvent = { type: "expired", attempt: A }
const loaded: SignInEvent = { type: "repos.loaded", attempt: A, loadAttempt: 1, items: [repo] }
const saved: SignInEvent = { type: "saved", attempt: A }
const cancelled: SignInEvent = { type: "cancelled" }
const disposed: SignInEvent = { type: "disposed" }

/** Every event a driver can deliver for attempt A after the fact. */
const LATE: readonly SignInEvent[] = [
  started,
  connected,
  authFailed,
  requestFailed,
  expired,
  loaded,
  { type: "repos.failed", attempt: A, loadAttempt: 1 },
  { type: "repos.retried", attempt: A },
  { type: "repo.toggled", attempt: A, fullName: "a/b" },
  saved,
]

type Outcome = { readonly phase: SignInState["phase"]; readonly effects: readonly SignInEffect[] }

const TABLE: ReadonlyArray<{ name: string; from: SignInState; event: SignInEvent; outcome: Outcome | "ignored"; terminal: boolean }> = [
  // starting
  { name: "starting + started", from: starting, event: started, terminal: false, outcome: { phase: "awaiting", effects: [
    { type: "status.poll", attempt: A, authorizationId: "auth1" },
    { type: "expiry.schedule", attempt: A, at: 1000 },
  ] } },
  { name: "starting + authorization.failed", from: starting, event: authFailed, terminal: true, outcome: { phase: "failed", effects: [abort] } },
  { name: "starting + request.failed", from: starting, event: requestFailed, terminal: true, outcome: { phase: "failed", effects: [abort] } },
  { name: "starting + expired", from: starting, event: expired, terminal: false, outcome: "ignored" },
  { name: "starting + cancelled", from: starting, event: cancelled, terminal: true, outcome: { phase: "idle", effects: [abort] } },
  { name: "starting + disposed", from: starting, event: disposed, terminal: true, outcome: { phase: "idle", effects: [abort] } },
  // awaiting
  { name: "awaiting + connected", from: awaiting, event: connected, terminal: false, outcome: { phase: "installing", effects: [
    abort,
    { type: "repos.load", attempt: A, connectionId: "c1", loadAttempt: 1 },
  ] } },
  { name: "awaiting (reconnect) + connected", from: reconnecting, event: connected, terminal: true, outcome: { phase: "idle", effects: [abort] } },
  { name: "awaiting + authorization.failed", from: awaiting, event: authFailed, terminal: true, outcome: { phase: "failed", effects: [abort] } },
  { name: "awaiting + request.failed", from: awaiting, event: requestFailed, terminal: true, outcome: { phase: "failed", effects: [abort] } },
  { name: "awaiting + expired", from: awaiting, event: expired, terminal: true, outcome: { phase: "failed", effects: [abort] } },
  { name: "awaiting + cancelled", from: awaiting, event: cancelled, terminal: true, outcome: { phase: "idle", effects: [abort, cancel] } },
  { name: "awaiting + disposed", from: awaiting, event: disposed, terminal: true, outcome: { phase: "idle", effects: [abort, cancel] } },
  // installing
  { name: "installing + repos.loaded", from: installing, event: loaded, terminal: false, outcome: { phase: "repositories", effects: [] } },
  { name: "installing + request.failed", from: installing, event: requestFailed, terminal: true, outcome: { phase: "failed", effects: [abort] } },
  { name: "installing + expired", from: installing, event: expired, terminal: false, outcome: "ignored" },
  { name: "installing + cancelled", from: installing, event: cancelled, terminal: true, outcome: { phase: "idle", effects: [abort, cancel] } },
  { name: "installing + disposed", from: installing, event: disposed, terminal: true, outcome: { phase: "idle", effects: [abort] } },
  // repositories
  // `saved` emits no effects: the attempt's timers and requests were already aborted when it left `awaiting`.
  { name: "repositories + saved", from: repositories, event: saved, terminal: true, outcome: { phase: "idle", effects: [] } },
  { name: "repositories + request.failed", from: repositories, event: requestFailed, terminal: false, outcome: "ignored" },
  { name: "repositories + expired", from: repositories, event: expired, terminal: false, outcome: "ignored" },
  { name: "repositories + cancelled", from: repositories, event: cancelled, terminal: true, outcome: { phase: "idle", effects: [abort, cancel] } },
  { name: "repositories + disposed", from: repositories, event: disposed, terminal: true, outcome: { phase: "idle", effects: [abort] } },
]

describe("Property 7: a pending phase ends in exactly one terminal outcome", () => {
  for (const row of TABLE) {
    test(row.name, () => {
      const result = transition(row.from, row.event)
      if (row.outcome === "ignored") {
        expect(result.state).toBe(row.from)
        expect(result.effects).toEqual([])
        return
      }
      expect(result.state.phase).toBe(row.outcome.phase)
      expect(result.effects).toEqual(row.outcome.effects)
      // Exactly one outcome: never more than one abort or one authorization.cancel.
      expect(result.effects.filter((e) => e.type === "abort").length).toBeLessThanOrEqual(1)
      expect(result.effects.filter((e) => e.type === "authorization.cancel").length).toBeLessThanOrEqual(1)

      if (!row.terminal) return
      // Once terminal, every later result for the attempt is ignored: no second outcome, no effects.
      for (const late of LATE) {
        const again = transition(result.state, late)
        expect(again.state).toBe(result.state)
        expect(again.effects).toEqual([])
      }
      // A repeated exit event cannot emit a second abort or cancel.
      for (const exit of [cancelled, disposed]) {
        const again = transition(result.state, exit)
        expect(again.effects).toEqual([])
      }
    })
  }

  test("a retry after failure starts a new attempt and the old attempt's results stay ignored", () => {
    const failed = transition(awaiting, expired).state
    const retry = transition(failed, { type: "signin.activated" })
    expect(retry.state).toMatchObject({ phase: "starting", attempt: A + 1 })
    for (const late of LATE) {
      const again = transition(retry.state, late)
      expect(again.state).toBe(retry.state)
      expect(again.effects).toEqual([])
    }
  })
})
