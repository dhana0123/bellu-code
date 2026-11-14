import { describe, expect, test } from "bun:test"
import {
  selectAnnouncement,
  selectBusy,
  selectDisabled,
  selectError,
  selectPanel,
  selectPrompt,
  selectRemaining,
  selectRetryable,
  type SignInErrorCode,
  type SignInState,
} from "./signin-machine"

/**
 * Property 5: Selectors are a function of state and match the contract.
 * **Validates: Requirements 2.6, 2.11, 13.3, 15.10, 15.11**
 */

const awaiting = {
  phase: "awaiting",
  issued: 1,
  attempt: 1,
  authorizationId: "a1",
  userCode: "ABCD-1234",
  verificationUri: "https://github.com/login/device",
  expiresAt: 1_000_000,
} as const

const codes: SignInErrorCode[] = [
  "device_flow_disabled",
  "device_code_expired",
  "request_timeout",
  "access_denied" as SignInErrorCode,
  "unknown" as SignInErrorCode,
]

const failedStates: SignInState[] = [
  ...codes.map((error) => ({ phase: "failed", issued: 2, attempt: 2, error }) as const),
  { phase: "failed", issued: 2, attempt: 2, error: "request_timeout", retryAfterSec: 30 },
]

const states: SignInState[] = [
  { phase: "idle", issued: 0 },
  { phase: "idle", issued: 5 },
  { phase: "starting", issued: 1, attempt: 1 },
  { phase: "starting", issued: 1, attempt: 1, reconnectId: "c1" },
  awaiting,
  { ...awaiting, reconnectId: "c1" },
  { phase: "installing", issued: 1, attempt: 1, authorizationId: "a1", connectionId: "c1" },
  {
    phase: "repositories",
    issued: 1,
    attempt: 1,
    authorizationId: "a1",
    github: { status: "repositories", connectionId: "c1", attempt: 1, repos: { phase: "loading" }, selected: [], touched: false },
  },
  {
    phase: "repositories",
    issued: 1,
    attempt: 1,
    authorizationId: "a1",
    github: { status: "repositories", connectionId: "c1", attempt: 1, repos: { phase: "ready", items: [] }, selected: [], touched: true },
  },
  ...failedStates,
]

const panels = ["signin", "starting", "prompt", "installing", "repositories", "failed"]
const phaseOf = (s: SignInState) => s.phase

describe("Property 5: signin selectors", () => {
  test("every phase is covered", () => {
    expect(new Set(states.map(phaseOf))).toEqual(new Set(["idle", "starting", "awaiting", "installing", "repositories", "failed"]))
  })

  for (const state of states) {
    const label = `${state.phase}${state.phase === "failed" ? `:${state.error}${state.retryAfterSec ? "+retry" : ""}` : ""}`
    test(`contract for ${label}`, () => {
      const before = structuredClone(state)
      const frozen = Object.freeze(structuredClone(state))

      const snapshot = () => ({
        panel: selectPanel(state),
        busy: selectBusy(state),
        disabled: selectDisabled(state),
        error: selectError(state),
        prompt: selectPrompt(state),
        retryable: selectRetryable(state),
        announcement: selectAnnouncement(state),
        remaining: selectRemaining(state, 400_000),
      })

      // pure: repeated calls agree, input is not mutated, frozen input works
      const first = snapshot()
      expect(snapshot()).toEqual(first)
      expect(state).toEqual(before)
      expect(selectPanel(frozen)).toBe(first.panel)

      expect(first.busy).toBe(state.phase === "starting" || state.phase === "installing")
      expect(first.disabled).toBe(state.phase === "starting" || state.phase === "awaiting" || state.phase === "installing")

      // exactly one visible panel, from the closed set
      expect(panels.filter((p) => p === first.panel)).toHaveLength(1)

      if (state.phase === "failed") {
        expect(first.error?.code).toBe(state.error)
        expect(first.error?.retryAfterSec).toBe(state.retryAfterSec)
        expect(first.retryable).toBe(state.error !== "device_flow_disabled")
      } else {
        expect(first.error).toBeUndefined()
        expect(first.retryable).toBe(false)
      }

      if (state.phase === "awaiting") expect(first.prompt?.userCode).toBe(state.userCode)
      else expect(first.prompt).toBeUndefined()

      // announcement: one value per phase, independent of the clock
      expect(first.announcement).toBe(state.phase === "idle" ? undefined : first.panel as never)
      for (const now of [0, 1, 999_999, 1_000_000, 5_000_000]) {
        expect(selectAnnouncement(state)).toBe(first.announcement)
        expect(selectRemaining(state, now)).toBeGreaterThanOrEqual(0)
      }
      if (state.phase !== "awaiting") expect(selectRemaining(state, 0)).toBe(0)
    })
  }

  test("panels are distinct per phase", () => {
    const byPhase = new Map(states.map((s) => [s.phase, selectPanel(s)]))
    expect(byPhase.size).toBe(6)
    expect(new Set(byPhase.values()).size).toBe(6)
  })

  test("device_flow_disabled is the only non-retryable failure", () => {
    expect(failedStates.filter((s) => !selectRetryable(s)).map((s) => s.phase === "failed" && s.error)).toEqual([
      "device_flow_disabled",
    ])
  })

  test("countdown changes do not change the announcement", () => {
    const seen = new Set([0, 1_000, 500_000, 999_999].map(() => selectAnnouncement(awaiting)))
    expect(seen.size).toBe(1)
    expect(selectRemaining(awaiting, 0)).not.toBe(selectRemaining(awaiting, 500_000))
  })
})
