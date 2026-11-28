import { describe, expect, test } from "bun:test"
import type { Connectors } from "@bellucode/schema/connectors"
import { validateAlias, type AliasError } from "./machine"
import { selectSignInAvailable, selectSignInVisible } from "./signin-availability"
import { INITIAL_SIGNIN_STATE, transition, type SignInState } from "./signin-machine"

// Feature: github-app-signin, Property 2: The sign-in action is enabled exactly when it is allowed
// **Validates: Requirements 1.5, 1.6, 11.4, 11.5**

const starting = transition(INITIAL_SIGNIN_STATE, { type: "signin.activated" }).state
const awaiting = transition(starting, {
  type: "authorization.started",
  attempt: 1,
  authorizationId: "auth-1",
  userCode: "ABCD-1234",
  verificationUri: "https://github.com/login/device",
  expiresAt: 1_000,
}).state
const installing = transition(awaiting, { type: "authorization.connected", attempt: 1, connectionId: "c1" }).state
const repositories = transition(installing, { type: "repos.loaded", attempt: 1, loadAttempt: 1, items: [] }).state
const failed = transition(starting, { type: "request.failed", attempt: 1, error: "request_timeout" }).state

const machines: ReadonlyArray<readonly [SignInState["phase"], SignInState, boolean]> = [
  ["idle", INITIAL_SIGNIN_STATE, true],
  ["starting", starting, false],
  ["awaiting", awaiting, false],
  ["installing", installing, false],
  ["repositories", repositories, true],
  ["failed", failed, true],
]
const aliasErrors: ReadonlyArray<AliasError | undefined> = [undefined, "empty", "too-long", "taken"]
const hosts: ReadonlyArray<readonly [string, boolean]> = [
  ["", true],
  ["github.com", true],
  ["GitHub.COM", true],
  ["  github.com  ", true],
  ["github.example.com", false],
  ["api.github.com", false],
  ["github.com.evil.test", false],
  ["notgithub.com", false],
  ["x", false],
]

describe("selectSignInVisible", () => {
  for (const [host, visible] of hosts) {
    test(`host ${JSON.stringify(host)} -> ${visible}`, () => {
      expect(selectSignInVisible(host)).toBe(visible)
    })
  }
})

describe("selectSignInAvailable", () => {
  test("phases are covered by real machine states", () => {
    expect(machines.map(([phase, state]) => state.phase)).toEqual(machines.map(([phase]) => phase))
  })

  for (const [phase, machine, machineOk] of machines)
    for (const aliasError of aliasErrors)
      for (const patBusy of [false, true])
        for (const [host, hostOk] of hosts)
          test(`${phase} alias=${aliasError ?? "ok"} patBusy=${patBusy} host=${JSON.stringify(host)}`, () => {
            const expected = aliasError === undefined && machineOk && !patBusy && hostOk
            expect(selectSignInAvailable({ aliasError, machine, patBusy, host })).toBe(expected)
          })

  test("only idle, repositories and failed with a valid alias and no PAT request are enabled", () => {
    let enabled = 0
    for (const [, machine] of machines)
      for (const aliasError of aliasErrors)
        for (const patBusy of [false, true])
          if (selectSignInAvailable({ aliasError, machine, patBusy, host: "github.com" })) enabled++
    // idle, repositories and failed, each with a valid alias and no PAT request
    expect(enabled).toBe(3)
  })

  test("agrees with validateAlias for empty, long and taken aliases", () => {
    const connection = {
      id: "c1",
      connectorId: "github",
      alias: "work",
      removed: false,
    } as unknown as Connectors.Connection
    const connectorId = "github" as Connectors.ConnectorID
    const cases: ReadonlyArray<readonly [string, boolean]> = [
      ["personal", true],
      ["", false],
      ["x".repeat(65), false],
      ["work", false],
    ]
    for (const [alias, ok] of cases) {
      const aliasError = validateAlias(alias, connectorId, [connection])
      expect(
        selectSignInAvailable({ aliasError, machine: INITIAL_SIGNIN_STATE, patBusy: false, host: "github.com" }),
      ).toBe(ok)
    }
  })
})
