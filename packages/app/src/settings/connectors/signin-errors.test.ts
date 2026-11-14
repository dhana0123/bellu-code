import { describe, expect, test } from "bun:test"
import { Connectors } from "@bellucode/schema/connectors"
import { dict } from "@/runtime/i18n/en"
import { failureMessage, signInFailureMessage, type ConnectorFailure } from "./errors"

// Validates: Requirements 13.6, 13.7 (Property 35: every error code has a message)
const text = (key: string) => (dict as Record<string, unknown>)[key]
const codes: readonly Connectors.ErrorCode[] = Connectors.ErrorCode.literals
const expectMessage = (key: string) => {
  const value = text(key)
  expect(typeof value).toBe("string")
  expect((value as string).trim().length).toBeGreaterThan(0)
}

describe("sign-in error messages", () => {
  test("the schema enumerates the expected codes", () => {
    expect(codes.length).toBe(22)
  })

  test.each([...codes])("%s maps to an English message", (code) => {
    const connector: ConnectorFailure = { kind: "connector", code, offenders: ["a"] }
    for (const result of [failureMessage(connector), signInFailureMessage(code)]) {
      expect(result.plural).toBeUndefined()
      expectMessage(result.key)
    }
  })

  test.each([
    ["request_timeout", signInFailureMessage("request_timeout")],
    ["unknown", failureMessage({ kind: "unknown" })],
    ["timeout", failureMessage({ kind: "timeout" })],
    ["unavailable", failureMessage({ kind: "unavailable" })],
  ])("%s maps to an English message", (_, result) => expectMessage(result.key))

  test("rate_limited with retryAfterSec uses a plural base with one and other forms", () => {
    const result = failureMessage({ kind: "connector", code: "rate_limited", offenders: [], retryAfterSec: 5 })
    expect(result.plural).toEqual({ key: "settings.connectors.error.rateLimited.retry", count: 5 })
    expectMessage(`${result.plural!.key}.one`)
    expectMessage(`${result.plural!.key}.other`)
    expectMessage(result.key)
    expect(signInFailureMessage("rate_limited", 1).plural?.count).toBe(1)
  })

  test("rate_limited without a positive retry time has no plural", () => {
    expect(signInFailureMessage("rate_limited").plural).toBeUndefined()
    expect(signInFailureMessage("rate_limited", 0).plural).toBeUndefined()
  })

  test("an unmapped code falls back to the unknown message", () => {
    const failure = { kind: "connector", code: "not_a_code", offenders: [] } as unknown as ConnectorFailure
    const result = failureMessage(failure)
    expect(result.key).toBe("settings.connectors.error.unknown")
    expectMessage(result.key)
  })
})
