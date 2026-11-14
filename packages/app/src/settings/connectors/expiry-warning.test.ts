import { describe, expect, test } from "bun:test"
import { selectExpiryWarning } from "./expiry-warning"

// Property 26: "Expires soon" shows inside the open window only. Validates: Requirements 9.3
const WEEK = 7 * 24 * 60 * 60 * 1000
const now = Date.UTC(2025, 0, 1)
const at = (remaining: number) => new Date(now + remaining).toISOString()

describe("selectExpiryWarning", () => {
  const cases: [string, string, string | null | undefined, "expired" | "soon" | undefined][] = [
    ["just before 7 days", "ACTIVE", at(WEEK - 1), "soon"],
    ["exactly 7 days", "ACTIVE", at(WEEK), undefined],
    ["beyond 7 days", "ACTIVE", at(WEEK + 1), undefined],
    ["1 ms remaining", "ACTIVE", at(1), "soon"],
    ["exactly 0 remaining", "ACTIVE", at(0), undefined],
    ["past expiry, not yet EXPIRED", "ACTIVE", at(-1), undefined],
    ["no expiry (undefined)", "ACTIVE", undefined, undefined],
    ["no expiry (null)", "ACTIVE", null, undefined],
    ["invalid timestamp", "ACTIVE", "not-a-date", undefined],
    ["EXPIRED with past expiry", "EXPIRED", at(-1000), "expired"],
    ["EXPIRED inside window", "EXPIRED", at(1000), "expired"],
    ["EXPIRED without expiry", "EXPIRED", null, "expired"],
    ["PAUSED inside window", "PAUSED", at(1000), "soon"],
    ["ERROR inside window", "ERROR", at(WEEK - 1), "soon"],
    ["INITIATED inside window", "INITIATED", at(1000), "soon"],
    ["VERIFYING at 7 days", "VERIFYING", at(WEEK), undefined],
  ]
  for (const [name, status, exp, want] of cases) {
    test(name, () => {
      expect(selectExpiryWarning({ status, credentialExpiresAt: exp }, now)).toBe(want)
    })
  }
})
