import { describe, expect, test } from "bun:test"
import { formatCountdown, parseCountdown } from "./countdown"

// Feature: github-app-signin, Property 6: Countdown formatting round trips
// **Validates: Requirements 2.1**
describe("countdown formatting", () => {
  test("round trips for every second from 0 to 7200", () => {
    for (let n = 0; n <= 7200; n++) expect(parseCountdown(formatCountdown(n))).toBe(n)
  })

  test("boundary values", () => {
    const table: [number, string][] = [
      [0, "00:00"],
      [59, "00:59"],
      [60, "01:00"],
      [61, "01:01"],
      [899, "14:59"],
      [900, "15:00"],
      [3599, "59:59"],
      [3600, "60:00"],
    ]
    for (const [n, text] of table) {
      expect(formatCountdown(n)).toBe(text)
      expect(parseCountdown(text)).toBe(n)
    }
  })

  test("negatives clamp to 00:00", () => {
    for (const n of [-1, -59, -60, -3600, -0.5, Number.NEGATIVE_INFINITY, Number.NaN]) {
      expect(formatCountdown(n)).toBe("00:00")
    }
  })

  test("output is always MM:SS shaped", () => {
    for (let n = -100; n <= 7200; n++) expect(formatCountdown(n)).toMatch(/^\d{2,}:[0-5]\d$/)
  })

  test("parse rejects malformed text", () => {
    for (const t of ["", "1:00", "00:60", "00:5", "-1:00", "aa:bb", "00:00 ", "0:0:0"]) {
      expect(parseCountdown(t)).toBeUndefined()
    }
  })
})
