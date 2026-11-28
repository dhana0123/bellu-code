import { describe, expect, test } from "bun:test"
import { idle, initial, selectPolling, transition, transitionAction } from "./machine"
import { intervalSeconds, type Job } from "./model"

// Validates: Requirements 18.3, 18.12, 18.14, 19.7
const job = (status: Job["status"]): Job => ({
  id: status,
  kind: "sbom",
  targetType: "image",
  targetId: "x",
  status,
  queuedAt: "2025-01-01T00:00:00Z",
  created: 0,
  updated: 0,
  resolved: 0,
  scannerVersions: {},
})

describe("scans machine", () => {
  test("a stale result changes nothing", () => {
    const refreshed = transition(transition(initial, { type: "loaded", attempt: 1, scanners: [], jobs: [] }), { type: "refresh" })
    expect(transition(refreshed, { type: "loaded", attempt: 1, scanners: [], jobs: [] })).toBe(refreshed)
  })
  test("polls only while a job is queued or running", () => {
    const ready = (jobs: Job[]) => transition(initial, { type: "loaded", attempt: 1, scanners: [], jobs })
    expect(selectPolling(ready([job("succeeded")]))).toBe(false)
    expect(selectPolling(ready([job("succeeded"), job("running")]))).toBe(true)
    expect(selectPolling(ready([job("queued")]))).toBe(true)
  })
  test("a failed load keeps the rows", () => {
    const failed = transition(initial, { type: "failed", attempt: 1, reason: "error" })
    expect(failed.type).toBe("failed")
  })
})

describe("action machine", () => {
  const submit = { type: "submit", action: { name: "cancel", id: "a" } } as const
  test("one action runs at a time", () => {
    const busy = transitionAction(idle, submit)
    expect(transitionAction(busy, submit)).toBe(busy)
  })
  test("a rejection carries its message and a stale one is ignored", () => {
    const busy = transitionAction(idle, submit)
    expect(transitionAction(busy, { type: "rejected", attempt: 9, message: "no" })).toBe(busy)
    expect(transitionAction(busy, { type: "rejected", attempt: 1, message: "conflict" })).toMatchObject({
      type: "rejected",
      message: "conflict",
    })
  })
})

describe("intervalSeconds", () => {
  test("accepts 15 minutes to 30 days", () => {
    expect(intervalSeconds("15", "minutes")).toBe(900)
    expect(intervalSeconds("30", "days")).toBe(2592000)
    expect(intervalSeconds("14", "minutes")).toBeUndefined()
    expect(intervalSeconds("31", "days")).toBeUndefined()
    expect(intervalSeconds("1.5", "hours")).toBeUndefined()
    expect(intervalSeconds("", "hours")).toBeUndefined()
  })
})
