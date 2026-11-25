import { describe, expect, test } from "bun:test"
import { initial, selectLoading, selectLoadingMore, selectRows, transition, type FindingsState } from "./machine"
import { toFinding } from "./query"

// Validates: Requirements 3.2, 20.3
const row = (id: string) =>
  toFinding({
    id,
    ruleId: "rule",
    title: `finding ${id}`,
    description: "",
    category: "vulnerabilities",
    type: "vulnerability",
    severity: "high",
    status: "open",
    assetId: "asset-1",
    evidence: [],
    firstSeen: "2025-01-01T00:00:00Z",
    lastSeen: "2025-01-02T00:00:00Z",
    source: "scanner",
    occurrences: 1,
  })

const ready = (rows: string[], next?: string): FindingsState => ({
  type: "ready",
  attempt: 1,
  rows: rows.map(row),
  next,
  truncated: false,
})

describe("findings list machine", () => {
  test("a result for the current attempt makes the rows ready", () => {
    const next = transition(initial, { type: "loaded", attempt: 1, rows: [row("a")], next: "c1", truncated: false })
    expect(next).toMatchObject({ type: "ready", next: "c1" })
    expect(selectRows(next).map((item) => item.id)).toEqual(["a"])
  })

  test("a result for a stale attempt changes nothing", () => {
    const loading = transition(initial, { type: "query" })
    const next = transition(loading, { type: "loaded", attempt: 1, rows: [row("a")], truncated: false })
    expect(next).toBe(loading)
  })

  test("a query change drops the rows and restarts the load", () => {
    const next = transition(ready(["a"], "c1"), { type: "query" })
    expect(next).toMatchObject({ type: "loading", attempt: 2, rows: [] })
    expect(selectLoading(next)).toBe(true)
  })

  test("refresh during a load keeps that load", () => {
    expect(transition(initial, { type: "refresh" })).toBe(initial)
  })

  test("more keeps the rows, sends the cursor and appends the next page", () => {
    const more = transition(ready(["a"], "c1"), { type: "more" })
    expect(more).toMatchObject({ type: "loading", cursor: "c1" })
    expect(selectLoading(more)).toBe(false)
    expect(selectLoadingMore(more)).toBe(true)
    const done = transition(more, { type: "loaded", attempt: 2, rows: [row("b")], truncated: false })
    expect(selectRows(done).map((item) => item.id)).toEqual(["a", "b"])
  })

  test("more without a next cursor does nothing", () => {
    const state = ready(["a"])
    expect(transition(state, { type: "more" })).toBe(state)
  })

  test("a failed first load ends in failed, and refresh retries it", () => {
    const failed = transition(initial, { type: "failed", attempt: 1, reason: "unavailable" })
    expect(failed).toMatchObject({ type: "failed", reason: "unavailable", rows: [] })
    expect(transition(failed, { type: "refresh" })).toMatchObject({ type: "loading", attempt: 2 })
  })

  test("a failed load of more keeps the rows and retries from the same cursor", () => {
    const failed = transition(transition(ready(["a"], "c1"), { type: "more" }), {
      type: "failed",
      attempt: 2,
      reason: "error",
    })
    expect(selectRows(failed).map((item) => item.id)).toEqual(["a"])
    expect(transition(failed, { type: "more" })).toMatchObject({ type: "loading", cursor: "c1" })
  })

  test("a patched finding replaces the row with the same id", () => {
    const next = transition(ready(["a", "b"]), { type: "patched", finding: { ...row("b"), status: "ignored" } })
    expect(selectRows(next).map((item) => item.status)).toEqual(["open", "ignored"])
  })

  test("a disposed machine ignores every event", () => {
    const disposed = transition(initial, { type: "disposed" })
    expect(transition(disposed, { type: "query" })).toBe(disposed)
  })
})
