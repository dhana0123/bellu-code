import { describe, expect, test } from "bun:test"
import { ClientError } from "@bellucode/client/promise"
import { EMPTY_FILTERS } from "./model"
import { sortFindings } from "./filters"
import { failureReason, rejection, toListInput } from "./query"

// Validates: Requirements 3.2, 20.3
describe("toListInput", () => {
  test("empty filters send only the page size", () => {
    expect(toListInput(EMPTY_FILTERS, undefined)).toEqual({
      severity: undefined,
      type: undefined,
      status: undefined,
      category: undefined,
      asset: undefined,
      sort: undefined,
      limit: 500,
      cursor: undefined,
    })
  })

  test("the filters map to the API filters and the cursor passes through", () => {
    const input = toListInput(
      { ...EMPTY_FILTERS, search: "needle", severity: "info", types: ["secret"], statuses: ["open", "ignored"], asset: "a1" },
      undefined,
      "cur",
    )
    expect(input).toMatchObject({
      severity: ["info"],
      type: ["secret"],
      status: ["open", "ignored"],
      asset: ["a1"],
      cursor: "cur",
    })
    // The API has no search parameter, so the search text stays on the page.
    expect(JSON.stringify(input)).not.toContain("needle")
  })

  test.each([
    [{ key: "severity", dir: "asc" }, "severity"],
    [{ key: "severity", dir: "desc" }, "-severity"],
    [{ key: "risk", dir: "desc" }, "-risk_score"],
    [{ key: "firstSeen", dir: "asc" }, "first_seen"],
    [{ key: "lastSeen", dir: "desc" }, "-last_seen"],
    [{ key: "title", dir: "asc" }, undefined],
    [{ key: "source", dir: "desc" }, undefined],
  ] as const)("sort %j maps to %p", (sort, expected) => {
    expect(toListInput(EMPTY_FILTERS, sort).sort).toBe(expected)
  })
})

describe("sortFindings", () => {
  test("leaves a server-sorted column in the order the server sent", () => {
    const rows = [{ title: "b" }, { title: "a" }] as never
    expect(sortFindings(rows, { key: "severity", dir: "asc" })).toBe(rows)
  })
})

describe("failure classification", () => {
  test("a 404 or a NotFoundError means the API is unavailable", () => {
    expect(failureReason(new ClientError("UnexpectedStatus", { cause: { status: 404 } }))).toBe("unavailable")
    expect(failureReason({ _tag: "NotFoundError", message: "x" })).toBe("unavailable")
  })

  test("other failures are retryable errors", () => {
    expect(failureReason(new ClientError("UnexpectedStatus", { cause: { status: 500 } }))).toBe("error")
    expect(failureReason(new ClientError("Transport"))).toBe("error")
    expect(failureReason(undefined)).toBe("error")
  })

  test("a 400 keeps the field it names", () => {
    expect(rejection({ _tag: "InvalidRequestError", message: "must be in the future", field: "until" })).toEqual({
      field: "until",
      message: "must be in the future",
    })
    expect(rejection({ _tag: "ConflictError", message: "no" })).toEqual({ field: undefined, message: "no" })
  })
})
