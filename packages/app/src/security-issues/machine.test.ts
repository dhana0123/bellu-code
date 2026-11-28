import { describe, expect, test } from "bun:test"
import {
  complianceInitial,
  complianceTransition,
  detailInitial,
  detailTransition,
  listInitial,
  listTransition,
  selectItems,
} from "./machine"
import { issuesAvailable, issuesConfigFlag } from "../security/issues-enabled"
const issue = (id: string, status: "open" | "resolved" | "ignored" = "open") => ({
  id,
  title: id,
  ruleId: "r",
  severity: "high" as const,
  riskScore: 5,
  status,
  category: "identity" as const,
  includesInferred: false,
  findingCount: 1,
  path: [],
  createdAt: "",
  updatedAt: "",
})
const detail = (id: string, status: "open" | "resolved" | "ignored" = "open") => ({ ...issue(id, status), findings: [] })
describe("issue list", () => {
  test("a stale page is ignored and a filter change drops the rows", () => {
    const first = listTransition(listInitial({}), { type: "loaded", attempt: 1, items: [issue("a")], next: "c1", truncated: false })
    const filtered = listTransition(first, { type: "filter", filters: { severity: "high" } })
    expect(selectItems(filtered)).toEqual([])
    expect(listTransition(filtered, { type: "loaded", attempt: 1, items: [issue("b")], truncated: false })).toBe(filtered)
  })
  test("more appends the next cursor page", () => {
    const first = listTransition(listInitial({}), { type: "loaded", attempt: 1, items: [issue("a")], next: "c1", truncated: false })
    const more = listTransition(first, { type: "more" })
    const done = listTransition(more, { type: "loaded", attempt: 2, items: [issue("b")], truncated: false })
    expect(selectItems(done).map((item) => item.id)).toEqual(["a", "b"])
  })
})
describe("issue detail", () => {
  test("saving blocks a second status change and a late save of a closed issue changes nothing", () => {
    const ready = detailTransition(detailInitial("a"), { type: "loaded", attempt: 1, detail: detail("a") })
    const saving = detailTransition(ready, { type: "setStatus", status: "resolved" })
    expect(saving.type).toBe("saving")
    expect(detailTransition(saving, { type: "setStatus", status: "ignored" })).toBe(saving)
    const closed = detailTransition(saving, { type: "close" })
    expect(detailTransition(closed, { type: "saved", attempt: 1, detail: detail("a", "resolved") })).toBe(closed)
  })
  test("a failed save returns to ready with the error flag", () => {
    const ready = detailTransition(detailInitial("a"), { type: "loaded", attempt: 1, detail: detail("a") })
    const saving = detailTransition(ready, { type: "setStatus", status: "resolved" })
    expect(detailTransition(saving, { type: "saveFailed", attempt: 1 })).toMatchObject({ type: "ready", saveFailed: true })
  })
})
describe("compliance", () => {
  test("the first benchmark loads its controls after the list", () => {
    const loading = complianceTransition(complianceInitial, { type: "start" })
    const next = complianceTransition(loading, { type: "benchmarks", attempt: 1, benchmarks: ["cis", "nist"] })
    expect(next).toMatchObject({ type: "loading", attempt: 2, benchmark: "cis" })
    expect(complianceTransition(next, { type: "controls", attempt: 1, controls: [] })).toBe(next)
  })
})
describe("issues flag", () => {
  test("security_posture decides, and the page needs a probe", () => {
    const doc = (experimental: { security_posture?: boolean; all_flags?: boolean }) => ({ type: "document", info: { experimental } })
    expect(issuesConfigFlag([doc({ security_posture: false })])).toBe(false)
    expect(issuesConfigFlag([doc({ all_flags: true })])).toBe(true)
    expect(issuesAvailable({ flag: undefined, probe: { enabled: true } })).toBe(true)
    expect(issuesAvailable({ flag: false, probe: { enabled: true } })).toBe(false)
  })
})
