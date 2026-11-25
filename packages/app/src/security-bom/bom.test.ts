import { describe, expect, test } from "bun:test"
import {
  assetsInitial,
  assetsTransition,
  exportInitial,
  exportTransition,
  packagesInitial,
  packagesTransition,
} from "./machine"
import { ecosystemCounts, licenseCounts } from "./model"
const at = (state: { type: string; attempt?: number }) => state.attempt ?? -1
const pkg = { name: "a", licenses: [], locations: [] }
const asset = (id: string) => ({ assetId: id, digest: "d", packageCount: 1, createdAt: "", ecosystems: {}, licenses: {} })
describe("sbom counts", () => {
  test("sums by ecosystem and folds blank licenses into unknown", () => {
    const assets: { ecosystems: Record<string, number>; licenses: Record<string, number> }[] = [
      { ecosystems: { npm: 2 }, licenses: { MIT: 1, "": 1 } },
      { ecosystems: { npm: 1, pypi: 5 }, licenses: { NOASSERTION: 2, MIT: 1 } },
    ]
    expect(ecosystemCounts(assets)).toEqual([{ key: "pypi", count: 5 }, { key: "npm", count: 3 }])
    expect(licenseCounts(assets)).toEqual([{ key: "unknown", count: 3 }, { key: "MIT", count: 2 }])
  })
})
describe("assets machine", () => {
  test("ignores a stale result", () => {
    const next = assetsTransition(assetsTransition({ type: "failed", attempt: 1, reason: "error" }, { type: "refresh" }), {
      type: "loaded",
      attempt: 1,
      assets: [asset("x")],
    })
    expect(next).toEqual({ type: "loading", attempt: 2 })
    expect(assetsTransition(next, { type: "loaded", attempt: 2, assets: [] }).type).toBe("ready")
    expect(assetsTransition(assetsInitial, { type: "disposed" })).toEqual({ type: "disposed" })
  })
})
describe("packages machine", () => {
  test("selecting another asset drops the old result", () => {
    const first = packagesTransition(packagesInitial, { type: "select", assetId: "a" })
    const second = packagesTransition(first, { type: "select", assetId: "b" })
    expect(packagesTransition(second, { type: "loaded", attempt: at(first), packages: [pkg] })).toBe(second)
  })
  test("more appends and a failed page retries from its cursor", () => {
    let state = packagesTransition(packagesInitial, { type: "select", assetId: "a" })
    state = packagesTransition(state, { type: "loaded", attempt: at(state), packages: [pkg], next: "c1" })
    state = packagesTransition(state, { type: "more" })
    state = packagesTransition(state, { type: "failed", attempt: at(state) })
    state = packagesTransition(state, { type: "retry" })
    state = packagesTransition(state, { type: "loaded", attempt: at(state), packages: [pkg] })
    expect(state.type === "ready" && state.packages.length).toBe(2)
  })
})
describe("export machine", () => {
  test("a second start while exporting is ignored", () => {
    const running = exportTransition(exportInitial, { type: "start" })
    expect(exportTransition(running, { type: "start" })).toBe(running)
    expect(exportTransition(running, { type: "done", attempt: 9 })).toBe(running)
  })
})
