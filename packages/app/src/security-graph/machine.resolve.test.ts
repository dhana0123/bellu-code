import { describe, expect, test } from "bun:test"
import { resolveLens } from "./machine"

// Property 17, as an exhaustive generated table: fast-check is not a dependency of packages/app.
// Validates: Requirements 8.8
const pool = ["", "attack-paths", "identity", "exposure", "x"]
const DEFAULT = "default"

function* lists(): Generator<readonly string[]> {
  for (let mask = 0; mask < 1 << pool.length; mask++) {
    const subset = pool.filter((_, i) => mask & (1 << i))
    yield subset
    yield [...subset].reverse()
    yield [...subset, DEFAULT]
  }
}

describe("Property 17: resolveLens restores the stored lens only when listed", () => {
  test("returns stored when listed, the default otherwise, for every stored id and lens list", () => {
    let cases = 0
    for (const list of lists()) {
      for (const stored of [undefined, ...pool, "missing", "Identity"]) {
        const expected = stored !== undefined && list.includes(stored) ? stored : DEFAULT
        expect(resolveLens(stored, list, DEFAULT)).toBe(expected)
        cases++
      }
    }
    expect(cases).toBeGreaterThan(500)
  })

  test("an unlisted stored id and an empty list fall back to the default", () => {
    expect(resolveLens("identity", [], DEFAULT)).toBe(DEFAULT)
    expect(resolveLens(undefined, ["identity"], DEFAULT)).toBe(DEFAULT)
    expect(resolveLens("identity", ["identity"], DEFAULT)).toBe("identity")
  })
})
