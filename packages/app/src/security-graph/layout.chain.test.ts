import { describe, expect, test } from "bun:test"
import fc from "fast-check"
import type { GraphData } from "./model"
import { chainLayout } from "./layout"

// An acyclic slice: edges only run from a lower to a higher index, then the node list is shuffled so the layout
// cannot rely on input order being topological.
const slice = fc
  .integer({ min: 1, max: 12 })
  .chain((size) => {
    const ids = Array.from({ length: size }, (_, at) => `n${at}`)
    const pairs = ids.flatMap((source, at) => ids.slice(at + 1).map((target) => ({ source, target })))
    return fc.record({
      ids: fc.shuffledSubarray(ids, { minLength: size, maxLength: size }),
      edges: fc.subarray(pairs),
    })
  })
  .map(
    (input): GraphData => ({
      nodes: input.ids.map((id) => ({ id, kind: "module", name: id, importance: 0.5 })),
      edges: input.edges.map((edge) => ({ ...edge, kind: "uses" })),
    }),
  )

describe("chainLayout", () => {
  // Feature: unified-security-graph, Property 20: Chain layout increases left to right along every path
  // **Validates: Requirements 8.4**
  test("x strictly increases from each node to the next along every edge, so along every path", () => {
    fc.assert(
      fc.property(slice, (data) => {
        const layout = chainLayout(data)
        expect(layout.positions.size).toBe(data.nodes.length)
        data.edges.forEach((edge) =>
          expect(layout.positions.get(edge.target)!.x).toBeGreaterThan(layout.positions.get(edge.source)!.x),
        )
      }),
    )
  })
})
