import { describe, expect, test } from "bun:test"
import fc from "fast-check"
import { radialLayout } from "./layout"
import type { GraphData } from "./model"

// A tree of 1 to 30 nodes: node `i` hangs off a parent with a lower index. Edge direction is random.
const tree = fc
  .array(fc.record({ parent: fc.nat(), flip: fc.boolean(), importance: fc.double({ min: 0, max: 0.9, noNaN: true }) }), {
    minLength: 0,
    maxLength: 29,
  })
  .map((rows) => {
    const depth = [0]
    const data: GraphData = {
      nodes: [
        { id: "n0", kind: "module", name: "n0", importance: 1 },
        ...rows.map((row, at) => ({
          id: `n${at + 1}`,
          kind: "module" as const,
          name: `n${at + 1}`,
          importance: row.importance,
        })),
      ],
      edges: rows.map((row, at) => {
        const parent = row.parent % (at + 1)
        depth.push(depth[parent] + 1)
        const ends = row.flip ? [`n${at + 1}`, `n${parent}`] : [`n${parent}`, `n${at + 1}`]
        return { source: ends[0], target: ends[1], kind: "related" as const }
      }),
    }
    return { data, depth }
  })

describe("radialLayout", () => {
  // Feature: unified-security-graph, Property 19: Radial layout places nodes by hop count
  // **Validates: Requirements 8.3**
  test("puts the root at the origin and distance from it strictly increases with hop count", () => {
    fc.assert(
      fc.property(tree, ({ data, depth }) => {
        const { positions } = radialLayout(data)
        expect(positions.size).toBe(data.nodes.length)
        expect(positions.get("n0")).toEqual({ x: 0, y: 0 })
        const distance = data.nodes.map((node) => {
          const point = positions.get(node.id)!
          return Math.hypot(point.x, point.y)
        })
        distance.forEach((a, i) =>
          distance.forEach((b, j) => {
            if (depth[i] < depth[j]) expect(a).toBeLessThan(b)
          }),
        )
      }),
    )
  })
})
