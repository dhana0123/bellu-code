import { describe, expect, test } from "bun:test"
import fc from "fast-check"
import type { OverlayEvent } from "@bellucode/schema/graph"
import { playable } from "./overlay"

// Small id pool so events and rendered sets overlap often.
const id = fc.constantFrom("a", "b", "c", "d", "e", "f")

const event = fc.record(
  {
    seq: fc.nat(),
    entity: id,
    action: fc.constantFrom("focus_node", "walk_path", "proposed_change"),
    path: fc.array(id, { maxLength: 6 }),
    explanation: fc.string(),
  },
  { requiredKeys: ["seq", "entity", "action", "explanation"] },
) as fc.Arbitrary<OverlayEvent>

const events = fc.array(event, { maxLength: 20 })
const nodes = fc.uniqueArray(id).map((ids) => new Set<string>(ids))

describe("playable", () => {
  // Feature: unified-security-graph, Property 22: Playable events are exactly those naming rendered entities
  // **Validates: Requirements 9.5**
  test("keeps exactly the events naming rendered entities, in order, with absent path ids trimmed", () => {
    fc.assert(
      fc.property(events, nodes, (input, rendered) => {
        const out = playable(input, rendered)
        const expected = input.filter((item) => rendered.has(item.entity))

        expect(out.map((item) => item.seq)).toEqual(expected.map((item) => item.seq))
        out.forEach((item, index) => {
          const source = expected[index]
          expect({ ...item, path: undefined }).toEqual({ ...source, path: undefined })
          if (source.path === undefined) return expect(item.path).toBeUndefined()
          expect(item.path).toEqual(source.path.filter((node) => rendered.has(node)))
          expect(item.path!.every((node) => rendered.has(node))).toBe(true)
        })
      }),
      { numRuns: 200 },
    )
  })

  test("drops absent path ids and keeps the rest of a walk", () => {
    const out = playable(
      [{ seq: 1, entity: "a", action: "walk_path", path: ["a", "x", "b"], explanation: "walk" }],
      new Set(["a", "b"]),
    )
    expect(out[0].path).toEqual(["a", "b"])
  })
})
