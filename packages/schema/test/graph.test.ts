import { describe, expect, test } from "bun:test"
import { Arbitrary, Effect, Schema } from "effect"
import { Graph } from "../src/graph.js"

const at = { observed_at: "2026-01-01T00:00:00Z", recorded_at: "2026-01-01T00:00:01Z" }
const entity = { id: "e1", type: "host", attributes: { name: "a", tags: ["x"], n: 1 }, ...at }
const edge = { from: "e1", to: "e2", type: "runs", direction: "out", hops: 1 }
const change = { kind: "added", subject: "entity", entity: "e1", ...at }

const cases = [
  ["Graph.EntityID", Graph.EntityID, "e1", ""],
  ["Graph.Attributes", Graph.Attributes, { a: { b: [1, null] } }, []],
  ["Graph.Entity", Graph.Entity, entity, { ...entity, attributes: undefined }],
  ["Graph.Direction", Graph.Direction, "both", "sideways"],
  ["Graph.Edge", Graph.Edge, edge, { ...edge, hops: 0 }],
  ["Graph.ChangeKind", Graph.ChangeKind, "removed", "renamed"],
  ["Graph.ChangeSubject", Graph.ChangeSubject, "relation", "node"],
  ["Graph.Change", Graph.Change, change, { ...change, kind: "renamed" }],
  ["Graph.EntityPage", Graph.EntityPage, { items: [entity], total: 1, truncated: false, limit: 100 }, { items: [], total: 0, truncated: false, limit: 1001 }],
  ["Graph.EdgePage", Graph.EdgePage, { items: [edge], total: 1, truncated: true, limit: 1 }, { items: [edge], total: -1, truncated: false, limit: 1 }],
  ["Graph.ChangePage", Graph.ChangePage, { items: [change], total: 1, truncated: false, limit: 1000 }, { items: [{}], total: 1, truncated: false, limit: 1 }],
  [
    "Graph.Diff",
    Graph.Diff,
    { from: at.observed_at, to: at.recorded_at, added: [entity], changed: [], removed: ["e2"], truncated: false },
    { from: at.observed_at, to: at.recorded_at, added: [], changed: [], removed: [1], truncated: false },
  ],
  ["Graph.SchemaType", Graph.SchemaType, { name: "host", count: 2 }, { name: "host", count: -1 }],
  [
    "Graph.SchemaSummary",
    Graph.SchemaSummary,
    { entity_types: [{ name: "host", count: 1 }], relation_types: [] },
    { entity_types: [] },
  ],
  ["Graph.EngineState", Graph.EngineState, "ready", "degraded"],
  ["Graph.ChildState", Graph.ChildState, "degraded", "unknown"],
  ["Graph.Status", Graph.Status, { engine: "ready", ts_child: "degraded" }, { engine: "ready", ts_child: "on" }],
] as const

describe("Graph wire schemas", () => {
  for (const [identifier, schema, valid, invalid] of cases) {
    test(`${identifier} decodes a valid value and rejects an invalid one`, () => {
      expect(schema.ast.annotations?.identifier).toBe(identifier)
      expect(Schema.decodeUnknownSync(schema as Schema.Decoder<unknown>)(valid)).toEqual(valid)
      expect(() => Schema.decodeUnknownSync(schema as Schema.Decoder<unknown>)(invalid)).toThrow()
    })
  }

  test("identifiers are unique and optional fields omit undefined when encoding", () => {
    expect(new Set(cases.map((item) => item[0])).size).toBe(cases.length)
    expect(
      Schema.encodeSync(Graph.Status)({ engine: "ready", ts_child: "ready", detail: undefined }),
    ).toEqual({ engine: "ready", ts_child: "ready" })
  })
})

describe("Graph wire schemas round trip", () => {
  // Property: for every Graph.* schema, decode(encode(x)) equals x for all generated x.
  // **Validates: Requirements 17.3, 17.9**
  for (const [identifier, schema] of cases) {
    test(`${identifier} encode/decode round trips generated values`, async () => {
      const codec = schema as unknown as Schema.Codec<unknown, unknown>
      const result = await Effect.runPromise(
        Arbitrary.checkEffect(
          Arbitrary.schema(codec),
          (value) =>
            Effect.sync(() => {
              const decoded = Schema.decodeUnknownSync(codec)(Schema.encodeSync(codec)(value))
              expect(decoded).toEqual(value)
              return true
            }),
          { runs: 100 },
        ),
      )
      expect(result._tag).toBe("Passed")
    })
  }
})
