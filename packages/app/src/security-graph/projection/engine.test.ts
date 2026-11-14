import { describe, expect, test } from "bun:test"
import {
  areaIds,
  areaOrder,
  severities,
  type AttackPath,
  type Entity,
  type EntityType,
  type GraphData,
  type Relationship,
  type Severity,
  type Tag,
} from "../model"
import { generateDelta, generateGraph } from "../mock/generator"
import type { ZoomLevelKey } from "../theme"
import { createEngine, placeRadius, type Visible } from "./engine"

const risk = (label: string): Tag => ({ label, severity: "risk" })
const info = (label: string): Tag => ({ label, severity: "info" })
const rank = (severity: Severity) => severities.indexOf(severity)

function ent(id: string, parentId: string | undefined, severity?: Severity, tags: Tag[] = [], type: EntityType = "module"): Entity {
  return { id, type, name: id, parentId, severity, tags, metadata: {}, provenance: { source: "test", observedAt: 0 } }
}
function rel(id: string, source: string, target: string, relation: Relationship["relation"] = "uses"): Relationship {
  return { id, source, target, relation, directed: true, metadata: {} }
}

const app = areaIds.application
const backend = areaIds.backend

// application > A > (A1 > f1, f2), (A2 > f3);  backend > B > b1, b2
function small(): GraphData {
  const areas = areaOrder.map((key) => ent(areaIds[key], undefined, undefined, [], "cluster"))
  const path: AttackPath = {
    id: "path:1",
    steps: ["r1", "r3", "r9"],
    entry: "f1",
    target: "b2",
    severity: "high",
    evidence: [],
    remediation: "",
  }
  return {
    entities: [
      ...areas,
      ent("A", app),
      ent("A1", "A"),
      ent("A2", "A"),
      ent("f1", "A1", "low", [risk("X")]),
      ent("f2", "A1", "critical", [risk("X"), risk("Y"), info("Z")]),
      ent("f3", "A2", "medium", [risk("Y")]),
      ent("B", backend),
      ent("b1", "B", "high", [risk("W")]),
      ent("b2", "B", "info"),
    ],
    relationships: [
      rel("r1", "f1", "f2", "calls"), // inside A1
      rel("r2", "f1", "f3", "calls"), // inside A
      rel("r3", "f2", "b1"),
      rel("r4", "f3", "b1"),
      rel("r5", "b1", "A1", "reads"),
      rel("r6", "b2", "b1"), // inside B
      rel("r7", areaIds.database, areaIds.cloud),
      rel("r9", "b1", "b2", "writes"),
    ],
    boundaries: [],
    attackPaths: [path],
  }
}

function parentMap(data: GraphData) {
  return new Map(data.entities.map((entity) => [entity.id, entity.parentId]))
}
/** Independent descendant set: every entity whose parent chain reaches `root`. */
function below(data: GraphData, root: string) {
  const parents = parentMap(data)
  return data.entities
    .map((entity) => entity.id)
    .filter((id) => {
      for (let at = parents.get(id); at; at = parents.get(at)) if (at === root) return true
      return false
    })
}
/** Independent owner: the nearest visible node on the entity's own chain. */
function ownerIn(data: GraphData, visible: ReadonlySet<string>) {
  const parents = parentMap(data)
  return (id: string) => {
    for (let at: string | undefined = id; at; at = parents.get(at)) if (visible.has(at)) return at
    return undefined
  }
}
const ids = (view: Visible) => ({ nodes: view.nodes.map((n) => n.id), edges: view.edges.map((e) => e.id) })
const levels: ZoomLevelKey[] = ["L1", "L2", "L3", "L4"]

describe("LOD cut", () => {
  test("L1 shows only the nine areas, L2 adds their children", () => {
    const data = small()
    const engine = createEngine(data)
    expect(engine.project({ level: "L1" }).nodes.map((n) => n.id).sort()).toEqual(Object.values(areaIds).sort())
    const l2 = engine
      .project({ level: "L2" })
      .nodes.map((n) => n.id)
      .sort()
    expect(l2).toEqual([...Object.values(areaIds).filter((id) => id !== app && id !== backend), "A", "B"].sort())
  })

  test("each level shows exactly the entities at its depth or leaves above it", () => {
    const data = small()
    const parents = parentMap(data)
    const depth = (id: string) => {
      let n = 0
      for (let at = parents.get(id); at; at = parents.get(at)) n++
      return n
    }
    const hasKids = (id: string) => data.entities.some((e) => e.parentId === id)
    const engine = createEngine(data)
    const limit = { L1: 0, L2: 1, L3: 2, L4: Infinity }
    for (const level of levels) {
      const expected = data.entities
        .map((e) => e.id)
        .filter((id) => depth(id) === limit[level] || (depth(id) < limit[level] && !hasKids(id)))
      expect(
        engine
          .project({ level })
          .nodes.map((n) => n.id)
          .sort(),
      ).toEqual(expected.sort())
    }
  })
})

describe("manual override", () => {
  test("expanded beats the cut for its own subtree only", () => {
    const engine = createEngine(small())
    engine.expand(app)
    const view = engine.project({ level: "L1" })
    const visible = view.nodes.map((n) => n.id)
    expect(visible).toContain("A")
    expect(visible).not.toContain(app)
    expect(visible).not.toContain("A1") // one level only
    expect(visible).toContain(backend) // other subtree stays at the cut
    expect(visible).not.toContain("B")
    expect(visible).toHaveLength(9)
  })

  test("collapsed hides its subtree at L4 and leaves siblings expanded", () => {
    const engine = createEngine(small())
    engine.collapse("A1")
    const visible = engine.project({ level: "L4" }).nodes.map((n) => n.id)
    expect(visible).toContain("A1")
    expect(visible).not.toContain("f1")
    expect(visible).not.toContain("f2")
    expect(visible).toContain("f3")
    expect(visible).toContain("b1")
  })

  test("an explicit overrides option replaces the engine's own overrides", () => {
    const engine = createEngine(small())
    engine.collapse("A1")
    const view = engine.project({ level: "L4", overrides: new Map() })
    expect(view.nodes.map((n) => n.id)).toContain("f1")
  })
})

describe("aggregates", () => {
  test("collapsed node equals an independent fold over its descendants", () => {
    const data = small()
    const engine = createEngine(data)
    engine.collapse("A")
    const node = engine.project({ level: "L4" }).nodes.find((n) => n.id === "A")!
    expect(node.count).toBe(5)
    expect(node.severity).toBe("critical")
    expect(node.tags).toEqual([
      { label: "X", count: 2 },
      { label: "Y", count: 2 },
    ])
  })

  test("every collapsed node of the generated graph matches the fold", () => {
    const data = generateGraph("100")
    const byId = new Map(data.entities.map((e) => [e.id, e]))
    const engine = createEngine(data)
    for (const level of ["L1", "L2", "L3"] as const) {
      const collapsed = engine.project({ level }).nodes.filter((n) => n.count > 0)
      expect(collapsed.length).toBeGreaterThan(0)
      for (const node of collapsed) {
        const kids = below(data, node.id).map((id) => byId.get(id)!)
        expect(node.count).toBe(kids.length)
        const top = kids.flatMap((k) => (k.severity ? [k.severity] : [])).sort((a, b) => rank(a) - rank(b))
        // severities lists critical first, so the most severe has the lowest index
        expect(node.severity).toBe(top[0] ?? byId.get(node.id)!.severity)
        const union = new Set(kids.flatMap((k) => k.tags.filter((t) => t.severity === "risk").map((t) => t.label)))
        expect(new Set(node.tags.map((t) => t.label))).toEqual(union)
      }
    }
  })
})

describe("edge lifting", () => {
  test("lifted counts + internal + untouched equal the relationships touching a collapsed subtree", () => {
    const data = small()
    const engine = createEngine(data)
    engine.collapse("A")
    const view = engine.project({ level: "L4" })
    const inside = new Set(["A", ...below(data, "A")])
    const touching = data.relationships.filter((r) => inside.has(r.source) || inside.has(r.target))
    const internal = touching.filter((r) => inside.has(r.source) && inside.has(r.target))
    const lifted = view.edges.filter((e) => e.source === "A" || e.target === "A")
    expect(touching).toHaveLength(5)
    expect(internal.map((r) => r.id).sort()).toEqual(["r1", "r2"])
    expect(lifted.reduce((sum, e) => sum + e.count, 0) + internal.length).toBe(touching.length)
    // untouched relationships are carried over one for one
    const untouched = data.relationships.filter((r) => !touching.includes(r))
    const rest = view.edges.filter((e) => e.source !== "A" && e.target !== "A")
    expect(rest.reduce((sum, e) => sum + e.count, 0)).toBe(untouched.length)
    expect(view.edges.every((e) => e.source !== e.target)).toBe(true)
    const duplicate = lifted.find((e) => e.source === "A" && e.target === "b1")!
    expect(duplicate.count).toBe(2)
    expect(duplicate.members.sort()).toEqual(["r3", "r4"])
  })

  test("conserves every relationship at every level of the generated graph", () => {
    const data = generateGraph("100")
    const engine = createEngine(data)
    for (const level of levels) {
      const view = engine.project({ level })
      const visible = new Set(view.nodes.map((n) => n.id))
      const owner = ownerIn(data, visible)
      const internal = data.relationships.filter((r) => owner(r.source) !== undefined && owner(r.source) === owner(r.target)).length
      // The cut shows no expanded container, so a relationship ending on one has no visible owner.
      const parents = new Set(data.entities.flatMap((e) => (e.parentId ? [e.parentId] : [])))
      const orphaned = data.relationships.filter((r) => owner(r.source) === undefined || owner(r.target) === undefined)
      for (const r of orphaned) expect(parents.has(owner(r.source) === undefined ? r.source : r.target)).toBe(true)
      expect(view.edges.reduce((sum, e) => sum + e.count, 0) + internal + orphaned.length).toBe(data.relationships.length)
      for (const edge of view.edges) {
        expect(visible.has(edge.source)).toBe(true)
        expect(visible.has(edge.target)).toBe(true)
        expect(edge.source).not.toBe(edge.target)
      }
    }
  })

  test("a filter applies before lifting and aggregating", () => {
    const data = small()
    const engine = createEngine(data)
    const hideF2 = (e: Entity) => e.id !== "f2"
    const before = engine.project({ level: "L1" }).edges.find((e) => e.source === app && e.target === backend)!
    expect(before.count).toBe(2)
    const view = engine.project({ level: "L1", filter: hideF2 })
    const edge = view.edges.find((e) => e.source === app && e.target === backend)!
    expect(edge.count).toBe(1)
    expect(edge.id).toBe("r4") // a group of one keeps the real relationship id
    engine.collapse("A")
    const node = engine.project({ level: "L4", filter: hideF2 }).nodes.find((n) => n.id === "A")!
    expect(node.count).toBe(4)
    expect(node.severity).toBe("medium")
  })

  test("children of a filtered-out parent move to the nearest kept ancestor", () => {
    const engine = createEngine(small())
    engine.collapse("A")
    const view = engine.project({ level: "L4", filter: (e) => e.id !== "A1" })
    expect(view.nodes.find((n) => n.id === "A")!.count).toBe(4) // A2, f1, f2, f3
    expect(view.nodes.map((n) => n.id)).not.toContain("A1")
  })
})

describe("stable ids", () => {
  test("every visible id is a real id or a deterministic lifted id, at every level and override", () => {
    const data = generateGraph("100")
    const entities = new Set(data.entities.map((e) => e.id))
    const relationships = new Map(data.relationships.map((r) => [r.id, r]))
    const engine = createEngine(data)
    const overridden = data.entities.filter((e) => data.entities.some((c) => c.parentId === e.id)).slice(0, 5)
    for (const pick of [undefined, ...overridden]) {
      for (const mode of ["expanded", "collapsed"] as const) {
        engine.setOverride(pick?.id ?? "", pick ? mode : undefined)
        for (const level of levels) {
          const view = engine.project({ level })
          for (const node of view.nodes) expect(entities.has(node.id)).toBe(true)
          for (const edge of view.edges) {
            if (edge.count === 1) {
              expect(relationships.has(edge.id)).toBe(true)
              expect(edge.members).toEqual([edge.id])
              continue
            }
            expect(edge.id).toBe(`lift:${edge.source}>${edge.target}:${edge.relation}`)
            expect(edge.members.every((m) => relationships.has(m))).toBe(true)
          }
          expect(new Set(view.edges.map((e) => e.id)).size).toBe(view.edges.length)
          expect(ids(createEngine(data).project({ level }))).toEqual(
            ids(createEngine(data).project({ level })),
          )
        }
        engine.setOverride(pick?.id ?? "", undefined)
      }
    }
  })

  test("collapse then expand returns identical visible ids and positions", () => {
    const data = generateGraph("100")
    const engine = createEngine(data)
    const original = engine.project({ level: "L2" })
    const kids = (id: string) => data.entities.filter((e) => e.parentId === id).length
    const target = original.nodes.find((n) => kids(n.id) > 1)!
    engine.expand(target.id)
    const opened = engine.project({ level: "L2" })
    expect(opened.nodes.length).toBeGreaterThan(original.nodes.length)
    engine.collapse(target.id)
    expect(engine.project({ level: "L2" })).toEqual(original)
    engine.expand(target.id)
    const reopened = engine.project({ level: "L2" })
    expect(reopened).toEqual(opened)
    expect(ids(reopened)).toEqual(ids(opened))
  })
})

describe("attack paths", () => {
  test("fully expanded, segments equal the real steps in order", () => {
    const data = small()
    const view = createEngine(data).project({ level: "L4" })
    const path = view.paths[0]
    expect(path.segments.map((s) => s.stepIds)).toEqual([["r1"], ["r3"], ["r9"]])
    expect(path.segments.map((s) => [s.from, s.to])).toEqual([
      ["f1", "f2"],
      ["f2", "b1"],
      ["b1", "b2"],
    ])
  })

  test("a collapsed cut drops internal steps and joins visible ancestors", () => {
    const data = small()
    const view = createEngine(data).project({ level: "L1" })
    const path = view.paths[0]
    expect(path.segments.map((s) => [s.from, s.to, s.stepIds])).toEqual([[app, backend, ["r3"]]])
    expect(path.entry).toBe(app)
    expect(path.target).toBe(backend)
  })

  test("consecutive steps in the same visible pair merge under a derived id", () => {
    const data = small()
    data.attackPaths = [{ ...data.attackPaths[0], steps: ["r3", "r4"] }]
    const path = createEngine(data).project({ level: "L1" }).paths[0]
    expect(path.segments).toHaveLength(1)
    expect(path.segments[0].stepIds).toEqual(["r3", "r4"])
    expect(path.segments[0].count).toBe(2)
    expect(path.segments[0].id).toBe("seg:path:1:r3")
  })

  test("generated paths: segments connect visible ancestors, and L4 equals the real steps", () => {
    const data = generateGraph("100")
    expect(data.attackPaths.length).toBeGreaterThan(0)
    const rels = new Map(data.relationships.map((r) => [r.id, r]))
    const engine = createEngine(data)
    for (const level of levels) {
      const view = engine.project({ level })
      const owner = ownerIn(data, new Set(view.nodes.map((n) => n.id)))
      for (const path of data.attackPaths) {
        const shown = view.paths.find((p) => p.id === path.id)
        const segments = shown?.segments ?? []
        // every segment's endpoints are the visible owners of its real steps
        for (const seg of segments) {
          expect(owner(rels.get(seg.stepIds[0])!.source)).toBe(seg.from)
          expect(owner(rels.get(seg.stepIds[seg.stepIds.length - 1])!.target)).toBe(seg.to)
        }
        // real steps stay in order
        const flat = segments.flatMap((s) => s.stepIds)
        expect(flat).toEqual(path.steps.filter((s) => flat.includes(s)))
        if (level === "L4") expect(flat).toEqual(path.steps)
      }
    }
  })
})

describe("applyDelta", () => {
  test("existing positions are unchanged and new nodes land near their parent", () => {
    const data = small()
    const start = new Map(data.entities.map((e, i) => [e.id, { x: i * 100, y: -i * 37 }]))
    const engine = createEngine(data, start)
    engine.setPosition("f1", 5, 6)
    const before = new Map(engine.positions())
    engine.applyDelta({
      entities: [ent("n1", "A1", "high", [risk("X")]), ent("n2", "n1", "low")],
      relationships: [rel("rn", "n1", "b2")],
    })
    for (const [id, point] of before) expect(engine.position(id)).toEqual(point)
    const dist = (a: { x: number; y: number }, b: { x: number; y: number }) => Math.hypot(a.x - b.x, a.y - b.y)
    expect(dist(engine.position("n1")!, engine.position("A1")!)).toBeLessThanOrEqual(placeRadius)
    expect(dist(engine.position("n2")!, engine.position("n1")!)).toBeLessThanOrEqual(placeRadius)
  })

  test("a node without a parent is placed near its placed neighbors", () => {
    const data = small()
    const engine = createEngine(data, new Map(data.entities.map((e, i) => [e.id, { x: 1000 + i, y: 1000 }])))
    engine.applyDelta({
      entities: [ent("loose", undefined, undefined, [], "cluster")],
      relationships: [rel("rl1", "loose", "f1"), rel("rl2", "loose", "b2")],
    })
    const p = engine.position("loose")!
    const a = engine.position("f1")!
    const b = engine.position("b2")!
    const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }
    expect(Math.hypot(p.x - mid.x, p.y - mid.y)).toBeLessThanOrEqual(placeRadius)
  })

  test("generated delta keeps every position and refreshes the parent's aggregate", () => {
    const data = generateGraph("100")
    const engine = createEngine(data)
    const delta = generateDelta(data, 1)
    const parent = delta.entities![0].parentId!
    engine.collapse(parent)
    const before = new Map(engine.positions())
    const count = engine.project({ level: "L4" }).nodes.find((n) => n.id === parent)!.count
    engine.applyDelta(delta)
    for (const [id, point] of before) expect(engine.position(id)).toEqual(point)
    expect(engine.position(delta.entities![0].id)).toBeDefined()
    expect(engine.project({ level: "L4" }).nodes.find((n) => n.id === parent)!.count).toBe(count + 1)
  })
})
