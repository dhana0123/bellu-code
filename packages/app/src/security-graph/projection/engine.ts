import { areaIds, type Entity, type EntityType, type GraphData, type GraphDelta, type Relationship, type Severity } from "../model"
import type { ZoomLevelKey } from "../theme"
import { aggregateNode, type Aggregate, type TagCount } from "./aggregate"
import { ancestors as hierarchyAncestors, buildHierarchy, type Hierarchy } from "./hierarchy"
import { lift, visibleOwners, type LiftedEdge } from "./lift"
import { cut, type Override, type Overrides } from "./lod"
import { aggregatePath, type Segment } from "./paths"

export type Point = { x: number; y: number }

export type VisibleNode = {
  id: string
  /** The entity this node stands for. Equal to `id`: visible ids are entity ids. */
  entityId: string
  type: EntityType
  name: string
  /** Aggregated over the descendants when the node is collapsed. */
  severity?: Severity
  /** Number of hidden descendants; 0 for leaves. */
  count: number
  /** Risk tags with counts: aggregated for a collapsed node, the node's own for a leaf. */
  tags: TagCount[]
  expanded: boolean
  hasChildren: boolean
  x: number
  y: number
}

export type VisiblePath = {
  id: string
  /** Visible ancestors of the real entry and target. */
  entry: string
  target: string
  severity: Severity
  segments: Segment[]
}

export type VisibleBoundary = {
  id: string
  label: string
  parentId?: string
  /** Visible nodes that stand for the boundary's members, deduplicated. */
  memberIds: string[]
}

export type Visible = {
  nodes: VisibleNode[]
  edges: LiftedEdge[]
  paths: VisiblePath[]
  boundaries: VisibleBoundary[]
}

export type ProjectOptions = {
  level: ZoomLevelKey
  /** Falls back to the engine's own overrides (see expand, collapse, setOverride). */
  overrides?: Overrides
  /** Applied before projection: hidden entities are removed, then edges are lifted. */
  filter?: (entity: Entity) => boolean
}

export type Engine = {
  project(options: ProjectOptions): Visible
  expand(id: string): void
  collapse(id: string): void
  /** `undefined` clears the override. */
  setOverride(id: string, override: Override | undefined): void
  overrides(): Overrides
  applyDelta(delta: GraphDelta): void
  entity(id: string): Entity | undefined
  relationship(id: string): Relationship | undefined
  /** Ancestor ids from the parent up to the area root. */
  ancestors(id: string): string[]
  search(query: string, limit?: number): Entity[]
  position(id: string): Point | undefined
  setPosition(id: string, x: number, y: number): void
  /** Live view of the position cache. Do not mutate. */
  positions(): ReadonlyMap<string, Point>
}

/** Largest distance a new node lands from its anchor. */
export const placeRadius = 48
/** Scatter radius for a node with no placed parent or neighbor. */
const strayRadius = 400

type Context = { h: Hierarchy; entities: ReadonlyMap<string, Entity>; agg: Map<string, Aggregate> }

// Entities that lose their parent land in the area their type belongs to.
const typeArea: Partial<Record<EntityType, string>> = {
  "cloud-resource": areaIds.cloud,
  cluster: areaIds.cloud,
  dependency: areaIds.dependencies,
  package: areaIds.dependencies,
  framework: areaIds.dependencies,
  "external-service": areaIds.external,
  "security-control": areaIds.security,
  vulnerability: areaIds.security,
  "ai-agent": areaIds.agents,
  "data-model": areaIds.database,
}
const areaOf = (entity: Entity) => typeArea[entity.type]

function hash(text: string) {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

/** Deterministic offset from the id hash, at most `radius` long. */
function offset(id: string, radius: number): Point {
  const h = hash(id)
  const angle = ((h & 0xffff) / 0x10000) * Math.PI * 2
  const distance = radius * (0.5 + 0.5 * (h >>> 16) / 0x10000)
  return { x: Math.cos(angle) * distance, y: Math.sin(angle) * distance }
}

function markOrphan(entity: Entity): Entity {
  if (entity.provenance.source.includes("orphan")) return entity
  return {
    ...entity,
    provenance: { ...entity.provenance, source: `${entity.provenance.source} (orphan: unknown parent ${entity.parentId})` },
  }
}

export function createEngine(data: GraphData, positions: ReadonlyMap<string, Point> = new Map()): Engine {
  const entities = new Map<string, Entity>()
  const relationships = new Map<string, Relationship>()
  const boundaries = new Map(data.boundaries.map((item) => [item.id, item]))
  const attackPaths = new Map(data.attackPaths.map((item) => [item.id, item]))
  const neighbors = new Map<string, Set<string>>()
  const cache = new Map<string, Point>()
  const own = new Map<string, Override>()
  for (const [id, point] of positions) cache.set(id, { x: point.x, y: point.y })

  let relList: Relationship[] | undefined
  let base: Context
  let filtered: { filter: (entity: Entity) => boolean; context: Context } | undefined
  let index: { id: string; lower: string }[] | undefined

  function link(rel: Relationship) {
    for (const [a, b] of [
      [rel.source, rel.target],
      [rel.target, rel.source],
    ]) {
      const set = neighbors.get(a)
      if (set) set.add(b)
      else neighbors.set(a, new Set([b]))
    }
  }

  function ingest(items: readonly Entity[], rels: readonly Relationship[]) {
    for (const item of items) entities.set(item.id, item)
    for (const item of items) {
      if (item.parentId && !entities.has(item.parentId)) entities.set(item.id, markOrphan(item))
    }
    for (const rel of rels) {
      relationships.set(rel.id, rel)
      link(rel)
    }
    relList = undefined
    index = undefined
    filtered = undefined
  }

  function build(all: ReadonlyMap<string, Entity>): Context {
    return { h: buildHierarchy(Array.from(all.values()), areaOf), entities: all, agg: new Map() }
  }

  function place(ids: readonly string[], h: Hierarchy) {
    const order = ids
      .filter((id) => !cache.has(id) && h.nodes.has(id))
      .sort((a, b) => h.nodes.get(a)!.start - h.nodes.get(b)!.start)
    for (const id of order) {
      const parent = h.nodes.get(id)!.parent
      let anchor = parent ? cache.get(parent) : undefined
      let radius = placeRadius
      if (!anchor) {
        let sx = 0
        let sy = 0
        let n = 0
        for (const other of neighbors.get(id) ?? []) {
          const point = cache.get(other)
          if (!point) continue
          sx += point.x
          sy += point.y
          n++
        }
        if (n) anchor = { x: sx / n, y: sy / n }
      }
      if (!anchor) {
        anchor = { x: 0, y: 0 }
        radius = strayRadius
      }
      const delta = offset(id, radius)
      cache.set(id, { x: anchor.x + delta.x, y: anchor.y + delta.y })
    }
  }

  ingest(data.entities, data.relationships)
  base = build(entities)
  place(Array.from(entities.keys()), base.h)

  function context(filter?: (entity: Entity) => boolean): Context {
    if (!filter) return base
    if (filtered?.filter === filter) return filtered.context
    const kept = new Map<string, Entity>()
    for (const [id, item] of entities) if (filter(item)) kept.set(id, item)
    // A hidden parent hands its children to the nearest kept ancestor.
    const resolved = new Map<string, Entity>()
    for (const [id, item] of kept) {
      let parent = item.parentId
      let guard = entities.size
      while (parent && !kept.has(parent) && guard-- > 0) {
        const next = entities.get(parent)
        if (!next) break
        parent = next.parentId
      }
      resolved.set(id, parent === item.parentId ? item : { ...item, parentId: parent })
    }
    const context = build(resolved)
    filtered = { filter, context }
    return context
  }

  function rels() {
    return (relList ??= Array.from(relationships.values()))
  }

  function aggregateOf(ctx: Context, id: string) {
    let value = ctx.agg.get(id)
    if (!value) {
      value = aggregateNode(ctx.h, ctx.entities, id)
      ctx.agg.set(id, value)
    }
    return value
  }

  function project(options: ProjectOptions): Visible {
    const ctx = context(options.filter)
    const overrides = options.overrides ?? own
    const ids = cut(ctx.h, options.level, overrides)
    const owner = visibleOwners(ctx.h, ids)
    const nodes: VisibleNode[] = []
    for (const id of ids) {
      const item = ctx.entities.get(id)
      const info = ctx.h.nodes.get(id)
      if (!item || !info) continue
      const collapsed = info.size > 0
      const agg = collapsed ? aggregateOf(ctx, id) : undefined
      const point = cache.get(id) ?? { x: 0, y: 0 }
      nodes.push({
        id,
        entityId: id,
        type: item.type,
        name: item.name,
        severity: agg ? (agg.severity ?? item.severity) : item.severity,
        count: info.size,
        tags: agg ? agg.tags : leafTags(item),
        expanded: !collapsed && info.children.length > 0 && overrides.get(id) === "expanded",
        hasChildren: info.children.length > 0,
        x: point.x,
        y: point.y,
      })
    }
    const edges = lift(rels(), owner).edges
    const paths: VisiblePath[] = []
    for (const path of attackPaths.values()) {
      const segments = aggregatePath(path, (id) => relationships.get(id), owner)
      if (!segments.length) continue
      paths.push({
        id: path.id,
        entry: owner.get(path.entry) ?? segments[0].from,
        target: owner.get(path.target) ?? segments[segments.length - 1].to,
        severity: path.severity,
        segments,
      })
    }
    const visibleBoundaries: VisibleBoundary[] = []
    for (const boundary of boundaries.values()) {
      const members = new Set<string>()
      for (const id of boundary.memberIds) {
        const visible = owner.get(id)
        if (visible !== undefined) members.add(visible)
      }
      if (!members.size) continue
      visibleBoundaries.push({ id: boundary.id, label: boundary.label, parentId: boundary.parentId, memberIds: Array.from(members) })
    }
    return { nodes, edges, paths, boundaries: visibleBoundaries }
  }

  function applyDelta(delta: GraphDelta) {
    const added = delta.entities ?? []
    // Branches whose aggregates change: ancestors of every touched entity, before and after.
    const touched = new Set<string>()
    for (const item of added) {
      touched.add(item.id)
      for (const id of hierarchyAncestors(base.h, item.id)) touched.add(id)
    }
    const fresh = added.filter((item) => !cache.has(item.id)).map((item) => item.id)
    ingest(added, delta.relationships ?? [])
    for (const item of delta.boundaries ?? []) boundaries.set(item.id, item)
    for (const item of delta.attackPaths ?? []) attackPaths.set(item.id, item)
    const agg = base.agg
    base = build(entities)
    for (const item of added) for (const id of hierarchyAncestors(base.h, item.id)) touched.add(id)
    for (const [id, value] of agg) if (!touched.has(id)) base.agg.set(id, value)
    // New relationships can move a neighbor-placed node's anchor only for nodes placed now.
    place(fresh, base.h)
  }

  function search(query: string, limit = 20) {
    const text = query.trim().toLowerCase()
    if (!text) return []
    index ??= Array.from(entities.values(), (item) => ({ id: item.id, lower: item.name.toLowerCase() }))
    const hits: { id: string; score: number }[] = []
    for (const entry of index) {
      const at = entry.lower.indexOf(text)
      if (at < 0) continue
      const score = entry.lower === text ? 0 : at === 0 ? 1 : 2
      hits.push({ id: entry.id, score })
    }
    hits.sort((a, b) => a.score - b.score || entities.get(a.id)!.name.length - entities.get(b.id)!.name.length || (a.id < b.id ? -1 : 1))
    return hits.slice(0, limit).map((hit) => entities.get(hit.id)!)
  }

  return {
    project,
    expand: (id) => void own.set(id, "expanded"),
    collapse: (id) => void own.set(id, "collapsed"),
    setOverride(id, override) {
      if (override) own.set(id, override)
      else own.delete(id)
    },
    overrides: () => own,
    applyDelta,
    entity: (id) => entities.get(id),
    relationship: (id) => relationships.get(id),
    ancestors: (id) => hierarchyAncestors(base.h, id),
    search,
    position: (id) => cache.get(id),
    setPosition(id, x, y) {
      cache.set(id, { x, y })
    },
    positions: () => cache,
  }
}

function leafTags(item: Entity): TagCount[] {
  const seen = new Set<string>()
  const result: TagCount[] = []
  for (const tag of item.tags) {
    if (tag.severity !== "risk" || seen.has(tag.label)) continue
    seen.add(tag.label)
    result.push({ label: tag.label, count: 1 })
  }
  return result
}
