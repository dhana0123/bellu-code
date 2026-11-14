import { hierarchy } from "d3-hierarchy"
import { areaIds, type Entity } from "../model"

export type HierarchyNode = {
  id: string
  /** Undefined for roots (area clusters). */
  parent?: string
  /** 0 for roots. */
  depth: number
  children: readonly string[]
  /** Number of descendants, excluding the node itself. */
  size: number
  /** Position in `Hierarchy.order`; the descendants follow it contiguously. */
  start: number
}

export type Hierarchy = {
  nodes: ReadonlyMap<string, HierarchyNode>
  roots: readonly string[]
  /** Pre-order of every node: each subtree is a contiguous slice. */
  order: readonly string[]
}

type Datum = { id: string; kids: Datum[] }

/**
 * Builds the containment hierarchy from `parentId`, iteratively (d3-hierarchy
 * walks with explicit stacks, so 50k-deep chains do not overflow the call stack).
 * An unknown parent, a self parent or a parent cycle attaches the node to its
 * area root. `areaOf` picks that root for a node; by default it is the
 * Application area, or the first root when that is absent.
 */
export function buildHierarchy(entities: readonly Entity[], areaOf?: (entity: Entity) => string | undefined): Hierarchy {
  const byId = new Map(entities.map((entity) => [entity.id, entity]))
  const roots = entities.filter((entity) => !entity.parentId).map((entity) => entity.id)
  const fallback = roots.includes(areaIds.application) ? areaIds.application : roots[0]
  const areaRoot = (entity: Entity) => {
    const area = areaOf?.(entity)
    if (area && byId.has(area) && !byId.get(area)?.parentId) return area
    return fallback
  }
  const parents = new Map<string, string | undefined>()
  for (const entity of entities) {
    const parent = entity.parentId
    if (!parent) parents.set(entity.id, undefined)
    else if (byId.has(parent) && parent !== entity.id) parents.set(entity.id, parent)
    else parents.set(entity.id, areaRoot(entity))
  }
  breakCycles(parents, byId, areaRoot)

  const data = new Map<string, Datum>(entities.map((entity) => [entity.id, { id: entity.id, kids: [] }]))
  const top: Datum[] = []
  for (const entity of entities) {
    const datum = data.get(entity.id)!
    const parent = parents.get(entity.id)
    if (parent) data.get(parent)!.kids.push(datum)
    else top.push(datum)
  }

  const root = hierarchy<Datum>({ id: "", kids: top }, (datum) => datum.kids)
  const nodes = new Map<string, HierarchyNode>()
  const order: string[] = []
  root.eachBefore((node) => {
    if (!node.parent) return
    const id = node.data.id
    nodes.set(id, {
      id,
      parent: node.parent.parent ? node.parent.data.id : undefined,
      depth: node.depth - 1,
      children: (node.children ?? []).map((child) => child.data.id),
      size: 0,
      start: order.length,
    })
    order.push(id)
  })
  // Children follow their parent in pre-order, so one reverse pass sums subtrees.
  for (let i = order.length - 1; i >= 0; i--) {
    const item = nodes.get(order[i])!
    const parent = item.parent ? nodes.get(item.parent) : undefined
    if (parent) parent.size += item.size + 1
  }
  return { nodes, roots: top.map((datum) => datum.id), order }
}

// Parents form a functional graph; a cycle can never reach a root. Walk each
// chain once and reattach the node that closes a cycle to its area root.
function breakCycles(
  parents: Map<string, string | undefined>,
  byId: ReadonlyMap<string, Entity>,
  areaRoot: (entity: Entity) => string | undefined,
) {
  const done = new Set<string>()
  for (const start of parents.keys()) {
    if (done.has(start)) continue
    const path = new Set<string>()
    let id: string | undefined = start
    while (id && !done.has(id)) {
      if (path.has(id)) {
        parents.set(id, areaRoot(byId.get(id)!))
        break
      }
      path.add(id)
      id = parents.get(id)
    }
    for (const seen of path) done.add(seen)
  }
}

export function node(h: Hierarchy, id: string) {
  return h.nodes.get(id)
}

/** Descendant ids in pre-order, excluding the node itself. */
export function descendants(h: Hierarchy, id: string): string[] {
  const item = h.nodes.get(id)
  if (!item) return []
  return h.order.slice(item.start + 1, item.start + 1 + item.size)
}

/** Ancestor ids from the parent up to the root. */
export function ancestors(h: Hierarchy, id: string): string[] {
  const result: string[] = []
  let parent = h.nodes.get(id)?.parent
  while (parent) {
    result.push(parent)
    parent = h.nodes.get(parent)?.parent
  }
  return result
}

