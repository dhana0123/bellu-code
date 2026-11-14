import type { Relation, Relationship } from "../model"
import type { Hierarchy } from "./hierarchy"

export type LiftedEdge = {
  /** The real relationship id for a group of one; otherwise derived from endpoints and relation. */
  id: string
  /** Visible endpoints. */
  source: string
  target: string
  relation: Relation
  /** Number of relationships replaced by this edge. */
  count: number
  /** Ids of the real relationships, in input order. */
  members: string[]
}

export type Lift = {
  edges: LiftedEdge[]
  /** Relationships dropped because both endpoints sit under the same visible node. */
  internal: number
}

/**
 * Maps every entity to the visible node that stands for it (itself when
 * visible). One pass over each visible subtree's pre-order slice; the cut is an
 * antichain so each entity is written once.
 */
export function visibleOwners(h: Hierarchy, visible: readonly string[]) {
  const owner = new Map<string, string>()
  for (const id of visible) {
    const item = h.nodes.get(id)
    if (!item) continue
    const end = item.start + 1 + item.size
    for (let i = item.start; i < end; i++) owner.set(h.order[i], id)
  }
  return owner
}

/** Deterministic id of a lifted edge. Ids are opaque and never parsed. */
export function liftedId(source: string, target: string, relation: Relation) {
  return `lift:${source}>${target}:${relation}`
}

/**
 * Lifts relationships to the visible cut. Both endpoints map through `owner`;
 * edges that fall inside one visible node are dropped and counted; the rest are
 * grouped by (source, target, relation). Relationships with an endpoint that
 * has no owner (filtered out or unknown) are skipped and not counted.
 */
export function lift(relationships: readonly Relationship[], owner: ReadonlyMap<string, string>): Lift {
  const groups = new Map<string, LiftedEdge>()
  let internal = 0
  for (const rel of relationships) {
    const source = owner.get(rel.source)
    const target = owner.get(rel.target)
    if (source === undefined || target === undefined) continue
    if (source === target) {
      internal++
      continue
    }
    const key = `${source}\0${target}\0${rel.relation}`
    const group = groups.get(key)
    if (group) {
      group.members.push(rel.id)
      group.count++
      continue
    }
    groups.set(key, { id: rel.id, source, target, relation: rel.relation, count: 1, members: [rel.id] })
  }
  const edges: LiftedEdge[] = []
  for (const edge of groups.values()) {
    if (edge.count > 1) edge.id = liftedId(edge.source, edge.target, edge.relation)
    edges.push(edge)
  }
  return { edges, internal }
}

/** Convenience: owners for the cut, then the lift. Prefer sharing `visibleOwners` when it is reused. */
export function liftCut(h: Hierarchy, visible: readonly string[], relationships: readonly Relationship[]) {
  return lift(relationships, visibleOwners(h, visible))
}
