import type { Entity, Severity } from "../model"
import { severities } from "../theme"
import type { Hierarchy } from "./hierarchy"

export type TagCount = { label: string; count: number }

export type Aggregate = {
  /** Highest Severity_Scale rank among the descendants; undefined when none has a severity. */
  severity?: Severity
  /** Number of descendants, excluding the node itself. */
  count: number
  /** Risk tags of the descendants, deduplicated by label, in first-seen pre-order. */
  tags: TagCount[]
}

export function severityRank(severity: Severity) {
  return severities[severity].rank
}

/** The more severe of two optional severities by Severity_Scale rank. The first wins a tie. */
export function maxSeverity(a: Severity | undefined, b: Severity | undefined) {
  if (!a) return b
  if (!b) return a
  return severityRank(b) > severityRank(a) ? b : a
}

/**
 * Folds the descendants of one node. Descendants are a contiguous slice of the
 * pre-order, so this walks them in place without allocating. A label counts
 * once per entity, however often the entity repeats it.
 */
export function aggregateNode(h: Hierarchy, entities: ReadonlyMap<string, Entity>, id: string): Aggregate {
  const item = h.nodes.get(id)
  if (!item) return { count: 0, tags: [] }
  const tags = new Map<string, number>()
  let severity: Severity | undefined
  const end = item.start + 1 + item.size
  for (let i = item.start + 1; i < end; i++) {
    const entity = entities.get(h.order[i])
    if (!entity) continue
    severity = maxSeverity(severity, entity.severity)
    const seen = entity.tags.length > 1 ? new Set<string>() : undefined
    for (const tag of entity.tags) {
      if (tag.severity !== "risk") continue
      if (seen) {
        if (seen.has(tag.label)) continue
        seen.add(tag.label)
      }
      tags.set(tag.label, (tags.get(tag.label) ?? 0) + 1)
    }
  }
  return {
    severity,
    count: item.size,
    tags: Array.from(tags, ([label, count]) => ({ label, count })),
  }
}

/**
 * Aggregates for every collapsed node of a cut: visible nodes that have
 * descendants. The cut is an antichain, so subtrees are disjoint and the whole
 * pass is linear in the number of entities.
 */
export function aggregate(h: Hierarchy, entities: ReadonlyMap<string, Entity>, visible: readonly string[]) {
  const result = new Map<string, Aggregate>()
  for (const id of visible) {
    if (!h.nodes.get(id)?.size) continue
    result.set(id, aggregateNode(h, entities, id))
  }
  return result
}
