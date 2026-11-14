import type { AttackPath, Relationship, Severity } from "../model"

export type Segment = {
  /** The real step id for a group of one; otherwise derived from the path and its first step. */
  id: string
  /** Visible endpoints. */
  from: string
  to: string
  /** Ids of the real steps this segment stands for, in path order. */
  stepIds: string[]
  count: number
  /** Severity of the owning attack path. */
  severity: Severity
}

/** Deterministic id of a merged segment. Ids are opaque and never parsed. */
export function segmentId(pathId: string, firstStepId: string) {
  return `seg:${pathId}:${firstStepId}`
}

/**
 * Aggregates one attack path onto the visible cut. Each step's endpoints map
 * through `owner`; a step inside one visible node vanishes; consecutive steps
 * that map to the same visible pair merge. Steps whose relationship is unknown
 * or whose endpoint has no owner (filtered out) are skipped. With every node
 * visible the result is the real steps in order.
 */
export function aggregatePath(
  path: AttackPath,
  relationship: (id: string) => Relationship | undefined,
  owner: ReadonlyMap<string, string>,
): Segment[] {
  const result: Segment[] = []
  for (const stepId of path.steps) {
    const rel = relationship(stepId)
    if (!rel) continue
    const from = owner.get(rel.source)
    const to = owner.get(rel.target)
    if (from === undefined || to === undefined || from === to) continue
    const last = result[result.length - 1]
    if (last && last.from === from && last.to === to) {
      last.stepIds.push(stepId)
      last.count++
      last.id = segmentId(path.id, last.stepIds[0])
      continue
    }
    result.push({ id: stepId, from, to, stepIds: [stepId], count: 1, severity: path.severity })
  }
  return result
}
