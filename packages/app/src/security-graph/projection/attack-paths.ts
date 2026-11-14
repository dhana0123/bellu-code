// Attack-path search. Pure: BFS for the shortest path and a bounded DFS for all risky paths
// from an Internet Exposed entity to PII or Sensitive entities. Results are transient and
// carry structured evidence; the UI formats them with `security.graph.*` i18n keys.
import type { AttackPath, Entity, GraphData, Relation, Relationship, Severity } from "../model"

export const riskyRelations: readonly Relation[] = ["exposes", "calls", "assumes", "reads", "writes"]

export type EvidenceStep = {
  /** Relationship id of the step. */
  step: string
  relation: Relation
  from: string
  to: string
  fromName: string
  toName: string
}

export type FoundPath = Omit<AttackPath, "evidence" | "remediation"> & {
  kind: "shortest" | "risky"
  evidence: EvidenceStep[]
}

export type FindOptions = {
  /** Restrict the search to one target entity. */
  to?: string
  maxDepth?: number
  maxPaths?: number
}

const defaultDepth = 8
const defaultPaths = 50
const defaultSeverity: Severity = "high"
const severityRank: Partial<Record<Severity, number>> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const hasTag = (entity: Entity, match: (label: string) => boolean) => entity.tags.some((tag) => match(tag.label.toLowerCase()))
const isEntry = (entity: Entity) => hasTag(entity, (label) => label === "internet exposed")
const isTarget = (entity: Entity) => hasTag(entity, (label) => label === "pii" || label.startsWith("sensitive"))

export const entriesOf = (data: GraphData): Entity[] => data.entities.filter(isEntry)
export const targetsOf = (data: GraphData): Entity[] => data.entities.filter(isTarget)

export function findAttackPaths(data: GraphData, from: string, options: FindOptions = {}): FoundPath[] {
  const maxDepth = options.maxDepth ?? defaultDepth
  const maxPaths = options.maxPaths ?? defaultPaths
  const byId = new Map(data.entities.map((entity) => [entity.id, entity]))
  const start = byId.get(from)
  if (!start || !isEntry(start)) return []
  const targets = new Set(targetsOf(data).map((entity) => entity.id))
  targets.delete(from)
  if (options.to) {
    for (const id of [...targets]) if (id !== options.to) targets.delete(id)
  }
  if (targets.size === 0) return []

  const out = new Map<string, Relationship[]>()
  const risky = new Set<Relation>(riskyRelations)
  for (const rel of [...data.relationships].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    if (!risky.has(rel.relation) || !byId.has(rel.source) || !byId.has(rel.target)) continue
    const list = out.get(rel.source)
    if (list) list.push(rel)
    else out.set(rel.source, [rel])
  }

  const seen = new Set<string>()
  const results: { kind: FoundPath["kind"]; target: string; rels: Relationship[] }[] = []
  const add = (kind: FoundPath["kind"], target: string, rels: Relationship[]) => {
    const key = rels.map((rel) => rel.id).join("|")
    if (seen.has(key)) return
    seen.add(key)
    results.push({ kind, target, rels })
  }

  // BFS: first discovery of each target is its shortest path.
  const parent = new Map<string, Relationship>()
  const visited = new Set([from])
  const queue = [from]
  for (let head = 0; head < queue.length; head++) {
    const node = queue[head]!
    for (const rel of out.get(node) ?? []) {
      if (visited.has(rel.target)) continue
      visited.add(rel.target)
      parent.set(rel.target, rel)
      queue.push(rel.target)
    }
  }
  for (const target of [...targets].sort()) {
    if (!parent.has(target)) continue
    const rels: Relationship[] = []
    for (let at = target; at !== from; ) {
      const rel = parent.get(at)!
      rels.unshift(rel)
      at = rel.source
    }
    if (rels.length <= maxDepth) add("shortest", target, rels)
  }

  // Bounded DFS over simple paths. A target ends the path.
  const onPath = new Set([from])
  const stack: Relationship[] = []
  const walk = (node: string) => {
    if (results.length >= maxPaths) return
    for (const rel of out.get(node) ?? []) {
      if (results.length >= maxPaths) return
      if (onPath.has(rel.target)) continue
      stack.push(rel)
      if (targets.has(rel.target)) add("risky", rel.target, [...stack])
      else if (stack.length < maxDepth) {
        onPath.add(rel.target)
        walk(rel.target)
        onPath.delete(rel.target)
      }
      stack.pop()
    }
  }
  walk(from)

  const counters = new Map<string, number>()
  return results.slice(0, maxPaths).map(({ kind, target, rels }) => {
    const n = counters.get(target) ?? 0
    counters.set(target, n + 1)
    const evidence = rels.map((rel): EvidenceStep => ({
      step: rel.id,
      relation: rel.relation,
      from: rel.source,
      to: rel.target,
      fromName: byId.get(rel.source)!.name,
      toName: byId.get(rel.target)!.name,
    }))
    const ids = [from, ...rels.map((rel) => rel.target)]
    return {
      id: `found:${from}:${target}:${n}`,
      kind,
      steps: rels.map((rel) => rel.id),
      entry: from,
      target,
      severity: worst(ids.map((id) => byId.get(id)!.severity)),
      evidence,
    }
  })
}

function worst(values: (Severity | undefined)[]): Severity {
  let best: Severity | undefined
  for (const value of values) {
    const rank = value ? severityRank[value] : undefined
    if (rank && (!best || rank > severityRank[best]!)) best = value
  }
  return best ?? defaultSeverity
}

const isUntrusted = (boundary: { id: string; label: string }) => /untrusted/i.test(boundary.id) || /untrusted/i.test(boundary.label)

/** Relationship ids of the path steps that cross between an untrusted boundary and another one. */
export function crossings(data: GraphData, path: Pick<AttackPath, "steps">): string[] {
  const byId = new Map(data.entities.map((entity) => [entity.id, entity]))
  const rels = new Map(data.relationships.map((rel) => [rel.id, rel]))
  const boundaries = new Map(data.boundaries.map((boundary) => [boundary.id, boundary]))
  const boundaryOf = (id: string) => {
    const guard = new Set<string>()
    for (let at = byId.get(id); at && !guard.has(at.id); at = at.parentId ? byId.get(at.parentId) : undefined) {
      if (at.boundaryId) return at.boundaryId
      guard.add(at.id)
    }
    return undefined
  }
  const untrusted = (id: string | undefined) => {
    if (!id) return false
    const boundary = boundaries.get(id)
    return boundary ? isUntrusted(boundary) : isUntrusted({ id, label: "" })
  }
  return path.steps.filter((step) => {
    const rel = rels.get(step)
    if (!rel) return false
    const a = boundaryOf(rel.source)
    const b = boundaryOf(rel.target)
    return a !== b && (untrusted(a) || untrusted(b))
  })
}

/** Converts a found path into a model `AttackPath`, formatting evidence and remediation through the caller's i18n. */
export function toAttackPath(
  found: FoundPath,
  format: { evidence: (step: EvidenceStep) => string; remediation: string },
): AttackPath {
  return {
    id: found.id,
    steps: found.steps,
    entry: found.entry,
    target: found.target,
    severity: found.severity,
    evidence: found.evidence.map(format.evidence),
    remediation: format.remediation,
  }
}
