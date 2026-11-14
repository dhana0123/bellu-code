// Pure filter predicate and option lists for the filter panel. The driver applies the predicate before projection.
// Dimensions combine with AND, values inside a dimension with OR, and an empty dimension does not filter.
import type { AgentState } from "./agents/events"
import { severities, type Boundary, type Entity, type GraphData } from "./model"
import { filterDimensions, type FilterDimension, type Filters } from "./ui/store"

export type FilterContext = {
  boundaries: readonly Boundary[]
  /** Agent state the agent dimension reads. Without it no entity matches an active agent filter. */
  agents?: AgentState
}

export type FilterOption = {
  value: string
  /** Display text when it differs from the value (boundary label). */
  label: string
  count: number
}

export type FilterOptions = Record<FilterDimension, FilterOption[]>

const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)

/** Ids of every boundary under each root, the root included. */
function boundaryTree(boundaries: readonly Boundary[]) {
  const children = new Map<string, string[]>()
  for (const item of boundaries) {
    if (item.parentId === undefined) continue
    children.set(item.parentId, [...(children.get(item.parentId) ?? []), item.id])
  }
  const byId = new Map(boundaries.map((item) => [item.id, item]))
  return (root: string) => {
    const seen = new Set<string>()
    const walk = (id: string) => {
      if (seen.has(id)) return
      seen.add(id)
      for (const child of children.get(id) ?? []) walk(child)
    }
    walk(root)
    return [...seen].flatMap((id) => (byId.has(id) ? [byId.get(id)!] : []))
  }
}

/** Builds the predicate. It keeps every entity when no dimension has a value. */
export function createFilter(filters: Filters, ctx: FilterContext): (entity: Entity) => boolean {
  const active = filterDimensions.filter((dimension) => filters[dimension].length > 0)
  if (active.length === 0) return () => true

  const set = (dimension: FilterDimension) => new Set(filters[dimension])
  const repository = set("repository")
  const service = set("service")
  const environment = set("environment")
  const type = set("type")
  const tag = set("tag")
  const severity = set("severity")

  // A selected boundary covers its nested boundaries, its member ids and entities that name it as `boundaryId`.
  const boundaryIds = new Set<string>()
  const boundaryMembers = new Set<string>()
  if (filters.boundary.length > 0) {
    const subtree = boundaryTree(ctx.boundaries)
    for (const root of filters.boundary) {
      for (const item of subtree(root)) {
        boundaryIds.add(item.id)
        for (const member of item.memberIds) boundaryMembers.add(member)
      }
    }
  }

  const agentEntities = new Set<string>()
  if (filters.agent.length > 0 && ctx.agents) {
    for (const id of filters.agent) {
      const status = ctx.agents.agents[id]
      if (!status) continue
      for (const entity of status.accessed) agentEntities.add(entity)
      agentEntities.add(status.target)
    }
  }

  const checks: Record<FilterDimension, (entity: Entity) => boolean> = {
    repository: (entity) => entity.repo !== undefined && repository.has(entity.repo),
    service: (entity) => entity.service !== undefined && service.has(entity.service),
    environment: (entity) => entity.env !== undefined && environment.has(entity.env),
    type: (entity) => type.has(entity.type),
    tag: (entity) => entity.tags.some((item) => tag.has(item.label)),
    severity: (entity) => entity.severity !== undefined && severity.has(entity.severity),
    boundary: (entity) =>
      boundaryMembers.has(entity.id) || (entity.boundaryId !== undefined && boundaryIds.has(entity.boundaryId)),
    agent: (entity) => agentEntities.has(entity.id),
  }
  return (entity) => active.every((dimension) => checks[dimension](entity))
}

const count = (map: Map<string, number>, value: string | undefined) => {
  if (value !== undefined) map.set(value, (map.get(value) ?? 0) + 1)
}

const sorted = (map: Map<string, number>, label: (value: string) => string = (value) => value): FilterOption[] =>
  [...map]
    .map(([value, total]) => ({ value, label: label(value), count: total }))
    .sort((a, b) => compare(a.label, b.label) || compare(a.value, b.value))

/** Distinct values per dimension with the number of entities that carry each, sorted for a stable panel. */
export function options(data: Pick<GraphData, "entities" | "boundaries">, agents?: AgentState): FilterOptions {
  const maps = {
    repository: new Map<string, number>(),
    service: new Map<string, number>(),
    environment: new Map<string, number>(),
    type: new Map<string, number>(),
    tag: new Map<string, number>(),
    severity: new Map<string, number>(),
  }
  const known = new Set(data.entities.map((entity) => entity.id))
  for (const entity of data.entities) {
    count(maps.repository, entity.repo)
    count(maps.service, entity.service)
    count(maps.environment, entity.env)
    count(maps.type, entity.type)
    count(maps.severity, entity.severity)
    for (const label of new Set(entity.tags.map((item) => item.label))) count(maps.tag, label)
  }

  const subtree = boundaryTree(data.boundaries)
  const boundaries = new Map<string, number>()
  const labels = new Map(data.boundaries.map((item) => [item.id, item.label]))
  for (const boundary of data.boundaries) {
    const ids = new Set(subtree(boundary.id).map((item) => item.id))
    const members = new Set(subtree(boundary.id).flatMap((item) => item.memberIds.filter((id) => known.has(id))))
    for (const entity of data.entities) if (entity.boundaryId !== undefined && ids.has(entity.boundaryId)) members.add(entity.id)
    boundaries.set(boundary.id, members.size)
  }

  const agentCounts = new Map<string, number>()
  for (const status of Object.values(agents?.agents ?? {})) {
    agentCounts.set(status.id, new Set([...status.accessed, status.target]).size)
  }

  const severityOrder = new Map<string, number>(severities.map((value, index) => [value, index]))
  return {
    repository: sorted(maps.repository),
    service: sorted(maps.service),
    environment: sorted(maps.environment),
    type: sorted(maps.type),
    tag: sorted(maps.tag),
    severity: sorted(maps.severity).sort((a, b) => (severityOrder.get(a.value) ?? 99) - (severityOrder.get(b.value) ?? 99)),
    boundary: sorted(boundaries, (id) => labels.get(id) ?? id),
    agent: sorted(agentCounts),
  }
}
