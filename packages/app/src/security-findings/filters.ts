import type { Component, Finding, FilterState, Resource, Severity, SortState } from "./model"

/** All filters combine with AND. `skip` leaves one out, so a facet can count the options it offers. */
export function filterFindings(all: readonly Finding[], filters: FilterState, skip?: "severity") {
  const query = filters.search.trim().toLowerCase()
  return all.filter(
    (item) =>
      (!query || item.searchText.includes(query)) &&
      (skip === "severity" || filters.severity === "all" || item.severity === filters.severity) &&
      (!filters.hasFix || item.fixVersion !== undefined) &&
      (!filters.hasExploit || item.exploitable) &&
      (filters.resourceTypes.length === 0 || filters.resourceTypes.includes(item.resource.type)) &&
      (filters.dependencyTypes.length === 0 || filters.dependencyTypes.includes(item.component.dependency)) &&
      (filters.relatedSeverities.length === 0 || filters.relatedSeverities.some((level) => item.related[level] > 0)) &&
      (!filters.component || item.component.id === filters.component),
  )
}

export function severityCounts(list: readonly Finding[]) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  list.forEach((item) => (counts[item.severity] += 1))
  return counts
}

export type RankedGroup<T> = { item: T; critical: number; high: number }

/** Groups by component or resource and ranks by critical, then high, findings. */
export function topGroups<T extends Component | Resource>(
  list: readonly Finding[],
  pick: (item: Finding) => T,
  limit = 50,
): RankedGroup<T>[] {
  const groups = new Map<string, RankedGroup<T>>()
  list.forEach((finding) => {
    if (finding.severity !== "critical" && finding.severity !== "high") return
    const item = pick(finding)
    const group = groups.get(item.id) ?? { item, critical: 0, high: 0 }
    group[finding.severity] += 1
    groups.set(item.id, group)
  })
  return [...groups.values()].sort((a, b) => b.critical - a.critical || b.high - a.high).slice(0, limit)
}

export type TreemapGroup = {
  component: Component
  critical: number
  high: number
  value: number
  top: "critical" | "high"
}

/** Treemap boxes: one per component, sized by critical plus high findings, colored by the worst severity. */
export function treemapGroups(groups: readonly RankedGroup<Component>[]): TreemapGroup[] {
  return groups
    .map(
      (group): TreemapGroup => ({
        component: group.item,
        critical: group.critical,
        high: group.high,
        value: group.critical + group.high,
        top: group.critical > 0 ? "critical" : "high",
      }),
    )
    .sort((a, b) => b.value - a.value)
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 } satisfies Record<Severity, number>

export function sortFindings(list: readonly Finding[], sort: SortState) {
  if (!sort) return list
  const direction = sort.dir === "asc" ? 1 : -1
  const text = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true })
  const compare: Record<typeof sort.key, (a: Finding, b: Finding) => number> = {
    cve: (a, b) => text(a.cve, b.cve),
    resource: (a, b) => text(a.resource.name, b.resource.name),
    component: (a, b) => text(a.component.name, b.component.name),
    status: (a, b) => text(a.status, b.status),
    // Ascending severity runs from the least to the most severe.
    severity: (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
    related: (a, b) => a.related.critical - b.related.critical || a.related.high - b.related.high,
    fix: (a, b) => text(a.fixVersion ?? "", b.fixVersion ?? ""),
    detection: (a, b) => text(a.component.dependency, b.component.dependency),
    subscription: (a, b) => text(a.resource.subscription.name, b.resource.subscription.name),
  }
  return [...list].sort((a, b) => direction * compare[sort.key](a, b))
}
