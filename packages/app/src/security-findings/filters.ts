import type { FilterState, Finding, Group, Severity, SortState } from "./model"

/**
 * Narrows the loaded rows by the search text. Severity, type, status, category and asset are filters on the server,
 * so the rows already match them.
 */
export function filterFindings(all: readonly Finding[], filters: FilterState) {
  const query = filters.search.trim().toLowerCase()
  if (!query) return all
  return all.filter((item) => item.searchText.includes(query))
}

/** Counts per severity over the rows given. */
export function severityCounts(list: readonly Finding[]) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  list.forEach((item) => (counts[item.severity] += 1))
  return counts
}

export type RankedGroup = { item: Group; critical: number; high: number }

/** Groups by rule or asset and ranks by critical, then high, findings. */
export function topGroups(list: readonly Finding[], pick: (item: Finding) => Group, limit = 50): RankedGroup[] {
  const groups = new Map<string, RankedGroup>()
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
  group: Group
  critical: number
  high: number
  value: number
  top: "critical" | "high"
}

/** Treemap boxes: one per asset, sized by critical plus high findings, colored by the worst severity. */
export function treemapGroups(groups: readonly RankedGroup[]): TreemapGroup[] {
  return groups
    .map(
      (ranked): TreemapGroup => ({
        group: ranked.item,
        critical: ranked.critical,
        high: ranked.high,
        value: ranked.critical + ranked.high,
        top: ranked.critical > 0 ? "critical" : "high",
      }),
    )
    .sort((a, b) => b.value - a.value)
}

/**
 * Sorts the loaded rows for the columns the server cannot order. A column the server orders is already in order, and
 * sorting it again here could disagree with the server about ties and missing values.
 */
export function sortFindings(list: readonly Finding[], sort: SortState) {
  if (!sort) return list
  const direction = sort.dir === "asc" ? 1 : -1
  const text = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true })
  const compare: Partial<Record<typeof sort.key, (a: Finding, b: Finding) => number>> = {
    title: (a, b) => text(a.title, b.title),
    asset: (a, b) => text(a.assetId, b.assetId),
    type: (a, b) => text(a.type, b.type),
    status: (a, b) => text(a.status, b.status),
    source: (a, b) => text(a.source, b.source),
  }
  const order = compare[sort.key]
  if (!order) return list
  return [...list].sort((a, b) => direction * order(a, b))
}
