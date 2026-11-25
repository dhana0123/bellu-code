import type { SbomSummary } from "@bellucode/client/promise"
export const UNKNOWN_LICENSE = "unknown"
export const PAGE_LIMIT = 500
export const ROW_HEIGHT = 36
export type ExportFormat = "cyclonedx" | "spdx"
export const EXPORT_FORMATS: readonly ExportFormat[] = ["cyclonedx", "spdx"]
/** A blank or NOASSERTION license counts as unknown. */
export const licenseKey = (value: string) => {
  const trimmed = value.trim()
  return trimmed === "" || trimmed.toUpperCase() === "NOASSERTION" ? UNKNOWN_LICENSE : trimmed
}
/** Sums counts by key, folding the unknown license spellings into one bucket, most common first. */
export function tally(counts: readonly Record<string, number>[], normalize: (key: string) => string = (key) => key) {
  const totals = new Map<string, number>()
  counts.forEach((entry) =>
    Object.entries(entry).forEach(([key, count]) => totals.set(normalize(key), (totals.get(normalize(key)) ?? 0) + count)),
  )
  return [...totals].map(([key, count]) => ({ key, count })).toSorted((a, b) => b.count - a.count || a.key.localeCompare(b.key))
}
export const ecosystemCounts = (assets: readonly Pick<SbomSummary, "ecosystems">[]) =>
  tally(assets.map((asset) => asset.ecosystems))
export const licenseCounts = (assets: readonly Pick<SbomSummary, "licenses">[]) =>
  tally(assets.map((asset) => asset.licenses), licenseKey)
export const exportName = (assetId: string, format: ExportFormat) =>
  `${assetId.replace(/[^\w.-]+/g, "_")}.${format === "spdx" ? "spdx" : "cdx"}.json`
