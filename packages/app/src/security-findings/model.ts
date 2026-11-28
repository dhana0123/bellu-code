export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
export type Severity = (typeof SEVERITIES)[number]

export const FINDING_TYPES = [
  "vulnerability",
  "misconfiguration",
  "secret",
  "license",
  "malware",
  "runtime_threat",
  "ai_risk",
  "data_exposure",
  "identity_risk",
] as const
export type FindingType = (typeof FINDING_TYPES)[number]

export const STATUSES = ["open", "in_progress", "resolved", "ignored", "accepted_risk"] as const
export type Status = (typeof STATUSES)[number]

/** Statuses that need a reason and accept an expiry date. */
export const SNOOZE_STATUSES = ["ignored", "accepted_risk"] as const satisfies readonly Status[]

export const CATEGORIES = [
  "cloud_infrastructure",
  "identity",
  "vulnerabilities",
  "network_exposure",
  "secrets",
  "data_security",
  "code_and_dependencies",
  "runtime",
  "ai_security",
] as const
export type Category = (typeof CATEGORIES)[number]

export interface Evidence {
  kind: string
  ref: string
  line?: number
  excerpt?: string
}

export interface Finding {
  id: string
  ruleId: string
  title: string
  description: string
  category: Category
  type: FindingType
  severity: Severity
  status: Status
  assetId: string
  source: string
  firstSeen: string
  lastSeen: string
  occurrences: number
  riskScore?: number
  evidence: readonly Evidence[]
  /** Lowercased title, rule, asset and source text the search box matches against. */
  searchText: string
}

export interface StatusEvent {
  seq: number
  at: string
  actor: string
  prevStatus?: Status
  newStatus: Status
  reason?: string
}

export interface FilterState {
  search: string
  severity: Severity | "all"
  types: FindingType[]
  statuses: Status[]
  categories: Category[]
  /** Set by clicking a treemap box. */
  asset?: string
}

export const EMPTY_FILTERS: FilterState = {
  search: "",
  severity: "all",
  types: [],
  statuses: [],
  categories: [],
}

export type ViewMode = "table" | "treemap"

export const SORT_KEYS = [
  "title",
  "asset",
  "type",
  "status",
  "severity",
  "risk",
  "firstSeen",
  "lastSeen",
  "source",
] as const
export type SortKey = (typeof SORT_KEYS)[number]
export type SortState = { key: SortKey; dir: "asc" | "desc" } | undefined

/** The sort keys the server orders by. Every other column sorts the rows already loaded. */
export const SERVER_SORT: Partial<Record<SortKey, "severity" | "risk_score" | "first_seen" | "last_seen">> = {
  severity: "severity",
  risk: "risk_score",
  firstSeen: "first_seen",
  lastSeen: "last_seen",
}

export const PAGE_SIZES = [25, 50, 100] as const

/** One group in the summary cards and the treemap. */
export interface Group {
  id: string
  name: string
}
