export const SEVERITIES = ["critical", "high", "medium", "low"] as const
export type Severity = (typeof SEVERITIES)[number]

export const RESOURCE_TYPES = ["container-image", "serverless", "virtual-machine", "repository"] as const
export type ResourceType = (typeof RESOURCE_TYPES)[number]

export const DEPENDENCY_TYPES = ["os-package", "library", "file-path"] as const
export type DependencyType = (typeof DEPENDENCY_TYPES)[number]

export type Provider = "aws" | "azure" | "gcp" | "github"
export type Tech = "java" | "python" | "javascript" | "go" | "os" | "browser"

export interface Subscription {
  provider: Provider
  name: string
  id: string
}

export interface Resource {
  id: string
  name: string
  type: ResourceType
  subscription: Subscription
}

export interface Component {
  id: string
  name: string
  version: string
  /** Display type such as "DPKG OS Package". Mock data stands in for what a scanner reports. */
  kind: string
  dependency: DependencyType
  tech: Tech
}

export interface Finding {
  id: string
  cve: string
  severity: Severity
  status: "unresolved"
  resource: Resource
  component: Component
  fixVersion?: string
  exploitable: boolean
  /** Count of related risk issues per severity. */
  related: Record<Severity, number>
  description: string
  cvss: number
  /** Lowercased CVE, component, and resource text the search box matches against. */
  searchText: string
}

export interface FilterState {
  search: string
  severity: Severity | "all"
  hasFix: boolean
  hasExploit: boolean
  resourceTypes: ResourceType[]
  dependencyTypes: DependencyType[]
  relatedSeverities: Severity[]
  /** Set by clicking a treemap box. */
  component?: string
}

export const EMPTY_FILTERS: FilterState = {
  search: "",
  severity: "all",
  hasFix: false,
  hasExploit: false,
  resourceTypes: [],
  dependencyTypes: [],
  relatedSeverities: [],
}

export type ViewMode = "table" | "treemap"

export const SORT_KEYS = [
  "cve",
  "resource",
  "component",
  "status",
  "severity",
  "related",
  "fix",
  "detection",
  "subscription",
] as const
export type SortKey = (typeof SORT_KEYS)[number]
export type SortState = { key: SortKey; dir: "asc" | "desc" } | undefined

export const PAGE_SIZES = [25, 50, 100] as const
