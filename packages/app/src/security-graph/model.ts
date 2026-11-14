export const severities = ["critical", "high", "medium", "low", "info", "remediated", "validated"] as const
export type Severity = (typeof severities)[number]

export const relations = ["uses", "contains", "calls", "reads", "writes", "exposes", "assumes", "depends_on"] as const
export type Relation = (typeof relations)[number]

export const entityTypes = [
  "api",
  "module",
  "service",
  "dependency",
  "package",
  "data-model",
  "framework",
  "cloud-resource",
  "identity",
  "repository",
  "file",
  "function",
  "vulnerability",
  "security-control",
  "ai-agent",
  "external-service",
  "cluster",
] as const
export type EntityType = (typeof entityTypes)[number]

/** Ids of the nine L1 area clusters. They are the roots of the containment hierarchy. */
export const areaIds = {
  application: "area:application",
  backend: "area:backend",
  frontend: "area:frontend",
  database: "area:database",
  cloud: "area:cloud-infrastructure",
  external: "area:external-apis",
  dependencies: "area:dependencies",
  security: "area:security",
  agents: "area:ai-agents",
} as const
export type AreaKey = keyof typeof areaIds
export type AreaID = (typeof areaIds)[AreaKey]

/** Display order of the L1 areas. */
export const areaOrder: readonly AreaKey[] = [
  "application",
  "backend",
  "frontend",
  "database",
  "cloud",
  "external",
  "dependencies",
  "security",
  "agents",
]

export type Tag = { label: string; severity: "risk" | "info" }

export type Metadata = Record<string, string | number | boolean>

export type Entity = {
  id: string
  type: EntityType
  name: string
  /** Containment hierarchy. Area clusters (L1) have no parent. */
  parentId?: string
  repo?: string
  service?: string
  env?: string
  language?: string
  severity?: Severity
  tags: Tag[]
  boundaryId?: string
  sourceLocation?: { path: string; line: number }
  /** Credentials are references only (`secretRef`), never secret values. */
  metadata: Metadata
  provenance: { source: string; observedAt: number }
}

export type Relationship = {
  id: string
  source: string
  target: string
  relation: Relation
  directed: true
  metadata: Metadata
}

export type Boundary = { id: string; label: string; memberIds: string[]; parentId?: string }

export type AttackPath = {
  id: string
  /** Ordered Relationship ids from entry to target. */
  steps: string[]
  entry: string
  target: string
  severity: Severity
  evidence: string[]
  remediation: string
}

export type AgentEvent = {
  agentId: string
  type: "visit" | "traverse" | "finding" | "tool_call"
  entityId: string
  edgeId?: string
  ts: number
}

export type GraphData = {
  entities: Entity[]
  relationships: Relationship[]
  boundaries: Boundary[]
  attackPaths: AttackPath[]
}

/** Incremental update. Existing entities keep their positions when a delta is applied. */
export type GraphDelta = {
  entities?: Entity[]
  relationships?: Relationship[]
  boundaries?: Boundary[]
  attackPaths?: AttackPath[]
}
