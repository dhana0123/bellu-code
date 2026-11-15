export type NodeKind =
  | "api"
  | "data-model"
  | "dependency"
  | "internal-dependency"
  | "module"
  | "framework"
  | "service"
  | "repository"
  | "cloud-resource"
  | "package"
  | "vulnerability"
  | "account"
export type Tag =
  | "internet-exposed"
  | "sensitive-logic"
  | "pii"
  | "written-to-log"
  | "used-in-code"
  | "test-logic"
  | "web-client"
  | "writes-to-log"
export type Language = "csharp" | "java"
export type Brand = "stripe" | "auth0" | "openai"
export type EdgeKind =
  | "uses"
  | "contains"
  | "runs_on"
  | "on"
  | "owned_by"
  | "attached_to"
  | "mounts"
  | "depends_on"
  | "resolves_to"
  | "found_in"
  | "affected_by"
  | "same_as"
  | "likely_same_as"
  | "related"

export type GraphNode = {
  id: string
  kind: NodeKind
  /** The identifier shown under the type: a route, a package, a module name. */
  name: string
  /** 0 to 1. Sizes the node a little and fades the edges that point at it. */
  importance: number
  /** How many items the node groups. */
  count?: number
  tags?: readonly Tag[]
  /** Language mark floating above a module. */
  language?: Language
  /** Third-party service. Its logo replaces the icon. */
  brand?: Brand
}

export type GraphEdge = {
  source: string
  target: string
  kind: EdgeKind
  /** Bends the edge: 0 is straight. */
  curvature?: number
  /** Drawn dashed: the relation was inferred, not extracted from a source. */
  inferred?: boolean
}

export type GraphData = { nodes: readonly GraphNode[]; edges: readonly GraphEdge[] }
