export type NodeKind = "api" | "data-model" | "dependency" | "internal-dependency" | "module" | "framework" | "service"
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
export type EdgeKind = "uses" | "contains"

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
}

export type GraphData = { nodes: readonly GraphNode[]; edges: readonly GraphEdge[] }
