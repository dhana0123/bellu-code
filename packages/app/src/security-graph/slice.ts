import type { GraphLensNode, GraphLensSlice } from "@bellucode/client/promise"
import type { EdgeKind, GraphData, GraphEdge, GraphNode, NodeKind, Tag } from "./model"

// Entity kinds the engine reports, mapped to the node kind that draws them. Workflows, pull requests and alerts take the
// repository style; anything unlisted draws as a module.
const KIND = {
  github_org: "account",
  aws_account: "account",
  github_repo: "repository",
  repository: "repository",
  github_workflow: "repository",
  workflow: "repository",
  github_pull_request: "repository",
  github_alert: "repository",
  alert: "repository",
  aws_resource: "cloud-resource",
  image: "cloud-resource",
  package: "package",
  vulnerability: "vulnerability",
} as const satisfies Record<string, NodeKind>

const RELATION = new Set<string>([
  "runs_on",
  "on",
  "owned_by",
  "uses",
  "attached_to",
  "mounts",
  "depends_on",
  "resolves_to",
  "found_in",
  "affected_by",
  "same_as",
  "likely_same_as",
] satisfies EdgeKind[])

// Importance of a node that has no risk score. Containers weigh more than leaves.
const IMPORTANCE = {
  account: 0.6,
  repository: 0.5,
  "cloud-resource": 0.45,
  package: 0.3,
  module: 0.3,
} as const

export function nodeKind(kind: string): NodeKind {
  return Object.hasOwn(KIND, kind) ? KIND[kind as keyof typeof KIND] : "module"
}

export function edgeKind(type: string): EdgeKind {
  return RELATION.has(type) ? (type as EdgeKind) : "related"
}

function importance(kind: NodeKind, risk: GraphLensNode["risk"]) {
  if (kind === "vulnerability") return Math.min(1, Math.max(0, Number(risk?.score ?? 0) / 100))
  return IMPORTANCE[kind as keyof typeof IMPORTANCE] ?? IMPORTANCE.module
}

function tags(node: GraphLensNode): readonly Tag[] | undefined {
  return node.attrs.internet_exposed === "true" ? ["internet-exposed"] : undefined
}

/** Maps a lens slice to the render model. Each node and edge keeps the slice's order. */
export function toGraphData(slice: GraphLensSlice): GraphData {
  const nodes = slice.nodes.map((node): GraphNode => {
    const kind = nodeKind(node.kind)
    const result: GraphNode = { id: node.id, kind, name: node.label, importance: importance(kind, node.risk) }
    const tag = tags(node)
    return tag ? { ...result, tags: tag } : result
  })
  const edges = slice.edges.map(
    (edge): GraphEdge => ({
      source: edge.from,
      target: edge.to,
      kind: edgeKind(edge.type),
      ...(edge.confidence === "inferred" ? { inferred: true } : {}),
    }),
  )
  return { nodes, edges }
}
