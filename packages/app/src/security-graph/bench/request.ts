import { iterationBudget, type LayoutRequest } from "../layout/compute"
import type { GraphData } from "../model"
/** Builds the same layout request as `layout/client.ts`. */
export function layoutRequest(data: Pick<GraphData, "entities" | "relationships">): LayoutRequest {
  const index = new Map(data.entities.map((entity, i) => [entity.id, i]))
  return {
    id: 0,
    parents: Int32Array.from(data.entities, (entity) => index.get(entity.parentId ?? "") ?? -1),
    edges: Uint32Array.from(
      data.relationships.flatMap((edge) => {
        const source = index.get(edge.source)
        const target = index.get(edge.target)
        return source === undefined || target === undefined ? [] : [source, target]
      }),
    ),
    iterations: iterationBudget(data.entities.length),
    budgetMs: 10_000,
  }
}
