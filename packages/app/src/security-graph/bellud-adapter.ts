import type { AgentEvent, GraphData, GraphDelta } from "./model"
import type { GraphSource } from "./source"

/**
 * Adapter seam for the bellud graph (`bellu-graph-native`). Types only; there is no implementation yet.
 *
 * A bellud-backed `GraphSource` replaces the mock without touching the projection engine or renderer.
 * The rendered graph is a projection of the persistent graph, never the source of truth, so the
 * adapter should answer viewport- and level-scoped queries instead of loading everything.
 */

/** A request for the part of the graph the renderer needs at the current zoom. */
export type ProjectionQuery = {
  /** Zoom level, 1 (global) to 4 (code). */
  level: 1 | 2 | 3 | 4
  /** Viewport in graph coordinates. */
  viewport: { x: number; y: number; width: number; height: number }
  /** Hierarchy nodes the user expanded or collapsed manually. */
  overrides: Record<string, "expanded" | "collapsed">
}

export interface BelludGraphAdapter extends GraphSource {
  project(query: ProjectionQuery): Promise<GraphData>
  deltas(): AsyncIterable<GraphDelta>
  agentEvents(): AsyncIterable<AgentEvent>
}
