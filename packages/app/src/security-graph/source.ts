import type { AgentEvent, GraphData, GraphDelta } from "./model"

export type GraphSize = "100" | "5k" | "50k"

export type EventStream = AsyncIterable<AgentEvent> & { simulated: boolean }

/** All Security Graph data enters through this interface. */
export interface GraphSource {
  load(size: GraphSize): Promise<GraphData>
  events(): EventStream
  subscribe(onDelta: (delta: GraphDelta) => void): () => void
}
