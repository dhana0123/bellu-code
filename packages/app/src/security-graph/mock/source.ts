import type { GraphData, GraphDelta } from "../model"
import type { GraphSize, GraphSource } from "../source"
import { generateDelta, generateGraph } from "./generator"
import { createMockStream } from "./stream"

export type MockGraphSource = GraphSource & {
  /** Emits the next deterministic delta to subscribers. Returns false until a graph is loaded. */
  emitDelta(): boolean
}

export function createMockSource(): MockGraphSource {
  const listeners = new Set<(delta: GraphDelta) => void>()
  let data: GraphData | undefined
  let count = 0

  return {
    async load(size: GraphSize) {
      data = generateGraph(size)
      count = 0
      return data
    },
    events() {
      return createMockStream(data ?? generateGraph("100"))
    },
    subscribe(onDelta) {
      listeners.add(onDelta)
      return () => {
        listeners.delete(onDelta)
      }
    },
    emitDelta() {
      if (!data) return false
      const delta = generateDelta(data, ++count)
      listeners.forEach((fn) => fn(delta))
      return true
    },
  }
}
