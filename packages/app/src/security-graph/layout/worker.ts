import Graph from "graphology"
import forceAtlas2 from "graphology-layout-forceatlas2"
import { seedByHierarchy } from "./seed"

/** Runs in a Web Worker. The main thread never runs ForceAtlas2. */
export type LayoutRequest = {
  id: number
  /** Parent index per node, -1 for roots. Nodes are identified by index. */
  parents: Int32Array
  /** Flat `[source0, target0, source1, target1, ...]` node indices. */
  edges: Uint32Array
  /** Upper bound on ForceAtlas2 iterations. */
  iterations: number
  /** Wall-clock bound for the whole run, in milliseconds. */
  budgetMs: number
}

export type LayoutResponse = { id: number; positions: Float32Array } | { id: number; error: string }

type Scope = {
  addEventListener(type: "message", listener: (event: MessageEvent<LayoutRequest>) => void): void
  postMessage(message: LayoutResponse, transfer: Transferable[]): void
}

const scope = self as unknown as Scope

scope.addEventListener("message", (event) => {
  const request = event.data
  try {
    const positions = layout(request)
    scope.postMessage({ id: request.id, positions }, [positions.buffer])
  } catch (error) {
    scope.postMessage({ id: request.id, error: error instanceof Error ? error.message : String(error) }, [])
  }
})

function layout(request: LayoutRequest) {
  const count = request.parents.length
  const positions = seedByHierarchy(request.parents)
  if (count < 2 || request.iterations <= 0) return positions

  const graph = new Graph({ type: "undirected", multi: false })
  for (let i = 0; i < count; i++) graph.addNode(i, { x: positions[i * 2], y: positions[i * 2 + 1] })
  // Containment gives the hierarchy its pull even when no relationship connects siblings.
  request.parents.forEach((parent, i) => {
    if (parent >= 0 && parent < count && parent !== i) graph.mergeEdge(parent, i)
  })
  for (let i = 0; i + 1 < request.edges.length; i += 2) {
    const source = request.edges[i]
    const target = request.edges[i + 1]
    if (source !== target && source < count && target < count) graph.mergeEdge(source, target)
  }

  const settings = {
    ...forceAtlas2.inferSettings(graph),
    barnesHutOptimize: count > 2000,
    strongGravityMode: true,
    gravity: 0.5,
  }
  const deadline = performance.now() + request.budgetMs
  const chunk = 10
  for (let done = 0; done < request.iterations && performance.now() < deadline; done += chunk) {
    forceAtlas2.assign(graph, { iterations: Math.min(chunk, request.iterations - done), settings })
  }

  graph.forEachNode((node, attributes) => {
    const x = attributes.x as number
    const y = attributes.y as number
    positions[Number(node) * 2] = Number.isFinite(x) ? x : positions[Number(node) * 2]
    positions[Number(node) * 2 + 1] = Number.isFinite(y) ? y : positions[Number(node) * 2 + 1]
  })
  return positions
}
