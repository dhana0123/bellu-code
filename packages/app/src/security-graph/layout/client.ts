import type { GraphData } from "../model"
import { iterationBudget } from "./compute"
import type { LayoutRequest, LayoutResponse } from "./worker"
import { gridPositions, seedByHierarchy } from "./seed"

export type Point = { x: number; y: number }

export type LayoutResult = {
  positions: ReadonlyMap<string, Point>
  /** `cache`: nothing to compute. `worker`: ForceAtlas2 ran. `fallback`: grid after a worker failure. */
  source: "cache" | "worker" | "fallback"
  /** Set when the worker failed; the view shows a warning. */
  warning?: string
}

const workerTimeoutMs = 30_000

/**
 * Global layout. Positions are cached by entity id and pinned: ForceAtlas2 runs
 * (in a worker) only while the cache is empty. Entities that appear later are
 * placed next to their parent without moving anything else.
 */
export function createLayoutClient() {
  const cache = new Map<string, Point>()
  let worker: Worker | undefined
  let nextId = 0

  function spawn() {
    worker ??= new Worker(new URL("./worker.ts", import.meta.url), { type: "module" })
    return worker
  }

  function drop() {
    worker?.terminate()
    worker = undefined
  }

  function run(request: Omit<LayoutRequest, "id">) {
    return new Promise<Float32Array>((resolve, reject) => {
      const id = nextId++
      const target = spawn()
      const timer = setTimeout(() => finish(() => reject(new Error("layout worker timed out"))), workerTimeoutMs)
      const finish = (settle: () => void) => {
        clearTimeout(timer)
        target.removeEventListener("message", onMessage)
        target.removeEventListener("error", onError)
        target.removeEventListener("messageerror", onError)
        settle()
      }
      const onMessage = (event: MessageEvent<LayoutResponse>) => {
        if (event.data.id !== id) return
        const data = event.data
        finish(() => ("error" in data ? reject(new Error(data.error)) : resolve(data.positions)))
      }
      const onError = (event: Event) =>
        finish(() => reject(new Error(event instanceof ErrorEvent ? event.message : "layout worker failed")))
      target.addEventListener("message", onMessage)
      target.addEventListener("error", onError)
      target.addEventListener("messageerror", onError)
      target.postMessage({ ...request, id }, [request.parents.buffer, request.edges.buffer])
    })
  }

  return {
    /** Cached position of an entity, if it has one. */
    get: (id: string) => cache.get(id),
    /** Pins a position, for example after a drag. */
    set: (id: string, point: Point) => void cache.set(id, point),
    clear: () => cache.clear(),
    dispose: drop,
    async layout(data: Pick<GraphData, "entities" | "relationships">): Promise<LayoutResult> {
      const ids = data.entities.map((entity) => entity.id)
      if (cache.size > 0) {
        placeMissing(cache, data)
        return { positions: new Map(ids.map((id) => [id, cache.get(id)!])), source: "cache" }
      }
      const index = new Map(ids.map((id, i) => [id, i]))
      const parents = Int32Array.from(data.entities, (entity) => index.get(entity.parentId ?? "") ?? -1)
      const edges = Uint32Array.from(
        data.relationships.flatMap((edge) => {
          const source = index.get(edge.source)
          const target = index.get(edge.target)
          return source === undefined || target === undefined ? [] : [source, target]
        }),
      )
      // Seed fallback inputs are kept: the worker takes ownership of the transferred buffers.
      const grid = gridPositions(ids.length)
      const request = { parents, edges, iterations: iterationBudget(ids.length), budgetMs: 10_000 }
      const result = await run(request).then(
        (positions) => ({ positions, source: "worker" as const }),
        (error: unknown) => {
          drop()
          return {
            positions: grid,
            source: "fallback" as const,
            warning: error instanceof Error ? error.message : String(error),
          }
        },
      )
      ids.forEach((id, i) => cache.set(id, { x: result.positions[i * 2], y: result.positions[i * 2 + 1] }))
      return {
        positions: new Map(ids.map((id) => [id, cache.get(id)!])),
        source: result.source,
        ...(result.source === "fallback" ? { warning: result.warning } : {}),
      }
    },
  }
}

/** Places entities without a cached position near their parent, on the main thread (O(new)). */
function placeMissing(cache: Map<string, Point>, data: Pick<GraphData, "entities">) {
  const missing = data.entities.filter((entity) => !cache.has(entity.id))
  if (missing.length === 0) return
  // Parents first, so a new subtree lands around its new root.
  const pending = new Map(missing.map((entity) => [entity.id, entity]))
  const place = (id: string, guard: number): void => {
    const entity = pending.get(id)
    if (!entity) return
    pending.delete(id)
    const parent = entity.parentId
    if (parent && guard < 64) place(parent, guard + 1)
    const anchor = (parent ? cache.get(parent) : undefined) ?? { x: 0, y: 0 }
    const offset = seedByHierarchy(Int32Array.of(-1, 0), hash(id))
    cache.set(entity.id, { x: anchor.x + offset[2] * 0.2, y: anchor.y + offset[3] * 0.2 })
  }
  missing.forEach((entity) => place(entity.id, 0))
}

function hash(text: string) {
  return Array.from(text).reduce((acc, char) => (Math.imul(acc, 31) + char.charCodeAt(0)) | 0, 7)
}
