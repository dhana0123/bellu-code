import Graph from "graphology"
import forceAtlas2 from "graphology-layout-forceatlas2"
import FA2Layout from "graphology-layout-forceatlas2/worker"
import type { GraphData } from "./model"

export type Point = { x: number; y: number }
export type Boundary = Point & { radius: number }
export type Layout = { positions: ReadonlyMap<string, Point>; boundary: Boundary | undefined }
export type LayoutKind = "force" | "radial" | "chain"
/** Distance between rings of the radial layout. */
const RING = 170
/** Distance between ranks, and between nodes of one rank, in the chain layout. */
const COLUMN = 240
const ROW = 150

/**
 * Graph units are roughly pixels at the zoom the page opens at. The force layout knows nothing about labels, so after
 * it settles the nodes are pushed apart until each has this much room: its icon, the text under it and its tags.
 */
const WIDTH = 2300
const SPACING = { x: 205, y: 155 }
/** Ring the third-party services sit on, and the space the boundary leaves around them. */
const SERVICE_RING = 125
const BOUNDARY_PADDING = 115
const BOUNDARY_GAP = 90
/** How long the worker runs. Enough for a graph this size to settle; the layout is also stopped by `signal`. */
const RUN_MS = 1300

/**
 * Positions every node. The layered part of the graph runs through ForceAtlas2 in a web worker. The third-party
 * services are then placed on a ring beside it, inside a boundary circle that no other node can enter.
 */
export async function computeLayout(
  data: GraphData,
  signal: AbortSignal,
  kind: LayoutKind = "force",
): Promise<Layout | undefined> {
  if (kind === "radial") return signal.aborted ? undefined : radialLayout(data)
  if (kind === "chain") return signal.aborted ? undefined : chainLayout(data)
  const services = new Set(data.nodes.filter((node) => node.kind === "service").map((node) => node.id))
  const core = new Graph({ type: "undirected", multi: false })
  data.nodes.filter((node) => !services.has(node.id)).forEach((node) => core.addNode(node.id, seed(node.id)))
  data.edges.forEach((edge) => {
    if (services.has(edge.source) || services.has(edge.target)) return
    core.mergeEdge(edge.source, edge.target)
  })

  const settled = await settle(core, signal)
  if (!settled) return undefined

  const positions = new Map<string, Point>()
  const frame = spread(core)
  frame.forEach((point, id) => positions.set(id, point))
  if (services.size === 0) return { positions, boundary: undefined }

  const boundary = placeServices(data, services, frame, positions)
  return { positions, boundary }
}

/** The layout a lens uses: blast radius spreads from its entity, attack paths run left to right. */
export function layoutFor(lensId: string): LayoutKind {
  if (lensId === "blast-radius") return "radial"
  if (lensId === "attack-path") return "chain"
  return "force"
}
/**
 * Pure and synchronous. The root is the most important node (the first on a tie) and sits at the origin. A node at
 * `h` hops sits on the ring of radius `h * RING`, in an angle sector proportional to the leaves under it.
 */
export function radialLayout(data: GraphData): Layout {
  const positions = new Map<string, Point>()
  if (data.nodes.length === 0) return { positions, boundary: undefined }
  const adjacent = new Map<string, string[]>(data.nodes.map((node) => [node.id, []]))
  data.edges.forEach((edge) => {
    if (edge.source === edge.target) return
    adjacent.get(edge.source)?.push(edge.target)
    adjacent.get(edge.target)?.push(edge.source)
  })
  const root = data.nodes.reduce((best, node) => (node.importance > best.importance ? node : best)).id
  const children = new Map<string, string[]>()
  const depth = new Map<string, number>([[root, 0]])
  const order = [root]
  for (let index = 0; index < order.length; index++) {
    const id = order[index]
    const next: string[] = []
    adjacent.get(id)?.forEach((other) => {
      if (depth.has(other)) return
      depth.set(other, depth.get(id)! + 1)
      next.push(other)
      order.push(other)
    })
    children.set(id, next)
  }
  // Nodes the root cannot reach hang off it as extra branches of the first ring.
  data.nodes.forEach((node) => {
    if (depth.has(node.id)) return
    const stack = [node.id]
    depth.set(node.id, 1)
    children.set(root, [...(children.get(root) ?? []), node.id])
    while (stack.length) {
      const id = stack.pop()!
      const next: string[] = []
      adjacent.get(id)?.forEach((other) => {
        if (depth.has(other)) return
        depth.set(other, depth.get(id)! + 1)
        next.push(other)
        stack.push(other)
      })
      children.set(id, next)
    }
  })
  const leaves = new Map<string, number>()
  ;[...depth.keys()].reverse().forEach((id) => {
    const below = children.get(id) ?? []
    leaves.set(id, below.length === 0 ? 1 : below.reduce((sum, child) => sum + (leaves.get(child) ?? 1), 0))
  })
  positions.set(root, { x: 0, y: 0 })
  const place = (id: string, from: number, to: number) => {
    let cursor = from
    ;(children.get(id) ?? []).forEach((child) => {
      const span = ((to - from) * (leaves.get(child) ?? 1)) / leaves.get(id)!
      const angle = cursor + span / 2
      const radius = depth.get(child)! * RING
      positions.set(child, { x: radius * Math.cos(angle), y: radius * Math.sin(angle) })
      place(child, cursor, cursor + span)
      cursor += span
    })
  }
  place(root, 0, Math.PI * 2)
  return { positions, boundary: undefined }
}
/**
 * Pure and synchronous. A node's rank is its longest distance from a source (a node with no incoming edge), so `x`
 * grows along every edge. Edges that close a cycle are ignored for ranking.
 */
export function chainLayout(data: GraphData): Layout {
  const positions = new Map<string, Point>()
  const index = new Map(data.nodes.map((node, at) => [node.id, at]))
  const incoming = new Map<string, number>(data.nodes.map((node) => [node.id, 0]))
  const outgoing = new Map<string, string[]>(data.nodes.map((node) => [node.id, []]))
  data.edges.forEach((edge) => {
    if (edge.source === edge.target || !index.has(edge.source) || !index.has(edge.target)) return
    outgoing.get(edge.source)!.push(edge.target)
    incoming.set(edge.target, incoming.get(edge.target)! + 1)
  })
  const rank = new Map<string, number>()
  const done = new Set<string>()
  const ready = data.nodes.filter((node) => incoming.get(node.id) === 0).map((node) => node.id)
  while (done.size < data.nodes.length) {
    // Only a cycle leaves nothing ready: start it from its earliest node.
    const id = ready.shift() ?? data.nodes.find((node) => !done.has(node.id))!.id
    if (done.has(id)) continue
    done.add(id)
    const here = rank.get(id) ?? 0
    rank.set(id, here)
    outgoing.get(id)!.forEach((target) => {
      if (done.has(target)) return
      rank.set(target, Math.max(rank.get(target) ?? 0, here + 1))
      incoming.set(target, incoming.get(target)! - 1)
      if (incoming.get(target) === 0) ready.push(target)
    })
  }
  const columns = new Map<number, string[]>()
  data.nodes.forEach((node) => columns.set(rank.get(node.id)!, [...(columns.get(rank.get(node.id)!) ?? []), node.id]))
  columns.forEach((ids, at) =>
    ids.forEach((id, row) => positions.set(id, { x: at * COLUMN, y: (row - (ids.length - 1) / 2) * ROW })),
  )
  return { positions, boundary: undefined }
}
async function settle(graph: Graph, signal: AbortSignal) {
  const settings = {
    ...forceAtlas2.inferSettings(graph),
    strongGravityMode: false,
    gravity: 0.7,
    scalingRatio: 26,
    slowDown: 3,
  }
  if (typeof Worker === "undefined") {
    forceAtlas2.assign(graph, { iterations: 400, settings })
    return !signal.aborted
  }
  const layout = new FA2Layout(graph, { settings })
  layout.start()
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, RUN_MS)
    signal.addEventListener("abort", () => (clearTimeout(timer), resolve()), { once: true })
  })
  layout.stop()
  layout.kill()
  return !signal.aborted
}

/** Scales the layout up to the working size, gives every node room, and centers it on the origin. */
function spread(graph: Graph) {
  const points = graph.mapNodes((id, attributes) => ({ id, x: attributes.x as number, y: attributes.y as number }))
  const [minX, maxX] = [Math.min(...points.map((p) => p.x)), Math.max(...points.map((p) => p.x))]
  const scale = WIDTH / Math.max(maxX - minX, 1)
  points.forEach((point) => ((point.x *= scale), (point.y *= scale)))
  // Overlapping pairs move half the missing distance each, a few hundred times, until nothing overlaps.
  for (let round = 0; round < 400; round++) {
    let moved = false
    points.forEach((a, index) =>
      points.slice(index + 1).forEach((b) => {
        const dx = b.x - a.x || 0.01
        const dy = b.y - a.y || 0.01
        const metric = Math.hypot(dx / SPACING.x, dy / SPACING.y)
        if (metric >= 1) return
        moved = true
        const push = ((1 / metric - 1) * 0.5) * 0.6
        a.x -= dx * push
        a.y -= dy * push
        b.x += dx * push
        b.y += dy * push
      }),
    )
    if (!moved) break
  }
  const centerX = (Math.min(...points.map((p) => p.x)) + Math.max(...points.map((p) => p.x))) / 2
  const centerY = (Math.min(...points.map((p) => p.y)) + Math.max(...points.map((p) => p.y))) / 2
  return new Map<string, Point>(points.map((p) => [p.id, { x: p.x - centerX, y: p.y - centerY }]))
}

/** Puts the services on a ring on the side of the layout their neighbours are on. Returns the boundary around them. */
function placeServices(
  data: GraphData,
  services: ReadonlySet<string>,
  core: ReadonlyMap<string, Point>,
  positions: Map<string, Point>,
): Boundary {
  const neighbours = data.edges.flatMap((edge) => {
    const other = services.has(edge.source) ? edge.target : services.has(edge.target) ? edge.source : undefined
    const point = other === undefined ? undefined : core.get(other)
    return point ? [point] : []
  })
  const mean = {
    x: neighbours.reduce((sum, point) => sum + point.x, 0) / Math.max(neighbours.length, 1),
    y: neighbours.reduce((sum, point) => sum + point.y, 0) / Math.max(neighbours.length, 1),
  }
  const length = Math.hypot(mean.x, mean.y)
  const direction = length < 1 ? { x: 1, y: 0 } : { x: mean.x / length, y: mean.y / length }
  const reach = Math.max(...[...core.values()].map((point) => point.x * direction.x + point.y * direction.y))
  const radius = SERVICE_RING + BOUNDARY_PADDING
  const distance = reach + BOUNDARY_GAP + radius
  const center = { x: direction.x * distance, y: direction.y * distance }

  const ids = data.nodes.filter((node) => services.has(node.id)).map((node) => node.id)
  const start = Math.atan2(-direction.y, -direction.x) + Math.PI / 3
  ids.forEach((id, index) => {
    const angle = start + (index * Math.PI * 2) / ids.length
    positions.set(id, { x: center.x + SERVICE_RING * Math.cos(angle), y: center.y + SERVICE_RING * Math.sin(angle) })
  })
  return { ...center, radius }
}

/** A stable pseudo-random start per node, so the layout repeats across loads. */
function seed(id: string): Point {
  let state = 2166136261
  for (let index = 0; index < id.length; index++) state = Math.imul(state ^ id.charCodeAt(index), 16777619)
  const next = () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const angle = next() * Math.PI * 2
  const radius = 40 + next() * 260
  return { x: radius * Math.cos(angle), y: radius * Math.sin(angle) * 0.7 }
}
