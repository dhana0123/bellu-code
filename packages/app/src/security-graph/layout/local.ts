import { forceCollide, forceLink, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force"
import { nodeGap, nodeRadius, radialPlacement } from "./anchor"
import type { Point } from "./client"

export type LocalLayoutInput = {
  parent: Point
  childIds: readonly string[]
  /** Relationships between children of this subtree. Others are ignored. */
  links: readonly { source: string; target: string }[]
  /** Positions remembered from an earlier expand; reused as is. */
  cached?: ReadonlyMap<string, Point>
}

/** Up to this many uncached children are placed on a ring without simulating. */
export const radialMax = 8
/** Fixed budget, run synchronously. */
export const tickBudget = 120

type Body = SimulationNodeDatum & { id: string }

/**
 * Target positions for the children of a node being expanded. Only the subtree
 * is simulated, the parent is a fixed body, and cached children are pinned, so
 * nothing outside the subtree is read or moved. Animation starts every child at
 * the parent position and interpolates to the returned targets.
 */
export function layoutExpansion(input: LocalLayoutInput): Map<string, Point> {
  const result = new Map<string, Point>()
  const fresh: string[] = []
  for (const id of input.childIds) {
    const hit = input.cached?.get(id)
    if (hit) result.set(id, { x: hit.x, y: hit.y })
    else fresh.push(id)
  }
  if (fresh.length === 0) return result

  const { parent } = input
  if (fresh.length <= radialMax && result.size === 0) {
    radialPlacement(parent, fresh.length).forEach((p, i) => result.set(fresh[i], p))
    return result
  }

  const parentBody: Body = { id: "\0parent", x: parent.x, y: parent.y, fx: parent.x, fy: parent.y }
  const pinned: Body[] = [...result].map(([id, p]) => ({ id, x: p.x, y: p.y, fx: p.x, fy: p.y }))
  // Radial start: a deterministic spiral that widens with the index (golden angle).
  const step = nodeRadius * 2 + nodeGap
  const free: Body[] = fresh.map((id, i) => {
    const r = step * (1 + Math.sqrt(i))
    const a = i * 2.399963229728653
    return { id, x: parent.x + r * Math.cos(a), y: parent.y + r * Math.sin(a) }
  })
  const bodies = [parentBody, ...pinned, ...free]
  const ids = new Set(bodies.map((b) => b.id))
  const links: SimulationLinkDatum<Body>[] = input.links
    .filter((l) => ids.has(l.source) && ids.has(l.target) && l.source !== l.target)
    .map((l) => ({ source: l.source, target: l.target }))
  // Each child hangs off the parent so unlinked children stay close.
  for (const b of free) links.push({ source: parentBody.id, target: b.id })

  // d3 draws jitter from randomSource; a fixed LCG keeps the layout deterministic.
  let seed = 1
  const random = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296
  const simulation = forceSimulation(bodies)
    .randomSource(random)
    .stop()
    .force("link", forceLink<Body, SimulationLinkDatum<Body>>(links).id((b) => b.id).distance(step * 1.5).strength(0.4))
    .force("collide", forceCollide<Body>(nodeRadius + nodeGap / 2).iterations(2))
  for (let i = 0; i < tickBudget; i++) simulation.tick()

  for (const b of free) result.set(b.id, { x: b.x ?? parent.x, y: b.y ?? parent.y })
  return result
}
