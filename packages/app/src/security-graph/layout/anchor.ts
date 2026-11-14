import { sizes } from "../theme"
import type { Point } from "./client"

/** Gap kept between neighboring node circles. */
export const nodeGap = 8
export const nodeRadius = sizes.node / 2

/** Evenly spaced ring around `center`, wide enough that adjacent circles do not touch. */
export function radialPlacement(center: Point, count: number, startAngle = -Math.PI / 2): Point[] {
  if (count <= 0) return []
  if (count === 1) return [{ x: center.x + (nodeRadius * 2 + nodeGap) * Math.cos(startAngle), y: center.y + (nodeRadius * 2 + nodeGap) * Math.sin(startAngle) }]
  const chord = nodeRadius * 2 + nodeGap
  // Chord between adjacent points on a ring of radius r is 2 r sin(pi/n).
  const ring = Math.max(chord * 1.5, chord / (2 * Math.sin(Math.PI / count)))
  return Array.from({ length: count }, (_, i) => {
    const angle = startAngle + (i * 2 * Math.PI) / count
    return { x: center.x + ring * Math.cos(angle), y: center.y + ring * Math.sin(angle) }
  })
}

/**
 * Minimal neighbor nudge. Each placed neighbor that overlaps any new child is
 * pushed along the vector from the parent by the deepest overlap. Neighbors that
 * do not overlap are absent from the result, so callers move nothing else.
 * Pure: returns a delta map of moved ids only.
 */
export function nudgeNeighbors(
  parent: Point,
  footprint: ReadonlyMap<string, Point>,
  neighbors: ReadonlyMap<string, Point>,
): Map<string, Point> {
  const deltas = new Map<string, Point>()
  const min = nodeRadius * 2 + nodeGap
  for (const [id, n] of neighbors) {
    if (footprint.has(id)) continue
    let overlap = 0
    for (const c of footprint.values()) overlap = Math.max(overlap, min - Math.hypot(n.x - c.x, n.y - c.y))
    if (overlap <= 0) continue
    const dx = n.x - parent.x
    const dy = n.y - parent.y
    const len = Math.hypot(dx, dy)
    // A neighbor exactly on the parent has no direction; push along +x.
    const ux = len === 0 ? 1 : dx / len
    const uy = len === 0 ? 0 : dy / len
    deltas.set(id, { x: ux * overlap, y: uy * overlap })
  }
  return deltas
}
