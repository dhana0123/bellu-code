/**
 * Trust-boundary hulls. Pure data, no DOM.
 *
 * Each boundary becomes a thin padded convex hull around its visible members, or a
 * circle when fewer than 3 distinct points exist or the points are collinear.
 * A parent boundary is built from its own members plus the full outline of every
 * child boundary, so a child is always contained in its parent, and the parent
 * pads by its height in the boundary tree (leaf = base pad).
 *
 * Coordinates are graph coordinates. The caption anchors at the topmost point of
 * the shape (smallest y, or largest y with `yUp`).
 */
import { polygonHull } from "d3-polygon"
import type { Boundary } from "../model"

export type Point = { x: number; y: number }

export type Hull =
  | { id: string; label: string; kind: "hull"; points: [number, number][]; caption: Point }
  | { id: string; label: string; kind: "circle"; center: Point; radius: number; caption: Point }

export type HullOptions = {
  /** Visible node id that stands in for a member, e.g. its nearest visible ancestor. Undefined = not shown. */
  owner: (memberId: string) => string | undefined
  /** Pad of a leaf boundary. */
  basePad?: number
  /** Extra pad per level of nesting below a boundary. */
  depthPad?: number
  yUp?: boolean
}

type Pos = (id: string) => Point | undefined

/** Segments used to round hull corners. Octagon vertices are cheap and stay convex. */
const ROUND = 8
const EPS = 1e-6
const cornerCos = Math.cos(Math.PI / ROUND)

export function createHulls(boundaries: Boundary[], options: HullOptions) {
  const basePad = options.basePad ?? 18
  const depthPad = options.depthPad ?? 14
  const sign = options.yUp ? -1 : 1
  const byId = new Map(boundaries.map((b) => [b.id, b]))
  const children = new Map<string, string[]>()
  boundaries.forEach((b) => {
    if (b.parentId && byId.has(b.parentId) && b.parentId !== b.id)
      children.set(b.parentId, [...(children.get(b.parentId) ?? []), b.id])
  })
  const heights = new Map<string, number>()
  const height = (id: string, seen: Set<string>): number => {
    const known = heights.get(id)
    if (known !== undefined) return known
    if (seen.has(id)) return 0 // cyclic parentId: stop descending
    seen.add(id)
    const h = Math.max(-1, ...(children.get(id) ?? []).map((c) => height(c, seen))) + 1
    heights.set(id, h)
    return h
  }
  boundaries.forEach((b) => height(b.id, new Set()))
  // Children before parents, so a parent can read the cached outline of its children.
  const order = [...boundaries].sort((a, b) => heights.get(a.id)! - heights.get(b.id)!)
  const parentOf = (id: string) => {
    const p = byId.get(id)?.parentId
    return p && p !== id && byId.has(p) ? p : undefined
  }

  let membership = new Map<string, string[]>() // visible id -> boundary ids
  const cache = new Map<string, Hull>()
  let output: Hull[] = []

  function reset() {
    membership = new Map()
    boundaries.forEach((b) =>
      new Set(b.memberIds.flatMap((m) => options.owner(m) ?? [])).forEach((v) =>
        membership.set(v, [...(membership.get(v) ?? []), b.id]),
      ),
    )
    cache.clear()
  }
  reset()

  /**
   * Recompute hulls for boundaries touched by `changed` (and their ancestors).
   * Without `changed`, everything is recomputed. Untouched boundaries keep the
   * same object, so callers can compare by identity.
   */
  function update(position: Pos, changed?: Iterable<string>) {
    const dirty = new Set<string>()
    if (changed === undefined || cache.size === 0) boundaries.forEach((b) => dirty.add(b.id))
    else
      for (const id of changed)
        for (const b of membership.get(id) ?? []) {
          for (let cur: string | undefined = b, n = 0; cur && !dirty.has(cur) && n <= boundaries.length; n++) {
            dirty.add(cur)
            cur = parentOf(cur)
          }
        }
    if (dirty.size === 0) return output

    order.forEach((b) => {
      if (!dirty.has(b.id)) return
      const hull = build(b, position)
      if (hull) cache.set(b.id, hull)
      else cache.delete(b.id)
    })
    // Parents first so nested outlines draw under their children.
    output = [...order].reverse().flatMap((b) => cache.get(b.id) ?? [])
    return output
  }

  function build(b: Boundary, position: Pos): Hull | undefined {
    const pts: [number, number][] = []
    new Set(b.memberIds.flatMap((m) => options.owner(m) ?? [])).forEach((v) => {
      const p = position(v)
      if (p) pts.push([p.x, p.y])
    })
    ;(children.get(b.id) ?? []).forEach((c) => {
      const h = cache.get(c)
      if (h) pts.push(...outline(h))
    })
    if (pts.length === 0) return undefined
    return shape(b, distinct(pts), basePad + depthPad * (heights.get(b.id) ?? 0))
  }

  function shape(b: Boundary, pts: [number, number][], pad: number): Hull {
    const hull = pts.length >= 3 ? polygonHull(pts) : null
    if (!hull || degenerate(hull)) {
      const xs = pts.map((p) => p[0])
      const ys = pts.map((p) => p[1])
      const cx = (Math.min(...xs) + Math.max(...xs)) / 2
      const cy = (Math.min(...ys) + Math.max(...ys)) / 2
      const radius = Math.max(...pts.map((p) => Math.hypot(p[0] - cx, p[1] - cy))) + pad
      return {
        id: b.id,
        label: b.label,
        kind: "circle",
        center: { x: cx, y: cy },
        radius,
        caption: { x: cx, y: cy - sign * radius },
      }
    }
    // Hull of (hull ⊕ octagon) = hull of every vertex expanded by a small octagon.
    // The octagon is circumscribed about the pad circle, so the edge offset is >= pad.
    const r = pad / cornerCos
    const padded = polygonHull(
      hull.flatMap((p) =>
        Array.from({ length: ROUND }, (_, i): [number, number] => {
          const a = ((i + 0.5) * 2 * Math.PI) / ROUND
          return [p[0] + r * Math.cos(a), p[1] + r * Math.sin(a)]
        }),
      ),
    )!
    const top = padded.reduce((best, p) => (p[1] * sign < best[1] * sign ? p : best))
    return { id: b.id, label: b.label, kind: "hull", points: padded, caption: { x: top[0], y: top[1] } }
  }

  return { update, reset }
}

/** Points that span a shape: hull vertices, or the corners of a square around a circle. */
function outline(h: Hull): [number, number][] {
  if (h.kind === "hull") return h.points
  const { x, y } = h.center
  // Circumscribed octagon so the parent contains the whole circle, not just its inscribed polygon.
  const r = h.radius / cornerCos
  return Array.from({ length: ROUND }, (_, i): [number, number] => {
    const a = ((i + 0.5) * 2 * Math.PI) / ROUND
    return [x + r * Math.cos(a), y + r * Math.sin(a)]
  })
}

function distinct(pts: [number, number][]) {
  const seen = new Set<string>()
  return pts.filter((p) => {
    const key = `${Math.round(p[0] / EPS)},${Math.round(p[1] / EPS)}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

/** Zero-area hull (collinear points), by the shoelace formula. */
function degenerate(hull: [number, number][]) {
  if (hull.length < 3) return true
  const area = hull.reduce((sum, p, i) => {
    const q = hull[(i + 1) % hull.length]
    return sum + (p[0] * q[1] - q[0] * p[1])
  }, 0)
  return Math.abs(area) / 2 < EPS
}
