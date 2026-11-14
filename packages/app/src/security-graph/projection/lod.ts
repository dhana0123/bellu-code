import type { ZoomLevelKey } from "../theme"
import type { Hierarchy } from "./hierarchy"

export type Override = "expanded" | "collapsed"
export type Overrides = ReadonlyMap<string, Override>

/** Zoom level to the depth at which the cut stops: L1=0, L2=1, L3=2, L4=leaf. */
export function targetDepth(level: ZoomLevelKey) {
  if (level === "L1") return 0
  if (level === "L2") return 1
  if (level === "L3") return 2
  return Infinity
}

/**
 * Visible cut of the hierarchy in pre-order: an antichain that covers every
 * node through exactly one visible ancestor (or itself).
 *
 * A node stops the descent when it has no children, when its own override is
 * "collapsed", or when it has no override and its depth reaches the target.
 * An "expanded" override opens that node whatever the zoom. An override only
 * affects its own node and, through it, that subtree. When overrides sit on an
 * ancestor and a descendant, the deepest one decides for its node; a collapsed
 * ancestor hides the subtree, so overrides below it have no visible effect.
 */
export function cut(h: Hierarchy, level: ZoomLevelKey, overrides: Overrides = new Map()): string[] {
  const depth = targetDepth(level)
  const result: string[] = []
  const stack = [...h.roots].reverse()
  while (stack.length) {
    const id = stack.pop()!
    const item = h.nodes.get(id)!
    const own = overrides.get(id)
    const open = own ? own === "expanded" : item.depth < depth
    if (!open || item.children.length === 0) {
      result.push(id)
      continue
    }
    for (let i = item.children.length - 1; i >= 0; i--) stack.push(item.children[i])
  }
  return result
}
