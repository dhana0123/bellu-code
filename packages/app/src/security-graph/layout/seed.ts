/**
 * Deterministic placements shared by the layout worker (initial ForceAtlas2
 * positions) and the main-thread client (grid fallback, placement of late
 * entities). Positions are flat `[x0, y0, x1, y1, ...]` indexed like the input.
 */

/** Small seeded PRNG, so the same graph always starts from the same layout. */
function mulberry32(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/**
 * Hierarchy-aware start: roots (areas) sit on a ring, every child is scattered
 * around its parent in a disc that shrinks with depth. `parents[i]` is the index
 * of node i's parent, or -1 for a root. Nodes unreachable from a root (a parent
 * cycle) are scattered on the ring so every node gets a finite position.
 */
export function seedByHierarchy(parents: Int32Array, seed = 1) {
  const n = parents.length
  const out = new Float32Array(n * 2)
  const random = mulberry32(seed)
  const radius = Math.max(200, Math.sqrt(n) * 12)

  const kids = new Int32Array(n).fill(-1)
  const next = new Int32Array(n).fill(-1)
  const roots: number[] = []
  const placed = new Uint8Array(n)
  for (let i = n - 1; i >= 0; i--) {
    const parent = parents[i]
    if (parent < 0 || parent >= n || parent === i) {
      roots.push(i)
      continue
    }
    next[i] = kids[parent]
    kids[parent] = i
  }
  roots.reverse()

  const stack: number[] = []
  const depth = new Uint16Array(n)
  roots.forEach((root, index) => {
    const angle = (index / roots.length) * Math.PI * 2
    out[root * 2] = Math.cos(angle) * radius
    out[root * 2 + 1] = Math.sin(angle) * radius
    placed[root] = 1
    stack.push(root)
  })
  while (stack.length > 0) {
    const parent = stack.pop()!
    const spread = radius * 0.6 * Math.pow(0.45, depth[parent])
    for (let child = kids[parent]; child >= 0; child = next[child]) {
      const angle = random() * Math.PI * 2
      const distance = spread * Math.sqrt(random())
      out[child * 2] = out[parent * 2] + Math.cos(angle) * distance
      out[child * 2 + 1] = out[parent * 2 + 1] + Math.sin(angle) * distance
      depth[child] = depth[parent] + 1
      placed[child] = 1
      stack.push(child)
    }
  }
  for (let i = 0; i < n; i++) {
    if (placed[i]) continue
    const angle = random() * Math.PI * 2
    out[i * 2] = Math.cos(angle) * radius
    out[i * 2 + 1] = Math.sin(angle) * radius
  }
  return out
}

/** Row-major square grid in input order. Needs no worker and never fails. */
export function gridPositions(count: number, spacing = 40) {
  const out = new Float32Array(count * 2)
  const columns = Math.max(1, Math.ceil(Math.sqrt(count)))
  const offset = ((columns - 1) * spacing) / 2
  for (let i = 0; i < count; i++) {
    out[i * 2] = (i % columns) * spacing - offset
    out[i * 2 + 1] = Math.floor(i / columns) * spacing - offset
  }
  return out
}
