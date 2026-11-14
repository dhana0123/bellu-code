/**
 * Expand/collapse/focus animation. Framework-free, no DOM besides requestAnimationFrame.
 *
 * One rAF loop interpolates node positions and opacity with d3-interpolate. The loop only
 * runs while a run is active, and never touches the camera, so the viewport does not jump.
 * A newer `attempt` supersedes the active run without calling its `onDone`; `cancel()` and
 * `dispose()` stop with no callback. `onDone` receives the attempt for the machine's `anim-done`.
 */
import { interpolateNumber } from "d3-interpolate"

export type NodeFrame = { x: number; y: number; alpha: number }
export type Frames = Map<string, NodeFrame>

export type AnimationRun = {
  attempt: number
  kind: "expand" | "collapse" | "focus"
  from: Frames
  to: Frames
  durationMs: number
  onFrame: (frames: Frames) => void
  onDone: (attempt: number) => void
}

type Active = {
  run: AnimationRun
  start: number | undefined
  tweens: { id: string; x: (t: number) => number; y: (t: number) => number; alpha: (t: number) => number }[]
}

export const easeOutCubic = (t: number) => 1 - Math.pow(1 - t, 3)

export function createAnimator() {
  let active: Active | undefined
  let handle: number | undefined

  const stop = () => {
    active = undefined
    if (handle === undefined) return
    cancelAnimationFrame(handle)
    handle = undefined
  }

  const tick = (now: number) => {
    handle = undefined
    const current = active
    if (!current) return
    const run = current.run
    const start = current.start ?? now
    current.start = start
    const t = run.durationMs <= 0 ? 1 : Math.min(1, Math.max(0, (now - start) / run.durationMs))
    const k = easeOutCubic(t)
    run.onFrame(new Map(current.tweens.map((tween) => [tween.id, { x: tween.x(k), y: tween.y(k), alpha: tween.alpha(k) }])))
    // onFrame may have started a newer run or cancelled this one.
    if (active !== current) return
    if (t < 1) {
      handle = requestAnimationFrame(tick)
      return
    }
    active = undefined
    run.onDone(run.attempt)
  }

  return {
    run(run: AnimationRun) {
      // A late call for an older attempt must not cancel the newer run.
      if (active && run.attempt < active.run.attempt) return
      stop()
      active = {
        run,
        start: undefined,
        tweens: [...run.to].map(([id, target]) => {
          const origin = run.from.get(id) ?? target
          return {
            id,
            x: interpolateNumber(origin.x, target.x),
            y: interpolateNumber(origin.y, target.y),
            alpha: interpolateNumber(origin.alpha, target.alpha),
          }
        }),
      }
      // Reduced motion: finish in the next single frame.
      if (prefersReducedMotion()) run.durationMs = 0
      handle = requestAnimationFrame(tick)
    },
    /** Stops the loop with no callback. */
    cancel: stop,
    dispose: stop,
  }
}

function prefersReducedMotion() {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches
}

type Point = { x: number; y: number }

/**
 * Expand: children start at the parent position, transparent, and move to their targets.
 * Other nodes (e.g. pushed neighbors) tween from their current position when given.
 */
export function expandFrames(parent: Point, targets: ReadonlyMap<string, Point>, current?: ReadonlyMap<string, Point>) {
  const from: Frames = new Map()
  const to: Frames = new Map()
  for (const [id, target] of targets) {
    const start = current?.get(id) ?? parent
    from.set(id, { x: start.x, y: start.y, alpha: current?.has(id) ? 1 : 0 })
    to.set(id, { x: target.x, y: target.y, alpha: 1 })
  }
  return { from, to }
}

/** Collapse: children move into the parent position while fading out. The caller removes them on done. */
export function collapseFrames(parent: Point, children: ReadonlyMap<string, Point>) {
  const from: Frames = new Map()
  const to: Frames = new Map()
  for (const [id, position] of children) {
    from.set(id, { x: position.x, y: position.y, alpha: 1 })
    to.set(id, { x: parent.x, y: parent.y, alpha: 0 })
  }
  return { from, to }
}
