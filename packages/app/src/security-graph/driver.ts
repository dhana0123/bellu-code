// Thin edge of the Security Graph view. Framework-free: it connects the interaction machine to the projection
// engine, the local layout, the animator and the renderer.
//
// Renderer events become machine events. The machine returns effects and the driver runs them: expand and collapse
// change the engine overrides, lay out only the new subtree and animate positions; focus expands the ancestors and
// moves the camera; fit and reset call the camera helpers. Expand and collapse never move the camera.
//
// Every animation names its attempt and echoes it in `anim-done`, so the machine ignores a result that is no longer
// current. `dispose()` removes every input and resets the machine to its initial model. A late camera promise then
// finds no animation to finish and does nothing, so no disposed flag is needed.
import type { GraphDelta, Entity } from "./model"
import { INITIAL_MODEL, transition, type Camera, type Effect, type Event, type Model, type Resting } from "./machine"
import { type Engine, type Point, type Visible, type VisibleNode } from "./projection/engine"
import { nudgeNeighbors } from "./layout/anchor"
import { createHulls } from "./layout/hulls"
import { layoutExpansion } from "./layout/local"
import { collapseFrames, createAnimator, expandFrames, type Frames } from "./render/animate"
import type { Renderer } from "./render/sigma"
import {
  emptyHighlight,
  type Highlight,
  type RenderEdge,
  type RenderGraph,
  type RenderNode,
  type RenderPath,
  type RendererEvent,
  type Viewport,
} from "./render/types"
import { sizes, zoom, zoomLevel, type ZoomLevelKey } from "./theme"

export type { Engine }
export type Filter = (entity: Entity) => boolean
export type DriverOptions = {
  renderer: Renderer
  engine: Engine
  /** Receives positions the user changed by dragging, so the layout cache can pin them. */
  pin?: (id: string, point: Point) => void
}
export type Driver = ReturnType<typeof createDriver>

const expandMs = 320
const cameraMs = 420
const fitMs = 320
const keyZoomStep = 1.25
const keyPanMs = 180
const minNodeFactor = 0.05
// Nudging only looks at neighbors this close to the expanding parent (graph units).
const nudgeReach = 700

// Resting state behind transient ones: a gesture or animation keeps the selection and hover it will return to.
function resting(model: Model): Resting {
  const state = model.state
  switch (state.type) {
    case "panning":
    case "dragging":
      return state.resume
    case "animating":
      return state.next
    default:
      return state
  }
}

function selectionOf(model: Model) {
  const state = resting(model)
  return state.type === "selected" || state.type === "focused" ? state.id : undefined
}

function hoverOf(model: Model) {
  const state = resting(model)
  if (state.type === "hovering") return state.id
  return state.type === "selected" ? state.hover : undefined
}

const isExpanded = (node: { hasChildren: boolean; count: number }) => node.hasChildren && node.count === 0

export function createDriver(container: HTMLElement, options: DriverOptions) {
  const { renderer, engine } = options
  const animator = createAnimator()
  const selectCallbacks = new Set<(id: string | undefined) => void>()
  const viewportCallbacks = new Set<(viewport: Viewport) => void>()
  const stateCallbacks = new Set<(model: Model) => void>()
  // Parents whose children already have a local layout. Later expands reuse it.
  const placed = new Set<string>()

  let model: Model = INITIAL_MODEL
  let filter: Filter | undefined
  let level: ZoomLevelKey = "L1"
  let shownLevel: ZoomLevelKey = level
  let current: Visible = { nodes: [], edges: [], paths: [], boundaries: [] }
  let hulls = createHulls([], { owner: () => undefined })
  let viewport: Viewport | undefined
  let user: Highlight = emptyHighlight
  let announced: string | undefined

  const project = () => engine.project({ level, filter })

  // --- presentation -------------------------------------------------------------------------------------------

  function present(visible: Visible) {
    current = visible
    shownLevel = level
    const ids = new Set(visible.nodes.map((node) => node.id))
    hulls = createHulls(
      visible.boundaries.map((item) => ({
        id: item.id,
        label: item.label,
        memberIds: item.memberIds,
        parentId: item.parentId,
      })),
      { owner: (id) => (ids.has(id) ? id : undefined) },
    )
    paint()
  }

  function paint(frames?: Frames) {
    const graph = adapt(current, frames)
    const at = new Map<string, Point>(graph.nodes.map((node) => [node.id, node]))
    graph.boundaries = hulls.update((id) => at.get(id))
    renderer.setGraph(graph)
  }

  // Re-projects when the zoom level changed while an animation held the view.
  function reconcile() {
    if (shownLevel === level || model.state.type === "animating") return
    present(project())
  }

  function adapt(visible: Visible, frames?: Frames): RenderGraph {
    const nodes = visible.nodes.map((node): RenderNode => {
      const frame = frames?.get(node.id)
      return {
        id: node.id,
        type: node.type,
        name: node.name,
        x: frame?.x ?? node.x,
        y: frame?.y ?? node.y,
        ...(frame && frame.alpha < 1 ? { size: sizes.node * Math.max(frame.alpha, minNodeFactor) } : {}),
        severity: node.severity,
        count: node.count,
        expanded: node.expanded || isExpanded(node),
        hasChildren: node.hasChildren,
        tags: node.tags.map((tag) => ({ label: tag.label, severity: "risk", ...(tag.count > 1 ? { count: tag.count } : {}) })),
        language: engine.entity(node.id)?.language,
        external: node.type === "external-service",
      }
    })
    const edges = visible.edges.map(
      (edge): RenderEdge => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        relation: edge.relation,
        count: edge.count,
      }),
    )
    return { nodes, edges, paths: adaptPaths(visible), boundaries: [] }
  }

  function adaptPaths(visible: Visible): RenderPath[] {
    if (visible.paths.length === 0) return []
    const edgeOf = new Map<string, string>()
    const wanted = new Set(visible.paths.flatMap((path) => path.segments.map((segment) => segment.stepIds[0])))
    for (const edge of visible.edges) {
      for (const member of edge.members) if (wanted.has(member) && !edgeOf.has(member)) edgeOf.set(member, edge.id)
    }
    const groups = new Map<string, Set<string>>()
    const untrusted = new Set<string>()
    for (const item of visible.boundaries) {
      if (/untrusted/i.test(item.id) || /untrusted/i.test(item.label)) untrusted.add(item.id)
      for (const member of item.memberIds) {
        const set = groups.get(member) ?? new Set<string>()
        set.add(item.id)
        groups.set(member, set)
      }
    }
    // A segment crosses when its endpoints sit in different boundaries and one of them is untrusted.
    const crosses = (from: string, to: string) => {
      const a = groups.get(from)
      const b = groups.get(to)
      for (const id of a ?? []) if (!b?.has(id) && untrusted.has(id)) return true
      for (const id of b ?? []) if (!a?.has(id) && untrusted.has(id)) return true
      return false
    }
    return visible.paths.map((path) => ({
      id: path.id,
      from: path.entry,
      to: path.target,
      severity: path.severity,
      segments: path.segments.map((segment) => ({
        from: segment.from,
        to: segment.to,
        edgeId: edgeOf.get(segment.stepIds[0]),
        crossing: crosses(segment.from, segment.to),
      })),
    }))
  }

  function syncHighlight() {
    const ids = [selectionOf(model), hoverOf(model)].filter((id): id is string => id !== undefined)
    renderer.setHighlight({ ...user, focus: Array.from(new Set([...user.focus, ...ids])) })
  }

  // --- machine ------------------------------------------------------------------------------------------------

  /** Runs one machine event. Returns true when the machine state changed. */
  function dispatch(event: Event): boolean {
    const result = transition(model, event)
    const changed = result.model !== model
    model = result.model
    if (changed) {
      syncHighlight()
      const selected = selectionOf(model)
      if (selected !== announced) {
        announced = selected
        selectCallbacks.forEach((callback) => callback(selected))
      }
      stateCallbacks.forEach((callback) => callback(model))
    }
    result.effects.forEach(run)
    return changed
  }

  function run(effect: Effect) {
    switch (effect.type) {
      case "select":
        // The selection reaches the UI through the state change in dispatch.
        return
      case "expand":
        return expand(effect.id, effect.attempt)
      case "collapse":
        return collapse(effect.id, effect.attempt)
      case "focus":
        return focus(effect.id, effect.attempt, effect.camera)
      case "cancel-animation":
        animator.cancel()
        // The engine already holds the final overrides; show them.
        present(project())
        return
      case "fit":
        void renderer.fit({ duration: fitMs })
        return
      case "reset":
        return reset()
    }
  }

  function finish(attempt: number) {
    if (dispatch({ type: "anim-done", attempt })) reconcile()
  }

  // Lays out the nodes that appeared between two projections. Only new nodes and overlapped neighbors move.
  function grow(before: Visible, after: Visible, anchor: string) {
    const known = new Set(before.nodes.map((node) => node.id))
    const added = after.nodes.filter((node) => !known.has(node.id))
    const nodes = new Map(after.nodes.map((node) => [node.id, node]))
    const groups = new Map<string, VisibleNode[]>()
    for (const node of added) {
      const parentId = engine.entity(node.id)?.parentId
      const parent = parentId !== undefined && nodes.has(parentId) ? parentId : anchor
      groups.set(parent, [...(groups.get(parent) ?? []), node])
    }
    const targets = new Map<string, Point>()
    const origins = new Map<string, Point>()
    const nudged = new Map<string, Point>()
    for (const [parentId, children] of groups) {
      const parent = engine.position(parentId)
      if (!parent) continue
      const ids = children.map((node) => node.id)
      const idSet = new Set(ids)
      const cached = placed.has(parentId)
        ? new Map(ids.flatMap((id) => {
            const point = engine.position(id)
            return point ? [[id, point] as [string, Point]] : []
          }))
        : undefined
      const layout = layoutExpansion({
        parent,
        childIds: ids,
        links: after.edges.filter((edge) => idSet.has(edge.source) && idSet.has(edge.target)),
        cached,
      })
      placed.add(parentId)
      for (const [id, point] of layout) {
        targets.set(id, point)
        origins.set(id, parent)
        engine.setPosition(id, point.x, point.y)
      }
      const neighbors = new Map<string, Point>()
      for (const node of before.nodes) {
        if (node.id === parentId || idSet.has(node.id)) continue
        if (Math.hypot(node.x - parent.x, node.y - parent.y) <= nudgeReach) neighbors.set(node.id, { x: node.x, y: node.y })
      }
      for (const [id, delta] of nudgeNeighbors(parent, layout, neighbors)) {
        const from = neighbors.get(id)!
        nudged.set(id, { x: from.x, y: from.y })
        engine.setPosition(id, from.x + delta.x, from.y + delta.y)
      }
    }
    // The projection read positions before the layout; refresh the ones that changed.
    for (const node of after.nodes) {
      const point = engine.position(node.id)
      if (!point) continue
      node.x = point.x
      node.y = point.y
    }
    return { targets, origins, nudged }
  }

  function expand(id: string, attempt: number) {
    const before = current
    const parent = engine.position(id)
    engine.expand(id)
    const after = project()
    if (!parent) {
      present(after)
      return finish(attempt)
    }
    const moved = grow(before, after, id)
    const frames = expandFrames(parent, moved.targets)
    for (const [nodeId, from] of moved.nudged) {
      const to = engine.position(nodeId)
      if (!to) continue
      frames.from.set(nodeId, { ...from, alpha: 1 })
      frames.to.set(nodeId, { ...to, alpha: 1 })
    }
    current = after
    shownLevel = level
    present(after)
    paint(frames.from)
    animator.run({
      attempt,
      kind: "expand",
      from: frames.from,
      to: frames.to,
      durationMs: expandMs,
      onFrame: (frame) => paint(frame),
      onDone: (done) => {
        paint()
        finish(done)
      },
    })
  }

  function collapse(id: string, attempt: number) {
    const before = current
    const parent = engine.position(id)
    engine.collapse(id)
    const after = project()
    if (!parent) {
      present(after)
      return finish(attempt)
    }
    const stay = new Set(after.nodes.map((node) => node.id))
    const gone = before.nodes.filter((node) => !stay.has(node.id))
    const frames = collapseFrames(parent, new Map(gone.map((node) => [node.id, { x: node.x, y: node.y }])))
    // While the children fold in, draw them and their edges next to the new projection.
    const edges = new Map(before.edges.map((edge) => [edge.id, edge]))
    after.edges.forEach((edge) => edges.set(edge.id, edge))
    const during: Visible = { ...after, nodes: [...after.nodes, ...gone], edges: Array.from(edges.values()) }
    present(during)
    shownLevel = level
    animator.run({
      attempt,
      kind: "collapse",
      from: frames.from,
      to: frames.to,
      durationMs: expandMs,
      onFrame: (frame) => paint(frame),
      onDone: (done) => {
        present(after)
        finish(done)
      },
    })
  }

  function focus(id: string, attempt: number, camera?: Camera) {
    const before = current
    for (const ancestor of engine.ancestors(id)) {
      if (engine.overrides().get(ancestor) !== "expanded") engine.setOverride(ancestor, "expanded")
    }
    const after = project()
    const parent = engine.entity(id)?.parentId
    grow(before, after, parent ?? id)
    present(after)
    renderer.centerOn(id, { scale: camera?.ratio, duration: cameraMs }).then(() => finish(attempt))
  }

  function reset() {
    animator.cancel()
    for (const id of Array.from(engine.overrides().keys())) engine.setOverride(id, undefined)
    present(project())
    void renderer.fit({ duration: fitMs })
  }

  // --- renderer events ----------------------------------------------------------------------------------------

  const find = (id: string) => current.nodes.find((node) => node.id === id)

  function onRenderer(event: RendererEvent) {
    switch (event.type) {
      case "hover":
        dispatch({ type: "hover", id: event.id })
        return
      case "click": {
        const node = find(event.id)
        dispatch({ type: "click", id: event.id, badge: event.badge, expanded: node ? isExpanded(node) : false })
        return
      }
      case "click-stage":
        dispatch({ type: "escape" })
        return
      case "dblclick": {
        const at = engine.position(event.id)
        dispatch({
          type: "dblclick",
          id: event.id,
          camera: at && viewport ? { x: at.x, y: at.y, ratio: Math.max(viewport.scale, zoom.levels.L3) } : undefined,
        })
        return
      }
      case "drag-start":
        dispatch({ type: "drag-start", id: event.id })
        return
      case "drag":
        engine.setPosition(event.id, event.x, event.y)
        moveNode(event.id, event.x, event.y)
        return
      case "drag-end":
        engine.setPosition(event.id, event.x, event.y)
        moveNode(event.id, event.x, event.y)
        options.pin?.(event.id, { x: event.x, y: event.y })
        dispatch({ type: "drag-end" })
        return
      case "pan-start":
        dispatch({ type: "pan-start" })
        return
      case "pan-end":
        dispatch({ type: "pan-end" })
        return
      case "viewport":
        viewport = event.viewport
        viewportCallbacks.forEach((callback) => callback(event.viewport))
        onZoom(event.viewport.scale)
        return
    }
  }

  // Keeps the hulls around a dragged node. Sigma already moved the node itself.
  function moveNode(id: string, x: number, y: number) {
    const node = find(id)
    if (!node) return
    node.x = x
    node.y = y
    const at = new Map(current.nodes.map((item) => [item.id, item]))
    renderer.setBoundaries(hulls.update((key) => at.get(key), [id]))
  }

  function onZoom(scale: number) {
    const next = zoomLevel(scale)
    if (next === level) return
    level = next
    reconcile()
  }

  // --- keyboard -----------------------------------------------------------------------------------------------

  const directions: Record<string, Point> = {
    ArrowLeft: { x: -1, y: 0 },
    ArrowRight: { x: 1, y: 0 },
    ArrowUp: { x: 0, y: -1 },
    ArrowDown: { x: 0, y: 1 },
  }

  // The renderer has no pan helper, so arrows jump to the nearest node in that direction.
  function nearest(direction: Point) {
    const origin = hoverOf(model) ?? selectionOf(model)
    const from = (origin ? engine.position(origin) : undefined) ?? viewport
    if (!from) return undefined
    let best: { id: string; score: number } | undefined
    for (const node of current.nodes) {
      if (node.id === origin) continue
      const dx = node.x - from.x
      const dy = node.y - from.y
      const along = dx * direction.x + dy * direction.y
      if (along <= 0) continue
      const across = Math.abs(dx * direction.y - dy * direction.x)
      const score = Math.hypot(dx, dy) + across
      if (!best || score < best.score) best = { id: node.id, score }
    }
    return best?.id
  }

  function onKey(event: KeyboardEvent) {
    if (event.ctrlKey || event.metaKey) return
    const target = event.target
    if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement) return
    const handled = key(event)
    if (handled) event.preventDefault()
  }

  function key(event: KeyboardEvent) {
    if (event.altKey) {
      if (event.key === "ArrowLeft") return dispatch({ type: "back" }) || true
      if (event.key === "ArrowRight") return dispatch({ type: "forward" }) || true
      return false
    }
    const direction = directions[event.key]
    if (direction) {
      const id = nearest(direction)
      if (!id) return true
      dispatch({ type: "hover", id })
      void renderer.centerOn(id, { duration: keyPanMs })
      return true
    }
    switch (event.key) {
      case "+":
      case "=":
        zoomBy(keyZoomStep)
        return true
      case "-":
      case "_":
        zoomBy(1 / keyZoomStep)
        return true
      case "Enter": {
        const id = hoverOf(model) ?? selectionOf(model)
        if (!id) return true
        const node = find(id)
        // Enter on the selected node toggles its expansion, so it is reachable without the badge.
        const toggle = selectionOf(model) === id && !!node?.hasChildren
        dispatch({ type: "click", id, badge: toggle, expanded: node ? isExpanded(node) : false })
        return true
      }
      case "Escape":
        dispatch({ type: "escape" })
        return true
      case "f":
      case "F":
        dispatch({ type: "fit" })
        return true
      case "Backspace":
        dispatch({ type: "back" })
        return true
      default:
        return false
    }
  }

  function zoomBy(factor: number) {
    void renderer.zoomTo(renderer.getScale() * factor, { duration: keyPanMs })
  }

  // --- lifecycle ----------------------------------------------------------------------------------------------

  const stop: (() => void)[] = [renderer.onEvent(onRenderer)]
  container.addEventListener("keydown", onKey)
  stop.push(() => container.removeEventListener("keydown", onKey))

  present(project())
  void renderer.fit()

  const subscribe = <T>(set: Set<T>, callback: T) => {
    set.add(callback)
    return () => void set.delete(callback)
  }

  return {
    engine,
    /** The selected or focused entity id, or undefined when the selection is cleared. */
    onSelect: (callback: (id: string | undefined) => void) => subscribe(selectCallbacks, callback),
    onViewport: (callback: (viewport: Viewport) => void) => subscribe(viewportCallbacks, callback),
    /** Every machine model change. UI code reads it through selectors. */
    onState: (callback: (model: Model) => void) => subscribe(stateCallbacks, callback),
    state: () => model,
    visible: () => current,
    level: () => level,
    /** Hides entities before projection. `undefined` shows everything. */
    setFilter(next: Filter | undefined) {
      filter = next
      present(project())
    },
    /** Agent glow, lit edges and attack paths. The selection and hover focus are added to `focus`. */
    setHighlight(next: Highlight) {
      user = next
      syncHighlight()
    },
    /** Expands the ancestors of an entity and centers the camera on it. */
    focusEntity(id: string) {
      const camera = viewport ? { x: 0, y: 0, ratio: Math.max(viewport.scale, zoom.levels.L3) } : undefined
      const at = engine.position(id)
      if (dispatch({ type: "dblclick", id, camera: at && camera ? { ...camera, x: at.x, y: at.y } : camera })) return
      // Already focused (or busy): only bring the node back into view.
      if (model.state.type !== "animating") void renderer.centerOn(id, { scale: camera?.ratio, duration: cameraMs })
    },
    /** Moves the camera to a graph point without changing the zoom. */
    centerAt: (x: number, y: number) => void renderer.centerAt(x, y),
    /** Toggles expansion of a visible node, as a click on its badge does. */
    toggle(id: string) {
      const node = find(id)
      if (node?.hasChildren) dispatch({ type: "click", id, badge: true, expanded: isExpanded(node) })
    },
    zoomIn: () => zoomBy(keyZoomStep),
    zoomOut: () => zoomBy(1 / keyZoomStep),
    fit: () => void dispatch({ type: "fit" }),
    reset: () => void dispatch({ type: "reset" }),
    back: () => void dispatch({ type: "back" }),
    forward: () => void dispatch({ type: "forward" }),
    /** Adds data without moving the camera or any existing node. */
    applyDelta(delta: GraphDelta) {
      engine.applyDelta(delta)
      present(project())
    },
    dispose() {
      animator.dispose()
      stop.forEach((off) => off())
      selectCallbacks.clear()
      viewportCallbacks.clear()
      stateCallbacks.clear()
      model = INITIAL_MODEL
    },
  }
}

