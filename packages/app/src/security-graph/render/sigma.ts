// Sigma 4 renderer for the security graph.
//
// Coordinates: `autoRescale: false`, so 1 graph unit is 1 pixel at camera ratio 1 and the graph
// origin sits at the viewport center. Zoom scale (pixels per graph unit, larger = closer) is
// measured through Sigma's own conversion, never assumed. Node size attributes follow the
// `screen` size reference with `zoomToSizeRatioFunction = ratio`, so a node's pixel size is
// `size / ratio`, the same as the world-to-screen scale. LOD (dots, icons, badges) is done by
// the 3.4 shaders from pixel size; labels, pills and edge labels come from the overlay.
import Graph from "graphology"
import { DEFAULT_STYLES, Sigma } from "sigma"
import { brandIcons, type Atlas } from "./atlas"
import { createOverlay, nodeGeometry, sigmaSize, type Scene } from "./overlay"
import { securityGraphPrimitives } from "./programs"
import {
  emptyHighlight,
  type CameraOptions,
  type Highlight,
  type RenderEdge,
  type RenderGraph,
  type RenderNode,
  type RenderPath,
  type RendererEvent,
  type Viewport,
} from "./types"
import type { Hull } from "../layout/hulls"
import { nodeTypes, palettes, sizes, zoom, type ThemeMode } from "../theme"

export type RendererOptions = {
  mode: ThemeMode
  atlas: Atlas
  typeLabel?: (type: string) => string
  relationLabel?: (relation: string) => string
}

type NodeAttributes = Record<string, string | number | undefined>

const minScale = 0.02
const maxScale = 8

export function createRenderer(container: HTMLElement, options: RendererOptions) {
  let mode = options.mode
  const graph = new Graph({ type: "directed", multi: true })
  const nodes = new Map<string, RenderNode>()
  const edges = new Map<string, RenderEdge>()
  const paths = new Map<string, RenderPath>()
  const incident = new Map<string, Set<string>>()
  let boundaries: readonly Hull[] = []
  let highlight: Highlight = emptyHighlight
  let focus: Scene["focus"]
  let panning = false
  let dragging = false
  const listeners = new Set<(event: RendererEvent) => void>()
  const emit = (event: RendererEvent) => listeners.forEach((listener) => listener(event))

  let sigma = build()
  const overlay = createOverlay(container, {
    mode,
    atlas: options.atlas,
    typeLabel: options.typeLabel,
    relationLabel: options.relationLabel,
    view: {
      toViewport: (x, y) => sigma.graphToViewport({ x, y }),
      toGraph: (x, y) => sigma.viewportToGraph({ x, y }),
      scale: () => scale(),
    },
  })
  const scene = (): Scene => ({ nodes, edges, paths, boundaries, highlight, focus })
  const redraw = () => overlay.draw(scene())
  attach()

  function build() {
    const palette = palettes[mode]
    return new Sigma(graph, container, {
      primitives: securityGraphPrimitives({ atlas: options.atlas, mode }),
      styles: {
        nodes: [
          DEFAULT_STYLES.nodes,
          {
            shape: "sgnode",
            size: { attribute: "size", defaultValue: 10 },
            iconCell: { attribute: "iconCell", defaultValue: -1 },
            iconTint: { attribute: "iconTint", defaultValue: "#00000000" },
            ringColor: { attribute: "ringColor", defaultValue: "#00000000" },
            ringWidth: { attribute: "ringWidth", defaultValue: 0 },
            badge: { attribute: "badge", defaultValue: 0 },
          },
        ],
        edges: [
          DEFAULT_STYLES.edges,
          { path: "line", head: "arrow", size: sizes.edgeWidth, color: { attribute: "color", defaultValue: palette.edge } },
        ],
        // The overlay draws the canvas color and dot grid under the WebGL layer.
        stage: { when: () => true, then: { background: "transparent" } },
      },
      settings: {
        autoRescale: false,
        itemSizesReference: "screen",
        zoomToSizeRatioFunction: (ratio) => ratio,
        renderLabels: false,
        renderEdgeLabels: false,
        enableNodeDrag: true,
        minCameraRatio: 1 / maxScale,
        maxCameraRatio: 1 / minScale,
        hideEdgesOnMove: false,
      },
      nodeReducer: (key) => (focus && !focus.nodes.has(key) ? { opacity: sizes.dimAlpha } : {}),
      edgeReducer: (key) => (focus && !focus.edges.has(key) ? { opacity: sizes.dimAlpha } : {}),
    })
  }

  function attach() {
    sigma.on("afterRender", () => {
      redraw()
      syncPan()
    })
    sigma.on("resize", redraw)
    sigma.getCamera().on("updated", () => {
      emit({ type: "viewport", viewport: viewport() })
      syncPan()
    })
    sigma.on("enterNode", ({ node }) => emit({ type: "hover", id: node }))
    sigma.on("leaveNode", () => emit({ type: "hover" }))
    sigma.on("clickNode", ({ node, event }) => emit({ type: "click", id: node, badge: inBadge(node, event.x, event.y) }))
    sigma.on("clickStage", () => emit({ type: "click-stage" }))
    sigma.on("doubleClickNode", ({ node, preventSigmaDefault }) => {
      preventSigmaDefault()
      emit({ type: "dblclick", id: node })
    })
    sigma.on("doubleClickStage", ({ preventSigmaDefault }) => preventSigmaDefault())
    sigma.on("nodeDragStart", ({ node }) => {
      dragging = true
      emit({ type: "drag-start", id: node })
    })
    sigma.on("nodeDrag", ({ node }) => {
      const position = follow(node)
      if (position) emit({ type: "drag", id: node, ...position })
    })
    sigma.on("nodeDragEnd", ({ node }) => {
      dragging = false
      const position = follow(node)
      if (position) emit({ type: "drag-end", id: node, ...position })
    })
  }

  // Sigma writes dragged positions to the graph; mirror them into the overlay record.
  function follow(id: string) {
    const record = nodes.get(id)
    if (!record || !graph.hasNode(id)) return undefined
    record.x = graph.getNodeAttribute(id, "x")
    record.y = graph.getNodeAttribute(id, "y")
    return { x: record.x, y: record.y }
  }

  function syncPan() {
    const now = sigma.getGraphState().isPanning && !dragging
    if (now === panning) return
    panning = now
    emit({ type: now ? "pan-start" : "pan-end" })
  }

  function inBadge(id: string, x: number, y: number) {
    const record = nodes.get(id)
    if (!record || !record.hasChildren || record.expanded || record.count <= 0) return false
    if (scale() < zoom.iconThreshold) return false
    const at = sigma.graphToViewport({ x: record.x, y: record.y })
    const geometry = nodeGeometry(record, scale())
    return Math.hypot(x - (at.x + geometry.badgeX), y - (at.y + geometry.badgeY)) <= geometry.badgeRadius * 1.3
  }

  function scale() {
    const a = sigma.graphToViewport({ x: 0, y: 0 })
    const b = sigma.graphToViewport({ x: 1, y: 0 })
    return Math.hypot(b.x - a.x, b.y - a.y) || 1
  }

  function viewport(): Viewport {
    const size = sigma.getDimensions()
    const center = sigma.viewportToGraph({ x: size.width / 2, y: size.height / 2 })
    return { scale: scale(), x: center.x, y: center.y, width: size.width, height: size.height }
  }

  function nodeAttributes(node: RenderNode): NodeAttributes {
    const palette = palettes[mode]
    const brand = node.external ? brandKey(node.name) : undefined
    const icon = brand ?? nodeTypes[node.type].icon
    return {
      x: node.x,
      y: node.y,
      size: sigmaSize(node),
      color: node.external ? palette.externalFill : nodeTypes[node.type].color,
      iconCell: options.atlas.index(icon),
      // Generic external icon is white line art, so tint it grey; brand logos keep their colors.
      iconTint: node.external && !brand ? palette.externalRing : "#00000000",
      ringColor: node.external ? palette.externalRing : "#00000000",
      ringWidth: node.external ? sizes.externalRingWidth : 0,
      badge: node.hasChildren && !node.expanded && node.count > 0 ? 1 : 0,
    }
  }

  function edgeAttributes() {
    return { size: sizes.edgeWidth, color: palettes[mode].edge, path: "line", head: "arrow" }
  }

  function indexIncidence() {
    incident.clear()
    edges.forEach((edge) => {
      for (const id of [edge.source, edge.target]) {
        const set = incident.get(id) ?? new Set<string>()
        set.add(edge.id)
        incident.set(id, set)
      }
    })
  }

  function computeFocus() {
    const active = highlight.focus.length > 0 || highlight.paths.length > 0
    if (!active) {
      focus = undefined
      return
    }
    const focusNodes = new Set<string>()
    const focusEdges = new Set<string>()
    highlight.focus.forEach((id) => {
      focusNodes.add(id)
      incident.get(id)?.forEach((edgeId) => {
        const edge = edges.get(edgeId)
        if (!edge) return
        focusEdges.add(edgeId)
        focusNodes.add(edge.source)
        focusNodes.add(edge.target)
      })
    })
    highlight.paths.forEach((id) =>
      paths.get(id)?.segments.forEach((segment) => {
        focusNodes.add(segment.from)
        focusNodes.add(segment.to)
        if (segment.edgeId) focusEdges.add(segment.edgeId)
      }),
    )
    focus = { nodes: focusNodes, edges: focusEdges }
  }

  function setGraph(next: RenderGraph) {
    const camera = sigma.getCamera().getState()
    const nodeIds = new Set(next.nodes.map((node) => node.id))
    const edgeIds = new Set(next.edges.map((edge) => edge.id))
    // Drop edges first so removed nodes do not detach edges we still track.
    edges.forEach((edge, id) => {
      if (edgeIds.has(id)) return
      if (graph.hasEdge(id)) graph.dropEdge(id)
      edges.delete(id)
    })
    nodes.forEach((_, id) => {
      if (nodeIds.has(id)) return
      if (graph.hasNode(id)) graph.dropNode(id)
      nodes.delete(id)
    })
    next.nodes.forEach((node) => {
      const attributes = nodeAttributes(node)
      nodes.set(node.id, { ...node })
      if (!graph.hasNode(node.id)) return void graph.addNode(node.id, attributes)
      const current = graph.getNodeAttributes(node.id)
      if (Object.keys(attributes).some((key) => current[key] !== attributes[key])) graph.mergeNodeAttributes(node.id, attributes)
    })
    next.edges.forEach((edge) => {
      edges.set(edge.id, edge)
      if (graph.hasEdge(edge.id) || edge.source === edge.target) return
      if (!graph.hasNode(edge.source) || !graph.hasNode(edge.target)) return
      graph.addDirectedEdgeWithKey(edge.id, edge.source, edge.target, edgeAttributes())
    })
    paths.clear()
    next.paths.forEach((path) => paths.set(path.id, path))
    boundaries = next.boundaries
    indexIncidence()
    computeFocus()
    // Sigma keeps its camera across graph updates; restore it in case autoRescale shifted it.
    sigma.getCamera().setState(camera)
    sigma.scheduleRefresh()
    overlay.schedule(scene)
  }

  function setHighlight(next: Highlight) {
    highlight = next
    computeFocus()
    sigma.scheduleRefresh({ skipIndexation: true })
    overlay.schedule(scene)
  }

  function setBoundaries(next: readonly Hull[]) {
    boundaries = next
    overlay.schedule(scene)
  }

  function setMode(next: ThemeMode) {
    if (next === mode) return
    mode = next
    // Primitives (badge colors) are fixed at construction, so rebuild Sigma on the same graph.
    const camera = sigma.getCamera().getState()
    sigma.kill()
    nodes.forEach((node) => graph.mergeNodeAttributes(node.id, nodeAttributes(node)))
    graph.forEachEdge((id) => graph.mergeEdgeAttributes(id, edgeAttributes()))
    sigma = build()
    sigma.getCamera().setState(camera)
    attach()
    overlay.setMode(next)
    overlay.schedule(scene)
  }

  function animate(state: { x?: number; y?: number; ratio?: number }, camera?: CameraOptions) {
    const duration = camera?.duration ?? 0
    if (duration <= 0) return Promise.resolve(void sigma.getCamera().setState(state))
    return sigma.getCamera().animate(state, { duration })
  }

  function ratioFor(target: number) {
    const clamped = Math.min(maxScale, Math.max(minScale, target))
    return (sigma.getCamera().ratio * scale()) / clamped
  }

  return {
    setGraph,
    setHighlight,
    setBoundaries,
    setMode,
    onEvent(listener: (event: RendererEvent) => void) {
      listeners.add(listener)
      return () => void listeners.delete(listener)
    },
    getScale: scale,
    getViewport: viewport,
    zoomTo(target: number, camera?: CameraOptions) {
      return animate({ ratio: ratioFor(target) }, camera)
    },
    centerOn(id: string, target?: { scale?: number } & CameraOptions) {
      const record = nodes.get(id)
      if (!record) return Promise.resolve()
      const at = sigma.graphToFramedGraph({ x: record.x, y: record.y })
      return animate({ x: at.x, y: at.y, ...(target?.scale ? { ratio: ratioFor(target.scale) } : {}) }, target)
    },
    fit(camera?: CameraOptions & { padding?: number }) {
      if (nodes.size === 0) return Promise.resolve()
      const bounds = [...nodes.values()].reduce(
        (box, node) => ({
          x0: Math.min(box.x0, node.x),
          x1: Math.max(box.x1, node.x),
          y0: Math.min(box.y0, node.y),
          y1: Math.max(box.y1, node.y),
        }),
        { x0: Infinity, x1: -Infinity, y0: Infinity, y1: -Infinity },
      )
      const padding = camera?.padding ?? 80
      const size = sigma.getDimensions()
      const extent = Math.max(
        (bounds.x1 - bounds.x0 + sizes.node) / Math.max(1, size.width - padding * 2),
        (bounds.y1 - bounds.y0 + sizes.node) / Math.max(1, size.height - padding * 2),
      )
      const at = sigma.graphToFramedGraph({ x: (bounds.x0 + bounds.x1) / 2, y: (bounds.y0 + bounds.y1) / 2 })
      // Scale is the inverse of the extent in pixels per unit: fit when the extent fills the viewport.
      return animate({ x: at.x, y: at.y, ratio: ratioFor(1 / extent) }, camera)
    },
    dispose() {
      listeners.clear()
      overlay.dispose()
      sigma.kill()
      graph.clear()
    },
  }
}

export type Renderer = ReturnType<typeof createRenderer>

function brandKey(name: string) {
  const lower = name.toLowerCase()
  return Object.entries(brandIcons).find(([brand]) => lower.includes(brand.toLowerCase()))?.[1]
}
