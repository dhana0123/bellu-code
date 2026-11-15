import Graph from "graphology"
import Sigma, { DEFAULT_STYLES } from "sigma"
import { extremityArrow, layerFill, layerPlain, pathCurved, pathLine, sdfCircle } from "sigma/rendering"
import { brandLogo, kindIcon, languageMark } from "./icons"
import type { Boundary, Layout } from "./layout"
import type { GraphData, GraphEdge, GraphNode } from "./model"
import {
  BOUNDARY_KEY,
  BRAND_NAME,
  CATEGORY_KEY,
  EDGE_KEY,
  KIND_COLOR,
  KIND_KEY,
  NODE_RADIUS,
  RISK_TAGS,
  TAG_KEY,
  type GraphKey,
} from "./theme"

export type MountInput = {
  /** Holds the dot grid. */
  frame: HTMLElement
  /** The WebGL canvas goes here. */
  stage: HTMLElement
  /** Labels, icons, badges and chips are drawn here, above the canvas. */
  overlay: HTMLElement
  data: GraphData
  layout: Layout
  t: (key: GraphKey) => string
}

/** More nodes than this in view: draw only icons. More than ICON_LIMIT: leave everything to WebGL. */
const DETAIL_LIMIT = 250
const ICON_LIMIT = 1500
/** Below these node diameters in pixels the text and chips would crowd each other, then the icon itself would. */
const DETAIL_MIN_DIAMETER = 34
const ICON_MIN_DIAMETER = 18
/** An edge label needs this much bare line between the two nodes. */
const EDGE_LABEL_MIN_GAP = 64
/** Sigma fits the whole graph at camera ratio 1. When that would shrink the layout below this scale, open zoomed in. */
const MIN_OPEN_SCALE = 0.62
/** Spacing of the dot grid in graph units. */
const GRID = 56
/** How far past the viewport edge an element is still placed, so it does not pop in while panning. */
const MARGIN = 140

type NodeEntry = {
  node: GraphNode
  x: number
  y: number
  view: HTMLElement | undefined
  shown: boolean
  diameter: number
  detail: number
}
type EdgeEntry = { edge: GraphEdge; source: NodeEntry; target: NodeEntry; label: HTMLElement | undefined }

/**
 * Draws the graph. Sigma renders the circles, the edges and their arrowheads on the GPU. Everything with text or a
 * logo is an HTML element in the overlay, placed from Sigma's camera after each frame and only for what is in view,
 * so the text stays sharp and the cost follows what is on screen, not the size of the graph.
 */
export function mountGraph(input: MountInput) {
  const line = pathLine()
  const curved = pathCurved()
  const arrow = extremityArrow({ lengthRatio: 7, widthRatio: 5.5 })

  const palette = readPalette(input.frame)
  const graph = new Graph({ type: "directed", multi: false })
  const nodes = input.data.nodes.flatMap((node): NodeEntry[] => {
    const point = input.layout.positions.get(node.id)
    if (!point) return []
    graph.addNode(node.id, {
      x: point.x,
      y: point.y,
      size: NODE_RADIUS + 4 * node.importance,
      color: node.kind === "service" ? palette.raised : KIND_COLOR[node.kind],
    })
    return [{ node, x: point.x, y: point.y, view: undefined, shown: false, diameter: 0, detail: -1 }]
  })
  const byId = new Map(nodes.map((entry) => [entry.node.id, entry]))
  const edges = input.data.edges.flatMap((edge): EdgeEntry[] => {
    const source = byId.get(edge.source)
    const target = byId.get(edge.target)
    if (!source || !target) return []
    graph.addEdge(edge.source, edge.target, {
      size: 1,
      color: palette.edge,
      // Edges toward less important nodes are fainter.
      opacity: 0.3 + 0.5 * target.node.importance,
      path: edge.curvature ? curved.name : line.name,
      curvature: edge.curvature ?? 0,
    })
    return [{ edge, source, target, label: undefined }]
  })

  const opening = openingRatio(input.layout, input.stage.clientWidth, input.stage.clientHeight)
  const sigma = new Sigma(graph, input.stage, {
    primitives: {
      nodes: { shapes: [sdfCircle()], layers: [layerFill()] },
      edges: {
        paths: [line, curved],
        extremities: [arrow],
        layers: [layerPlain()],
        // The curved path reads this per edge. Declared here so the styles below can bind it.
        variables: { curvature: { type: "number", default: 0 } },
      },
    },
    styles: {
      nodes: [
        DEFAULT_STYLES.nodes,
        {
          size: { attribute: "size", defaultValue: NODE_RADIUS },
          color: { attribute: "color" },
          labelVisibility: "hidden",
          backdropVisibility: "hidden",
        },
      ],
      edges: [
        DEFAULT_STYLES.edges,
        {
          color: { attribute: "color" },
          opacity: { attribute: "opacity", defaultValue: 1 },
          head: arrow.name,
          path: { attribute: "path", defaultValue: line.name },
          curvature: { attribute: "curvature", defaultValue: 0 },
        },
      ],
      stage: { background: "transparent", cursor: "grab" },
    },
    settings: {
      renderLabels: false,
      renderEdgeLabels: false,
      enableEdgeEvents: false,
      enableNodeDrag: false,
      gestureTarget: "graph",
      // Node sizes are screen pixels: a node keeps its size whatever the extent of the graph.
      itemSizesReference: "screen",
      // Sigma grows nodes as the camera zooms in. Anchor that curve so a node is its set size when the page opens.
      zoomToSizeRatioFunction: (ratio) => Math.sqrt(ratio / opening),
      autoRescaleContent: "nodes",
      stagePadding: 80,
      minCameraRatio: 0.2,
      maxCameraRatio: 3,
    },
  })

  const boundary = input.layout.boundary ? element("div", "boundary") : undefined
  boundary?.append(element("span", "boundary-caption", input.t(BOUNDARY_KEY)))
  const edgeLayer = element("div", "edge-labels")
  const nodeLayer = element("div", "nodes")
  input.overlay.replaceChildren(...(boundary ? [boundary] : []), edgeLayer, nodeLayer)

  let labelled = new Set<EdgeEntry>()
  const sync = () => {
    syncGrid(sigma, input.frame)
    const { width, height } = sigma.getDimensions()

    const inView = new Set<NodeEntry>()
    nodes.forEach((entry) => {
      const display = sigma.getNodeDisplayData(entry.node.id)
      if (!display) return
      const point = sigma.graphToViewport(entry)
      entry.diameter = 2 * sigma.scaleSize(display.size)
      if (point.x < -MARGIN || point.x > width + MARGIN || point.y < -MARGIN || point.y > height + MARGIN) return
      inView.add(entry)
      const view = (entry.view ??= createNodeView(entry.node, input.t, nodeLayer))
      view.style.transform = `translate(${point.x.toFixed(1)}px, ${point.y.toFixed(1)}px)`
      if (view.dataset.d !== entry.diameter.toFixed(0)) {
        view.dataset.d = entry.diameter.toFixed(0)
        view.style.setProperty("--d", `${entry.diameter.toFixed(1)}px`)
      }
    })
    nodes.forEach((entry) => {
      if (!entry.view || entry.shown === inView.has(entry)) return
      entry.shown = !entry.shown
      entry.view.style.display = entry.shown ? "" : "none"
    })
    inView.forEach((entry) => {
      const level =
        inView.size > ICON_LIMIT || entry.diameter < ICON_MIN_DIAMETER
          ? 0
          : inView.size > DETAIL_LIMIT || entry.diameter < DETAIL_MIN_DIAMETER
            ? 1
            : 2
      if (entry.detail === level || !entry.view) return
      entry.detail = level
      entry.view.dataset.detail = String(level)
    })

    labelled = syncEdgeLabels(inView.size <= DETAIL_LIMIT, width, height, labelled)
    if (boundary && input.layout.boundary) syncBoundary(sigma, boundary, input.layout.boundary)
  }

  const syncEdgeLabels = (enabled: boolean, width: number, height: number, previous: Set<EdgeEntry>) => {
    const next = new Set<EdgeEntry>()
    if (enabled)
      edges.forEach((entry) => {
        const a = sigma.graphToViewport(entry.source)
        const b = sigma.graphToViewport(entry.target)
        const dx = b.x - a.x
        const dy = b.y - a.y
        const length = Math.hypot(dx, dy)
        if (length - (entry.source.diameter + entry.target.diameter) / 2 < EDGE_LABEL_MIN_GAP) return
        // A curved edge is a quadratic curve: its midpoint sits half the control offset off the straight line.
        const bend = (entry.edge.curvature ?? 0) * length * 0.5
        const x = (a.x + b.x) / 2 + (-dy / length) * bend
        const y = (a.y + b.y) / 2 + (dx / length) * bend
        if (x < -60 || x > width + 60 || y < -30 || y > height + 30) return
        // Text reads left to right whichever way the edge points.
        const angle = dx < 0 ? Math.atan2(-dy, -dx) : Math.atan2(dy, dx)
        const label = (entry.label ??= createEdgeLabel(input.t(EDGE_KEY[entry.edge.kind]), edgeLayer))
        label.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px) translate(-50%, -50%) rotate(${angle.toFixed(3)}rad)`
        if (!previous.has(entry)) label.style.display = ""
        next.add(entry)
      })
    previous.forEach((entry) => {
      if (!next.has(entry) && entry.label) entry.label.style.display = "none"
    })
    return next
  }

  openCamera(sigma, opening, input.layout.boundary)
  sigma.on("afterRender", sync)
  // Sigma draws once while it is constructed, before this listener exists.
  sync()
  const observer = new ResizeObserver(() => sigma.resize())
  observer.observe(input.stage)
  // A theme switch changes the CSS tokens. Overlay colors follow by themselves; WebGL colors are set here.
  const themeObserver = new MutationObserver(() => {
    const next = readPalette(input.frame)
    graph.updateEachEdgeAttributes((_, attributes) => ({ ...attributes, color: next.edge }))
    nodes.forEach((entry) => entry.node.kind === "service" && graph.setNodeAttribute(entry.node.id, "color", next.raised))
  })
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-color-scheme"] })

  return {
    kill() {
      observer.disconnect()
      themeObserver.disconnect()
      sigma.off("afterRender", sync)
      sigma.kill()
      input.overlay.replaceChildren()
      input.frame.style.removeProperty("background-size")
      input.frame.style.removeProperty("background-position")
    },
  }
}

/** The theme colors WebGL needs, resolved to hex: Sigma cannot read CSS variables. */
function readPalette(frame: HTMLElement) {
  return { edge: cssColor(frame, "--sg-edge", "#8497b0"), raised: cssColor(frame, "--sg-raised", "#ffffff") }
}

// A canvas turns any CSS color (oklch, color-mix, var chains) into the sRGB pixel Sigma can parse.
let probe: CanvasRenderingContext2D | null | undefined
function cssColor(frame: HTMLElement, variable: string, fallback: string) {
  probe ??= document.createElement("canvas").getContext("2d", { willReadFrequently: true })
  const value = getComputedStyle(frame).getPropertyValue(variable).trim()
  if (!probe || !value) return fallback
  probe.clearRect(0, 0, 1, 1)
  probe.fillStyle = "#000"
  probe.fillStyle = value
  probe.fillRect(0, 0, 1, 1)
  const [red, green, blue] = probe.getImageData(0, 0, 1, 1).data
  return `#${[red, green, blue].map((channel) => (channel ?? 0).toString(16).padStart(2, "0")).join("")}`
}

/**
 * Nodes keep their pixel size, so a graph fitted into a small view piles up. When fitting would shrink the layout below
 * MIN_OPEN_SCALE, open zoomed in and let the user pan. Sigma fits the whole graph at ratio 1.
 */
function openingRatio(layout: Layout, width: number, height: number) {
  const circle = layout.boundary
  const points = [...layout.positions.values()]
  const xs = points.map((point) => point.x).concat(circle ? [circle.x - circle.radius, circle.x + circle.radius] : [])
  const ys = points.map((point) => point.y).concat(circle ? [circle.y - circle.radius, circle.y + circle.radius] : [])
  const fit = Math.min(
    (width - 160) / Math.max(Math.max(...xs) - Math.min(...xs), 1),
    (height - 160) / Math.max(Math.max(...ys) - Math.min(...ys), 1),
  )
  return fit < MIN_OPEN_SCALE ? Math.max(fit / MIN_OPEN_SCALE, 0.2) : 1
}

/** Opens centered on the graph, leaning toward the boundary so the third-party group is in view when the graph is cropped. */
function openCamera(sigma: Sigma, ratio: number, boundary: Boundary | undefined) {
  const camera = sigma.getCamera()
  if (!boundary || ratio >= 1) return camera.setState({ ratio })
  const framed = sigma.graphToFramedGraph(boundary)
  camera.setState({ ratio, x: 0.5 + 0.4 * (framed.x - 0.5), y: 0.5 + 0.4 * (framed.y - 0.5) })
}

/** The dot grid follows the camera, so the canvas reads as one surface when panning and zooming. */
function syncGrid(sigma: Sigma, frame: HTMLElement) {
  const origin = sigma.graphToViewport({ x: 0, y: 0 })
  let step = Math.abs(sigma.graphToViewport({ x: GRID, y: 0 }).x - origin.x)
  if (!Number.isFinite(step) || step <= 0) return
  while (step < 20) step *= 2
  while (step > 40) step /= 2
  frame.style.backgroundSize = `${step.toFixed(2)}px ${step.toFixed(2)}px`
  frame.style.backgroundPosition = `${(origin.x % step).toFixed(2)}px ${(origin.y % step).toFixed(2)}px`
}

function syncBoundary(sigma: Sigma, root: HTMLElement, boundary: Boundary) {
  const center = sigma.graphToViewport(boundary)
  const radius = Math.abs(sigma.graphToViewport({ x: boundary.x + boundary.radius, y: boundary.y }).x - center.x)
  root.style.width = root.style.height = `${(radius * 2).toFixed(1)}px`
  root.style.transform = `translate(${(center.x - radius).toFixed(1)}px, ${(center.y - radius).toFixed(1)}px)`
}

function createNodeView(node: GraphNode, t: MountInput["t"], layer: HTMLElement) {
  const root = element("div", "node")
  root.dataset.kind = node.kind
  // The SVG strings are constants from icons.ts. Everything that comes from data goes in as text.
  if (node.brand) {
    const logo = element("div", "ring")
    logo.innerHTML = brandLogo(node.brand)
    root.append(logo)
  } else if (node.kind !== "service") {
    const icon = element("div", "icon")
    icon.innerHTML = kindIcon(node.kind)
    root.append(icon)
  }
  if (node.language) {
    const mark = element("div", "language")
    mark.innerHTML = languageMark(node.language)
    root.append(mark)
  }
  if (node.count !== undefined) root.append(element("div", "badge", String(node.count)))
  if (node.tags?.length) {
    const chips = element("div", "chips")
    node.tags.forEach((tag) => {
      const chip = element("span", "chip", t(TAG_KEY[tag]))
      chip.dataset.tone = RISK_TAGS.has(tag) ? "risk" : "neutral"
      chips.append(chip)
    })
    root.append(chips)
  }
  const label = element("div", "label")
  label.append(
    element("div", "type", node.brand ? t(CATEGORY_KEY[node.brand]) : node.kind === "service" ? "" : t(KIND_KEY[node.kind])),
    element("div", "name", node.brand ? BRAND_NAME[node.brand] : node.name),
  )
  root.append(label)
  layer.append(root)
  return root
}

function createEdgeLabel(text: string, layer: HTMLElement) {
  const label = element("span", "edge-label", text)
  layer.append(label)
  return label
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, slot: string, text?: string) {
  const node = document.createElement(tag)
  node.dataset.slot = slot
  if (text !== undefined) node.textContent = text
  return node
}
