// Canvas layers around Sigma. No DOM element is created per node.
//   back  (under WebGL): canvas color, dot grid, boundary hulls and captions, attack-path
//         highlight, agent-lit edges, agent glow. Nodes and edges draw over it.
//   front (above WebGL): count text, severity markers, and, above the label thresholds,
//         labels, pills, language icons and rotated edge labels. Only in-viewport nodes.
// Everything is drawn in viewport pixels from graph coordinates through `OverlayView`.
import type { Hull } from "../layout/hulls"
import {
  canvasFont,
  nodeTypes,
  palettes,
  pills,
  readFontFamily,
  severities,
  sizes,
  zoom,
  type SeverityShape,
  type ThemeMode,
} from "../theme"
import { languageIcons, type Atlas } from "./atlas"
import { badgeCenter, badgeRadius, mainRadius } from "./programs/geometry"
import type { Highlight, RenderEdge, RenderNode, RenderPath } from "./types"

export const litFadeMs = 4000

export type OverlayView = {
  toViewport: (x: number, y: number) => { x: number; y: number }
  toGraph: (x: number, y: number) => { x: number; y: number }
  /** Screen pixels per graph unit. */
  scale: () => number
}

export type Scene = {
  nodes: ReadonlyMap<string, RenderNode>
  edges: ReadonlyMap<string, RenderEdge>
  paths: ReadonlyMap<string, RenderPath>
  boundaries: readonly Hull[]
  highlight: Highlight
  /** Nodes and edges kept at full opacity. Undefined means nothing is dimmed. */
  focus?: { nodes: ReadonlySet<string>; edges: ReadonlySet<string> }
}

export type OverlayOptions = {
  mode: ThemeMode
  atlas: Atlas
  view: OverlayView
  /** Visible text of an entity type. Defaults to the type key. */
  typeLabel?: (type: string) => string
  /** Visible text of a relation. Defaults to the relation key. */
  relationLabel?: (relation: string) => string
  /** Replaces the default boundary-crossing marker. Called with the segment midpoint and angle. */
  drawCrossing?: (context: CanvasRenderingContext2D, x: number, y: number, angle: number, color: string) => void
}

// Half-size of the node quad, circle radius and badge geometry in screen pixels.
export function nodeGeometry(node: { size?: number }, scale: number) {
  const diameter = node.size ?? sizes.node
  const quad = (diameter / 2 / mainRadius) * scale
  return {
    radius: (diameter / 2) * scale,
    quad,
    badgeX: badgeCenter * quad,
    badgeY: -badgeCenter * quad,
    badgeRadius: badgeRadius * quad,
  }
}

// Quad half-size in graph units for the Sigma `size` attribute.
export function sigmaSize(node: { size?: number }) {
  return (node.size ?? sizes.node) / 2 / mainRadius
}

export function createOverlay(container: HTMLElement, options: OverlayOptions) {
  const family = readFontFamily("sans", container) || getComputedStyle(container).fontFamily
  const view = options.view
  const typeLabel = options.typeLabel ?? ((type: string) => type)
  const relationLabel = options.relationLabel ?? ((relation: string) => relation)
  if (getComputedStyle(container).position === "static") container.style.position = "relative"
  const back = layer(container, true)
  const front = layer(container, false)
  const backContext = back.getContext("2d")
  const frontContext = front.getContext("2d")
  const widths = new Map<string, number>()
  let mode = options.mode
  let frame = 0

  function draw(scene: Scene) {
    if (!backContext || !frontContext) return
    const width = container.clientWidth
    const height = container.clientHeight
    const ratio = window.devicePixelRatio || 1
    prepare(back, backContext, width, height, ratio)
    prepare(front, frontContext, width, height, ratio)
    const scale = view.scale()
    drawBack(backContext, scene, width, height, scale)
    if (scale >= zoom.iconThreshold) drawFront(frontContext, scene, width, height, scale)
  }

  // One redraw per animation frame for changes that do not make Sigma render.
  function schedule(scene: () => Scene) {
    if (frame) return
    frame = requestAnimationFrame(() => {
      frame = 0
      draw(scene())
    })
  }

  function drawBack(context: CanvasRenderingContext2D, scene: Scene, width: number, height: number, scale: number) {
    const palette = palettes[mode]
    context.fillStyle = palette.canvas
    context.fillRect(0, 0, width, height)
    dotGrid(context, width, height, scale)
    scene.boundaries.forEach((hull) => drawHull(context, hull, scale))
    scene.highlight.paths.forEach((id) => {
      const path = scene.paths.get(id)
      if (path) drawPath(context, scene, path)
    })
    drawLit(context, scene)
    scene.highlight.agent.forEach((id) => {
      const node = scene.nodes.get(id)
      if (node) drawGlow(context, node, scale)
    })
  }

  function dotGrid(context: CanvasRenderingContext2D, width: number, height: number, scale: number) {
    const palette = palettes[mode]
    // Grid is anchored to the graph. Spacing doubles until dots are at least 10px apart.
    const spacing = (() => {
      let value = palette.dotSpacing * scale
      if (!(value > 0)) return 0
      while (value < 10) value *= 2
      return value
    })()
    if (!spacing) return
    const origin = view.toViewport(0, 0)
    const startX = ((origin.x % spacing) + spacing) % spacing
    const startY = ((origin.y % spacing) + spacing) % spacing
    const size = palette.dotRadius * 2
    context.fillStyle = palette.dot
    for (let x = startX; x < width; x += spacing)
      for (let y = startY; y < height; y += spacing) context.fillRect(x - palette.dotRadius, y - palette.dotRadius, size, size)
  }

  function drawHull(context: CanvasRenderingContext2D, hull: Hull, scale: number) {
    const palette = palettes[mode]
    context.strokeStyle = palette.boundaryStroke
    context.lineWidth = sizes.boundaryStroke
    context.beginPath()
    if (hull.kind === "circle") {
      const center = view.toViewport(hull.center.x, hull.center.y)
      context.arc(center.x, center.y, hull.radius * scale, 0, Math.PI * 2)
    }
    if (hull.kind === "hull")
      hull.points.forEach((point, index) => {
        const at = view.toViewport(point[0], point[1])
        if (index === 0) context.moveTo(at.x, at.y)
        else context.lineTo(at.x, at.y)
      })
    if (hull.kind === "hull") context.closePath()
    context.stroke()
    const caption = view.toViewport(hull.caption.x, hull.caption.y)
    context.font = canvasFont(sizes.mutedLabelFont, family, 400)
    context.fillStyle = palette.boundaryCaption
    context.textAlign = "center"
    context.textBaseline = "bottom"
    context.fillText(hull.label, caption.x, caption.y - 4)
  }

  function drawPath(context: CanvasRenderingContext2D, scene: Scene, path: RenderPath) {
    const color = severities[path.severity].color
    context.lineCap = "round"
    path.segments.forEach((segment) => {
      const from = scene.nodes.get(segment.from)
      const to = scene.nodes.get(segment.to)
      if (!from || !to) return
      const a = view.toViewport(from.x, from.y)
      const b = view.toViewport(to.x, to.y)
      context.beginPath()
      context.moveTo(a.x, a.y)
      context.lineTo(b.x, b.y)
      context.globalAlpha = 0.25
      context.strokeStyle = color
      context.lineWidth = 8
      context.stroke()
      context.globalAlpha = 0.95
      context.lineWidth = 2.5
      context.stroke()
      context.globalAlpha = 1
    })
  }

  function drawLit(context: CanvasRenderingContext2D, scene: Scene) {
    const now = scene.highlight.now ?? Date.now()
    context.strokeStyle = nodeTypes["ai-agent"].color
    context.lineWidth = 2.5
    context.lineCap = "round"
    scene.highlight.lit.forEach((lit) => {
      const edge = scene.edges.get(lit.id)
      const alpha = 1 - (now - lit.ts) / litFadeMs
      if (!edge || alpha <= 0) return
      const from = scene.nodes.get(edge.source)
      const to = scene.nodes.get(edge.target)
      if (!from || !to) return
      const a = view.toViewport(from.x, from.y)
      const b = view.toViewport(to.x, to.y)
      context.globalAlpha = Math.min(1, alpha)
      context.beginPath()
      context.moveTo(a.x, a.y)
      context.lineTo(b.x, b.y)
      context.stroke()
    })
    context.globalAlpha = 1
  }

  function drawGlow(context: CanvasRenderingContext2D, node: RenderNode, scale: number) {
    const at = view.toViewport(node.x, node.y)
    const radius = nodeGeometry(node, scale).radius + 6
    const color = nodeTypes["ai-agent"].color
    context.beginPath()
    context.arc(at.x, at.y, radius, 0, Math.PI * 2)
    context.globalAlpha = 0.18
    context.fillStyle = color
    context.fill()
    context.globalAlpha = 0.8
    context.strokeStyle = color
    context.lineWidth = 2
    context.stroke()
    context.globalAlpha = 1
  }

  function drawFront(context: CanvasRenderingContext2D, scene: Scene, width: number, height: number, scale: number) {
    const labels = scale >= zoom.labelThreshold
    const margin = 160
    const corner = view.toGraph(-margin, -margin)
    const opposite = view.toGraph(width + margin, height + margin)
    const minX = Math.min(corner.x, opposite.x)
    const maxX = Math.max(corner.x, opposite.x)
    const minY = Math.min(corner.y, opposite.y)
    const maxY = Math.max(corner.y, opposite.y)
    const visible = new Set<string>()
    scene.nodes.forEach((node) => {
      if (node.x < minX || node.x > maxX || node.y < minY || node.y > maxY) return
      visible.add(node.id)
      const alpha = scene.focus && !scene.focus.nodes.has(node.id) ? sizes.dimAlpha : 1
      context.globalAlpha = alpha
      const at = view.toViewport(node.x, node.y)
      const geometry = nodeGeometry(node, scale)
      if (node.hasChildren && !node.expanded && node.count > 0) drawCount(context, node, at, geometry)
      if (node.severity) drawSeverity(context, node.severity, at.x + geometry.radius * 0.75, at.y + geometry.radius * 0.75)
      if (labels) drawNodeText(context, node, at, geometry.radius)
    })
    context.globalAlpha = 1
    if (scale >= zoom.edgeLabelThreshold) drawEdgeLabels(context, scene, visible)
    drawCrossings(context, scene)
  }

  function measure(context: CanvasRenderingContext2D, text: string) {
    const key = `${context.font}|${text}`
    const known = widths.get(key)
    if (known !== undefined) return known
    const value = context.measureText(text).width
    widths.set(key, value)
    return value
  }

  function drawCount(
    context: CanvasRenderingContext2D,
    node: RenderNode,
    at: { x: number; y: number },
    geometry: ReturnType<typeof nodeGeometry>,
  ) {
    const palette = palettes[mode]
    context.font = canvasFont(Math.max(7, geometry.badgeRadius * 1.15), family, 500)
    context.fillStyle = node.external ? "#111827" : palette.badgeText
    context.textAlign = "center"
    context.textBaseline = "middle"
    context.fillText(formatCount(node.count), at.x + geometry.badgeX, at.y + geometry.badgeY, geometry.badgeRadius * 1.8)
  }

  function drawSeverity(context: CanvasRenderingContext2D, severity: keyof typeof severities, x: number, y: number) {
    const token = severities[severity]
    const half = 7
    shape(context, token.shape, x, y, half, token.color, palettes[mode].canvas)
    const rect = options.atlas.rect(token.icon)
    if (!rect || !options.atlas.canvas) return
    const size = half * 1.5
    context.drawImage(options.atlas.canvas, rect.x, rect.y, rect.w, rect.h, x - size / 2, y - size / 2, size, size)
  }

  function drawNodeText(context: CanvasRenderingContext2D, node: RenderNode, at: { x: number; y: number }, radius: number) {
    const palette = palettes[mode]
    context.textAlign = "center"
    context.textBaseline = "top"
    context.font = canvasFont(sizes.labelFont, family, 500)
    context.fillStyle = palette.label
    const top = at.y + radius + 4
    context.fillText(typeLabel(node.type), at.x, top)
    context.font = canvasFont(sizes.mutedLabelFont, family, 400)
    context.fillStyle = palette.labelMuted
    context.fillText(node.name, at.x, top + sizes.labelFont + 2, 220)
    drawPills(context, node, at.x + radius * 0.8, at.y - radius)
    const icon = node.language && !node.external ? languageIcons[node.language as keyof typeof languageIcons] : undefined
    const rect = icon ? options.atlas.rect(icon) : undefined
    if (rect && options.atlas.canvas)
      context.drawImage(
        options.atlas.canvas,
        rect.x,
        rect.y,
        rect.w,
        rect.h,
        at.x - sizes.languageIcon / 2,
        at.y - radius - sizes.languageIcon - 2,
        sizes.languageIcon,
        sizes.languageIcon,
      )
  }

  function drawPills(context: CanvasRenderingContext2D, node: RenderNode, x: number, y: number) {
    context.font = canvasFont(sizes.pillFont, family, 500)
    context.textAlign = "left"
    context.textBaseline = "middle"
    node.tags.slice(0, 4).forEach((tag, index) => {
      const style = pills[mode][tag.severity === "risk" ? "risk" : "neutral"]
      const text = tag.count && tag.count > 1 ? `${tag.label} ${tag.count}` : tag.label
      const pillWidth = measure(context, text) + 10
      const top = y + index * (sizes.pillHeight + sizes.pillGap)
      context.beginPath()
      context.roundRect(x, top, pillWidth, sizes.pillHeight, sizes.pillHeight / 2)
      context.fillStyle = style.bg
      context.fill()
      context.strokeStyle = style.border
      context.lineWidth = 1
      context.stroke()
      context.fillStyle = style.text
      context.fillText(text, x + 5, top + sizes.pillHeight / 2 + 0.5)
    })
  }

  function drawEdgeLabels(context: CanvasRenderingContext2D, scene: Scene, visible: ReadonlySet<string>) {
    const palette = palettes[mode]
    context.font = canvasFont(sizes.edgeLabelFont, family, 400)
    context.textAlign = "center"
    context.textBaseline = "middle"
    context.lineJoin = "round"
    scene.edges.forEach((edge) => {
      if (!visible.has(edge.source) && !visible.has(edge.target)) return
      const from = scene.nodes.get(edge.source)
      const to = scene.nodes.get(edge.target)
      if (!from || !to) return
      const a = view.toViewport(from.x, from.y)
      const b = view.toViewport(to.x, to.y)
      const length = Math.hypot(b.x - a.x, b.y - a.y)
      const text = edge.count > 1 ? `${relationLabel(edge.relation)} ×${edge.count}` : relationLabel(edge.relation)
      // Skip edges too short to carry their label.
      if (length < measure(context, text) + 40) return
      const raw = Math.atan2(b.y - a.y, b.x - a.x)
      const angle = raw > Math.PI / 2 || raw < -Math.PI / 2 ? raw + Math.PI : raw
      context.save()
      context.globalAlpha = scene.focus && !scene.focus.edges.has(edge.id) ? sizes.dimAlpha : 1
      context.translate((a.x + b.x) / 2, (a.y + b.y) / 2)
      context.rotate(angle)
      context.lineWidth = 3
      context.strokeStyle = palette.halo
      context.strokeText(text, 0, 0)
      context.fillStyle = palette.edgeLabel
      context.fillText(text, 0, 0)
      context.restore()
    })
  }

  function drawCrossings(context: CanvasRenderingContext2D, scene: Scene) {
    scene.highlight.paths.forEach((id) => {
      const path = scene.paths.get(id)
      if (!path) return
      const color = severities[path.severity].color
      path.segments.forEach((segment) => {
        const from = scene.nodes.get(segment.from)
        const to = scene.nodes.get(segment.to)
        if (!segment.crossing || !from || !to) return
        const a = view.toViewport(from.x, from.y)
        const b = view.toViewport(to.x, to.y)
        const angle = Math.atan2(b.y - a.y, b.x - a.x)
        const x = (a.x + b.x) / 2
        const y = (a.y + b.y) / 2
        if (options.drawCrossing) return options.drawCrossing(context, x, y, angle, color)
        shape(context, "diamond", x, y, 6, color, palettes[mode].canvas)
      })
    })
  }

  return {
    draw,
    schedule,
    setMode(next: ThemeMode) {
      mode = next
    },
    dispose() {
      if (frame) cancelAnimationFrame(frame)
      back.remove()
      front.remove()
    },
  }
}

function layer(container: HTMLElement, under: boolean) {
  const canvas = document.createElement("canvas")
  canvas.setAttribute("aria-hidden", "true")
  Object.assign(canvas.style, { position: "absolute", inset: "0", width: "100%", height: "100%", pointerEvents: "none" })
  if (under) container.insertBefore(canvas, container.firstChild)
  else container.appendChild(canvas)
  return canvas
}

function prepare(canvas: HTMLCanvasElement, context: CanvasRenderingContext2D, width: number, height: number, ratio: number) {
  const pixelWidth = Math.max(1, Math.round(width * ratio))
  const pixelHeight = Math.max(1, Math.round(height * ratio))
  if (canvas.width !== pixelWidth) canvas.width = pixelWidth
  if (canvas.height !== pixelHeight) canvas.height = pixelHeight
  context.setTransform(ratio, 0, 0, ratio, 0, 0)
  context.clearRect(0, 0, width, height)
  context.globalAlpha = 1
}

function formatCount(count: number) {
  if (count < 1000) return String(count)
  if (count < 10_000) return `${(count / 1000).toFixed(1).replace(/\.0$/, "")}k`
  return `${Math.round(count / 1000)}k`
}

// Severity glyph shapes so severity is never color-only.
function shape(
  context: CanvasRenderingContext2D,
  kind: SeverityShape,
  x: number,
  y: number,
  half: number,
  color: string,
  background: string,
) {
  context.beginPath()
  if (kind === "diamond") {
    context.moveTo(x, y - half)
    context.lineTo(x + half, y)
    context.lineTo(x, y + half)
    context.lineTo(x - half, y)
    context.closePath()
  }
  if (kind === "triangle") {
    context.moveTo(x, y - half)
    context.lineTo(x + half, y + half * 0.8)
    context.lineTo(x - half, y + half * 0.8)
    context.closePath()
  }
  if (kind === "square") context.rect(x - half * 0.85, y - half * 0.85, half * 1.7, half * 1.7)
  if (kind === "shield") {
    context.moveTo(x, y - half)
    context.lineTo(x + half * 0.9, y - half * 0.55)
    context.lineTo(x + half * 0.9, y + half * 0.1)
    context.quadraticCurveTo(x + half * 0.6, y + half * 0.8, x, y + half)
    context.quadraticCurveTo(x - half * 0.6, y + half * 0.8, x - half * 0.9, y + half * 0.1)
    context.lineTo(x - half * 0.9, y - half * 0.55)
    context.closePath()
  }
  if (kind === "circle" || kind === "ring" || kind === "check") context.arc(x, y, half, 0, Math.PI * 2)
  if (kind === "ring") {
    context.fillStyle = background
    context.fill()
    context.strokeStyle = color
    context.lineWidth = 1.5
    context.stroke()
    return
  }
  context.fillStyle = color
  context.fill()
}
