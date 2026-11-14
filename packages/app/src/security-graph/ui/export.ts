// Export of the visible graph: PNG (composited layers), SVG and JSON (pure string builders).
// The builders take plain data so the benchmark can reuse them without a DOM.
import { createHulls, type Hull } from "../layout/hulls"
import type { Visible } from "../projection/engine"
import type { RenderGraph } from "../render/types"
import { nodeTypes, palettes, severities, sizes, type ThemeMode } from "../theme"

export type PngSource = {
  /** Renders Sigma synchronously so its WebGL canvases can be read in this task. */
  renderNow(): void
}

/** Composites the overlay back canvas, the Sigma canvases and the overlay front canvas in DOM order. */
export async function exportPng(container: HTMLElement, source?: PngSource): Promise<Blob> {
  source?.renderNow()
  const width = container.clientWidth
  const height = container.clientHeight
  const ratio = window.devicePixelRatio || 1
  const out = document.createElement("canvas")
  out.width = Math.max(1, Math.round(width * ratio))
  out.height = Math.max(1, Math.round(height * ratio))
  const context = out.getContext("2d")
  if (!context) throw new Error("2d canvas is unavailable")
  // WebGL buffers are only valid until the next task, so draw every layer before awaiting anything.
  Array.from(container.children).forEach((child) => {
    if (!(child instanceof HTMLCanvasElement) || child.width === 0 || child.height === 0) return
    context.drawImage(child, 0, 0, out.width, out.height)
  })
  return toBlob(out)
}

function toBlob(canvas: HTMLCanvasElement) {
  return new Promise<Blob>((resolve, reject) => {
    if (typeof canvas.toBlob === "function") {
      canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("PNG encoding failed"))), "image/png")
      return
    }
    const bytes = atob(canvas.toDataURL("image/png").split(",")[1] ?? "")
    resolve(new Blob([Uint8Array.from(bytes, (char) => char.charCodeAt(0))], { type: "image/png" }))
  })
}

/** Adapts the visible projection to the renderer's input, including boundary hulls. */
export function renderGraphOf(visible: Visible): RenderGraph {
  const ids = new Set(visible.nodes.map((node) => node.id))
  const at = new Map(visible.nodes.map((node) => [node.id, node]))
  const hulls = createHulls(
    visible.boundaries.map((item) => ({ id: item.id, label: item.label, memberIds: item.memberIds, parentId: item.parentId })),
    { owner: (id) => (ids.has(id) ? id : undefined) },
  )
  return {
    nodes: visible.nodes.map((node) => ({
      id: node.id,
      type: node.type,
      name: node.name,
      x: node.x,
      y: node.y,
      severity: node.severity,
      count: node.count,
      expanded: node.expanded,
      hasChildren: node.hasChildren,
      tags: node.tags.map((tag) => ({ label: tag.label, severity: "risk" as const, count: tag.count })),
      external: node.type === "external-service",
    })),
    edges: visible.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      relation: edge.relation,
      count: edge.count,
    })),
    paths: visible.paths.map((path) => ({
      id: path.id,
      from: path.entry,
      to: path.target,
      severity: path.severity,
      segments: path.segments.map((segment) => ({ from: segment.from, to: segment.to })),
    })),
    boundaries: hulls.update((id) => at.get(id)),
  }
}

const xmlEscapes: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }
// Control characters other than tab, LF and CR are not valid in XML 1.0.
const invalidXml = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g
const escapeXml = (text: string) => text.replace(invalidXml, "").replace(/[&<>"']/g, (char) => xmlEscapes[char] ?? char)
const num = (value: number) => String(Math.round(value * 100) / 100)

/** Standalone SVG of a render graph. All text is escaped. */
export function exportSvg(graph: RenderGraph, mode: ThemeMode): string {
  const palette = palettes[mode]
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]))
  const radius = (id: string) => (nodes.get(id)?.size ?? sizes.node) / 2
  const margin = sizes.node
  const box = bounds(graph)
  const x0 = box.x0 - margin
  const y0 = box.y0 - margin
  const width = box.x1 - box.x0 + margin * 2
  const height = box.y1 - box.y0 + margin * 2
  const edges = graph.edges.flatMap((edge) => {
    const a = nodes.get(edge.source)
    const b = nodes.get(edge.target)
    if (!a || !b) return []
    const distance = Math.hypot(b.x - a.x, b.y - a.y) || 1
    const ux = (b.x - a.x) / distance
    const uy = (b.y - a.y) / distance
    const from = radius(a.id)
    const to = radius(b.id) + sizes.arrowhead
    const label =
      edge.count > 1
        ? `<text x="${num((a.x + b.x) / 2)}" y="${num((a.y + b.y) / 2)}" font-size="${sizes.edgeLabelFont}" text-anchor="middle" fill="${palette.edgeLabel}">${escapeXml(`${edge.relation} ×${edge.count}`)}</text>`
        : ""
    return [
      `<line x1="${num(a.x + ux * from)}" y1="${num(a.y + uy * from)}" x2="${num(b.x - ux * to)}" y2="${num(b.y - uy * to)}" stroke="${palette.edge}" stroke-width="${sizes.edgeWidth}" marker-end="url(#arrow)"/>`,
      label,
    ]
  })
  const hulls = graph.boundaries.map((hull) => hullElement(hull, palette.boundaryStroke, palette.boundaryCaption))
  const paths = graph.paths.flatMap((path) =>
    path.segments.flatMap((segment) => {
      const a = nodes.get(segment.from)
      const b = nodes.get(segment.to)
      if (!a || !b) return []
      const color = severities[path.severity].color
      return [`<line x1="${num(a.x)}" y1="${num(a.y)}" x2="${num(b.x)}" y2="${num(b.y)}" stroke="${color}" stroke-width="${sizes.edgeWidth * 3}" stroke-opacity="0.6" stroke-linecap="round"/>`]
    }),
  )
  const circles = graph.nodes.flatMap((node) => {
    const fill = node.external ? palette.externalFill : nodeTypes[node.type].color
    const stroke = node.severity ? severities[node.severity].color : node.external ? palette.externalRing : "none"
    const badge = node.hasChildren && !node.expanded && node.count > 0 ? ` +${node.count}` : ""
    return [
      `<circle cx="${num(node.x)}" cy="${num(node.y)}" r="${num(radius(node.id))}" fill="${fill}" stroke="${stroke}" stroke-width="${stroke === "none" ? 0 : 2}"/>`,
      `<text x="${num(node.x)}" y="${num(node.y + radius(node.id) + sizes.labelFont + 2)}" font-size="${sizes.labelFont}" text-anchor="middle" fill="${palette.label}">${escapeXml(node.name + badge)}</text>`,
    ]
  })
  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${num(x0)} ${num(y0)} ${num(width)} ${num(height)}" width="${num(width)}" height="${num(height)}" font-family="sans-serif">`,
    `<defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="${sizes.arrowhead}" markerHeight="${sizes.arrowhead}" markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0L10 5L0 10z" fill="${palette.edge}"/></marker></defs>`,
    `<rect x="${num(x0)}" y="${num(y0)}" width="${num(width)}" height="${num(height)}" fill="${palette.canvas}"/>`,
    ...hulls,
    ...paths,
    ...edges,
    ...circles,
    `</svg>`,
  ]
    .filter(Boolean)
    .join("\n")
}

function hullElement(hull: Hull, stroke: string, caption: string) {
  const shape =
    hull.kind === "circle"
      ? `<circle cx="${num(hull.center.x)}" cy="${num(hull.center.y)}" r="${num(hull.radius)}" fill="none" stroke="${stroke}" stroke-width="${sizes.boundaryStroke}"/>`
      : `<polygon points="${hull.points.map((point) => `${num(point[0])},${num(point[1])}`).join(" ")}" fill="none" stroke="${stroke}" stroke-width="${sizes.boundaryStroke}"/>`
  return `${shape}<text x="${num(hull.caption.x)}" y="${num(hull.caption.y - 4)}" font-size="${sizes.mutedLabelFont}" text-anchor="middle" fill="${caption}">${escapeXml(hull.label)}</text>`
}

function bounds(graph: RenderGraph) {
  const box = { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity }
  const add = (x: number, y: number) => {
    box.x0 = Math.min(box.x0, x)
    box.y0 = Math.min(box.y0, y)
    box.x1 = Math.max(box.x1, x)
    box.y1 = Math.max(box.y1, y)
  }
  graph.nodes.forEach((node) => add(node.x, node.y))
  graph.boundaries.forEach((hull) => {
    if (hull.kind === "circle") {
      add(hull.center.x - hull.radius, hull.center.y - hull.radius)
      add(hull.center.x + hull.radius, hull.center.y + hull.radius)
      return
    }
    hull.points.forEach((point) => add(point[0], point[1]))
  })
  return box.x0 === Infinity ? { x0: 0, y0: 0, x1: 0, y1: 0 } : box
}

/** JSON of the visible projection: ids, positions, edges with counts, paths. Entity attributes are never included. */
export function exportJson(visible: Visible): string {
  return JSON.stringify(
    {
      nodes: visible.nodes.map((node) => ({
        id: node.id,
        type: node.type,
        name: node.name,
        severity: node.severity,
        count: node.count,
        expanded: node.expanded,
        x: node.x,
        y: node.y,
        tags: node.tags.map((tag) => ({ label: tag.label, count: tag.count })),
      })),
      edges: visible.edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        relation: edge.relation,
        count: edge.count,
        members: edge.members,
      })),
      paths: visible.paths.map((path) => ({
        id: path.id,
        entry: path.entry,
        target: path.target,
        severity: path.severity,
        segments: path.segments.map((segment) => ({ from: segment.from, to: segment.to, count: segment.count })),
      })),
      boundaries: visible.boundaries.map((item) => ({
        id: item.id,
        label: item.label,
        parentId: item.parentId,
        memberIds: item.memberIds,
      })),
    },
    null,
    2,
  )
}

/** Saves through an object URL and a clicked <a download>. Without `URL.createObjectURL`, falls back to a data URL. */
export function download(content: Blob | string, filename: string, mime: string) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mime })
  const link = document.createElement("a")
  link.download = filename
  link.rel = "noopener"
  if (typeof URL.createObjectURL === "function") {
    const url = URL.createObjectURL(blob)
    link.href = url
    click(link)
    // Revoke after the browser has started the download.
    setTimeout(() => URL.revokeObjectURL(url), 0)
    return Promise.resolve()
  }
  return new Promise<void>((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      link.href = String(reader.result)
      click(link)
      resolve()
    }
    reader.onerror = () => reject(reader.error ?? new Error("download failed"))
    reader.readAsDataURL(blob)
  })
}

function click(link: HTMLAnchorElement) {
  document.body.appendChild(link)
  link.click()
  link.remove()
}
