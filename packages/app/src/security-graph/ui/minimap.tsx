import { createEffect, onCleanup, onMount } from "solid-js"
import { useTheme } from "@bellucode/ui/theme"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { Viewport } from "../render/types"
import { nodeTypes, palettes } from "../theme"

export type MinimapProps = {
  /** The driver of the loaded graph, or `undefined` while none is loaded. */
  driver: Driver | undefined
  /** Canvas size in CSS pixels. */
  width?: number
  height?: number
  class?: string
}

const padding = 6
const dot = 2
// Keyboard nudge as a fraction of the viewport extent.
const nudge = 0.1
// The driver has no event for filter or delta changes, so the visible set is polled this often.
const pollMs = 500

type Transform = { scale: number; x: number; y: number }
type Cache = {
  visible: Driver extends { visible: () => infer V } ? V : never
  bounds: { x0: number; y0: number; x1: number; y1: number }
  groups: Map<string, number[]>
}

export function Minimap(props: MinimapProps) {
  const language = useLanguage()
  const theme = useTheme()
  const width = () => props.width ?? 176
  const height = () => props.height ?? 120
  let canvas!: HTMLCanvasElement
  let frame = 0
  let dragging = false
  let viewport: Viewport | undefined
  let cache: Cache | undefined
  let transform: Transform = { scale: 1, x: 0, y: 0 }

  const invalidate = () => {
    if (frame) return
    frame = requestAnimationFrame(() => {
      frame = 0
      draw()
    })
  }

  onCleanup(() => cancelAnimationFrame(frame))

  createEffect(() => {
    theme.mode()
    width()
    height()
    invalidate()
  })

  createEffect(() => {
    const driver = props.driver
    viewport = undefined
    cache = undefined
    invalidate()
    if (!driver) return
    const stops = [
      driver.onViewport((next) => {
        viewport = next
        invalidate()
      }),
      driver.onState(invalidate),
    ]
    const poll = setInterval(() => {
      if (driver.visible() !== cache?.visible) invalidate()
    }, pollMs)
    onCleanup(() => {
      stops.forEach((stop) => stop())
      clearInterval(poll)
    })
  })

  onMount(invalidate)

  // Groups node coordinates by type once per visible set. Redraws reuse it.
  function index(driver: Driver): Cache {
    const visible = driver.visible()
    if (cache?.visible === visible) return cache
    const groups = new Map<string, number[]>()
    const bounds = { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity }
    for (const node of visible.nodes) {
      const key = node.type
      const list = groups.get(key)
      if (list) list.push(node.x, node.y)
      else groups.set(key, [node.x, node.y])
      bounds.x0 = Math.min(bounds.x0, node.x)
      bounds.y0 = Math.min(bounds.y0, node.y)
      bounds.x1 = Math.max(bounds.x1, node.x)
      bounds.y1 = Math.max(bounds.y1, node.y)
    }
    cache = { visible, bounds, groups }
    return cache
  }

  function draw() {
    const driver = props.driver
    const context = canvas.getContext("2d")
    if (!context) return
    const ratio = window.devicePixelRatio || 1
    const w = width()
    const h = height()
    if (canvas.width !== Math.round(w * ratio) || canvas.height !== Math.round(h * ratio)) {
      canvas.width = Math.round(w * ratio)
      canvas.height = Math.round(h * ratio)
    }
    context.setTransform(ratio, 0, 0, ratio, 0, 0)
    const palette = palettes[theme.mode()]
    context.clearRect(0, 0, w, h)
    context.fillStyle = palette.canvas
    context.fillRect(0, 0, w, h)
    if (!driver) return
    const data = index(driver)
    const box = { ...data.bounds }
    if (!Number.isFinite(box.x0)) {
      if (!viewport) return
      box.x0 = box.x1 = viewport.x
      box.y0 = box.y1 = viewport.y
    }
    // The map always contains the viewport, so the rectangle stays visible when the camera leaves the graph.
    const view = viewport && {
      x0: viewport.x - viewport.width / viewport.scale / 2,
      x1: viewport.x + viewport.width / viewport.scale / 2,
      y0: viewport.y - viewport.height / viewport.scale / 2,
      y1: viewport.y + viewport.height / viewport.scale / 2,
    }
    if (view) {
      box.x0 = Math.min(box.x0, view.x0)
      box.y0 = Math.min(box.y0, view.y0)
      box.x1 = Math.max(box.x1, view.x1)
      box.y1 = Math.max(box.y1, view.y1)
    }
    const scale = Math.min((w - padding * 2) / Math.max(1, box.x1 - box.x0), (h - padding * 2) / Math.max(1, box.y1 - box.y0))
    transform = {
      scale,
      x: (w - (box.x1 - box.x0) * scale) / 2 - box.x0 * scale,
      y: (h - (box.y1 - box.y0) * scale) / 2 - box.y0 * scale,
    }
    for (const [type, points] of data.groups) {
      context.fillStyle = type === "external-service" ? palette.externalRing : nodeTypes[type as keyof typeof nodeTypes].color
      for (let i = 0; i < points.length; i += 2) {
        context.fillRect(points[i]! * transform.scale + transform.x - dot / 2, points[i + 1]! * transform.scale + transform.y - dot / 2, dot, dot)
      }
    }
    if (!view) return
    const x = view.x0 * transform.scale + transform.x
    const y = view.y0 * transform.scale + transform.y
    const rw = (view.x1 - view.x0) * transform.scale
    const rh = (view.y1 - view.y0) * transform.scale
    context.globalAlpha = 0.12
    context.fillStyle = palette.label
    context.fillRect(x, y, rw, rh)
    context.globalAlpha = 1
    context.strokeStyle = palette.label
    context.lineWidth = 1
    context.strokeRect(x + 0.5, y + 0.5, Math.max(0, rw - 1), Math.max(0, rh - 1))
  }

  function centerAtPointer(event: PointerEvent) {
    const rect = canvas.getBoundingClientRect()
    props.driver?.centerAt(
      (event.clientX - rect.left - transform.x) / transform.scale,
      (event.clientY - rect.top - transform.y) / transform.scale,
    )
  }

  function onPointerDown(event: PointerEvent) {
    if (event.button !== 0 || !props.driver) return
    dragging = true
    canvas.setPointerCapture(event.pointerId)
    centerAtPointer(event)
  }

  function onPointerMove(event: PointerEvent) {
    if (dragging) centerAtPointer(event)
  }

  function onPointerEnd(event: PointerEvent) {
    dragging = false
    if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId)
  }

  function onKeyDown(event: KeyboardEvent) {
    if (event.ctrlKey || event.metaKey || event.altKey || !viewport || !props.driver) return
    const dx = event.key === "ArrowLeft" ? -1 : event.key === "ArrowRight" ? 1 : 0
    const dy = event.key === "ArrowUp" ? -1 : event.key === "ArrowDown" ? 1 : 0
    if (!dx && !dy) return
    event.preventDefault()
    // Stop the graph's own arrow handling, which jumps between nodes.
    event.stopPropagation()
    props.driver.centerAt(
      viewport.x + (dx * viewport.width * nudge) / viewport.scale,
      viewport.y + (dy * viewport.height * nudge) / viewport.scale,
    )
  }

  return (
    <>
      <canvas
        ref={canvas}
        class={`touch-none rounded-md border border-border-weak-base outline-none focus-visible:ring-2 ${props.class ?? ""}`}
        style={{ width: `${width()}px`, height: `${height()}px` }}
        tabindex="0"
        role="application"
        aria-label={language.t("security.graph.minimap.label")}
        aria-describedby="security-graph-minimap-hint"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerEnd}
        onPointerCancel={onPointerEnd}
        onKeyDown={onKeyDown}
      />
      <span id="security-graph-minimap-hint" class="sr-only">
        {language.t("security.graph.minimap.hint")}
      </span>
    </>
  )
}
