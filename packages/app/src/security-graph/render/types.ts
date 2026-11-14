// Renderer input and output types. The renderer knows nothing about the projection engine:
// the engine's `Visible` output is adapted into a `RenderGraph`.
import type { Hull } from "../layout/hulls"
import type { EntityType, Relation, Severity } from "../model"

export type RenderTag = { label: string; severity: "risk" | "info"; count?: number }

export type RenderNode = {
  id: string
  type: EntityType
  name: string
  /** Graph coordinates. */
  x: number
  y: number
  /** Node diameter in graph units. Defaults to `sizes.node`. */
  size?: number
  severity?: Severity
  /** Collapsed child count shown in the badge. */
  count: number
  expanded: boolean
  hasChildren: boolean
  tags: RenderTag[]
  language?: string
  external?: boolean
}

export type RenderEdge = {
  id: string
  source: string
  target: string
  relation: Relation | string
  count: number
}

export type RenderPathSegment = {
  from: string
  to: string
  /** Edge id the segment follows, when it maps to a visible edge. */
  edgeId?: string
  /** The segment crosses a trust boundary: a marker is drawn on its midpoint. */
  crossing?: boolean
}

export type RenderPath = {
  id: string
  from: string
  to: string
  severity: Severity
  segments: RenderPathSegment[]
}

export type RenderGraph = {
  nodes: RenderNode[]
  edges: RenderEdge[]
  paths: RenderPath[]
  boundaries: Hull[]
}

export type LitEdge = { id: string; ts: number }

export type Highlight = {
  /** Hovered or selected node ids. They, their neighbors and incident edges stay at full opacity. */
  focus: readonly string[]
  /** Nodes an agent is working on. They get a glow. */
  agent: readonly string[]
  /** Edges an agent traversed. They fade out over `litFadeMs` after `ts`. */
  lit: readonly LitEdge[]
  /** Attack paths to draw. */
  paths: readonly string[]
  /** Clock for the lit-edge fade. Defaults to `Date.now()`. */
  now?: number
}

export const emptyHighlight: Highlight = { focus: [], agent: [], lit: [], paths: [] }

export type Viewport = {
  /** Screen pixels per graph unit. Larger means closer. */
  scale: number
  /** Graph coordinates of the viewport center. */
  x: number
  y: number
  width: number
  height: number
}

export type RendererEvent =
  | { type: "click"; id: string; badge: boolean }
  | { type: "click-stage" }
  | { type: "dblclick"; id: string }
  | { type: "hover"; id?: string }
  | { type: "drag-start"; id: string }
  | { type: "drag"; id: string; x: number; y: number }
  | { type: "drag-end"; id: string; x: number; y: number }
  | { type: "pan-start" }
  | { type: "pan-end" }
  | { type: "viewport"; viewport: Viewport }

export type CameraOptions = { duration?: number }
