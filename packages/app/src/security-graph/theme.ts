// The one tokens file for the security graph: palettes, node type colors and
// icons, severity scale, pills, sizes and zoom thresholds.

export type ThemeMode = "dark" | "light"

export type NodeTypeKey =
  | "api"
  | "module"
  | "service"
  | "dependency"
  | "package"
  | "data-model"
  | "framework"
  | "cloud-resource"
  | "identity"
  | "repository"
  | "file"
  | "function"
  | "vulnerability"
  | "security-control"
  | "ai-agent"
  | "external-service"
  | "cluster"

export type SeverityKey = "critical" | "high" | "medium" | "low" | "info" | "remediated" | "validated"

export type SeverityShape = "diamond" | "triangle" | "square" | "circle" | "ring" | "check" | "shield"

export type ZoomLevelKey = "L1" | "L2" | "L3" | "L4"

export type Palette = {
  canvas: string
  dot: string
  dotSpacing: number
  dotRadius: number
  edge: string
  edgeLabel: string
  halo: string
  label: string
  labelMuted: string
  boundaryStroke: string
  boundaryCaption: string
  iconStroke: string
  badgeBg: string
  badgeText: string
  externalFill: string
  externalRing: string
}

export type PillStyle = { bg: string; text: string; border: string }

export const dark: Palette = {
  canvas: "#0B0F17",
  dot: "rgba(255, 255, 255, 0.07)",
  dotSpacing: 24,
  dotRadius: 1,
  edge: "rgba(160, 174, 192, 0.45)",
  edgeLabel: "rgba(203, 213, 225, 0.85)",
  halo: "#0B0F17",
  label: "#F1F5F9",
  labelMuted: "#94A3B8",
  boundaryStroke: "rgba(148, 163, 184, 0.35)",
  boundaryCaption: "#94A3B8",
  iconStroke: "#FFFFFF",
  badgeBg: "#1E293B",
  badgeText: "#F1F5F9",
  externalFill: "#FFFFFF",
  externalRing: "#9CA3AF",
}

export const light: Palette = {
  canvas: "#FFFFFF",
  dot: "#D4D8DE",
  dotSpacing: 24,
  dotRadius: 1,
  edge: "rgba(100, 116, 139, 0.55)",
  edgeLabel: "#475569",
  halo: "#FFFFFF",
  label: "#0F172A",
  labelMuted: "#64748B",
  boundaryStroke: "rgba(100, 116, 139, 0.4)",
  boundaryCaption: "#64748B",
  iconStroke: "#FFFFFF",
  badgeBg: "#E2E8F0",
  badgeText: "#0F172A",
  externalFill: "#FFFFFF",
  externalRing: "#9CA3AF",
}

export const palettes: Record<ThemeMode, Palette> = { dark, light }

export type NodeTypeToken = { color: string; icon: string }

export const nodeTypes: Record<NodeTypeKey, NodeTypeToken> = {
  api: { color: "#2F4C8F", icon: "api" },
  module: { color: "#14BFA6", icon: "module" },
  service: { color: "#14BFA6", icon: "service" },
  dependency: { color: "#8B5CF6", icon: "dependency" },
  package: { color: "#8B5CF6", icon: "package" },
  "data-model": { color: "#FBA91A", icon: "data-model" },
  framework: { color: "#5EEAD4", icon: "framework" },
  "cloud-resource": { color: "#0EA5E9", icon: "cloud" },
  identity: { color: "#EC4899", icon: "identity" },
  repository: { color: "#64748B", icon: "repository" },
  file: { color: "#6366F1", icon: "file" },
  function: { color: "#A3E635", icon: "function" },
  vulnerability: { color: "#EF4444", icon: "bug" },
  "security-control": { color: "#22C55E", icon: "shield" },
  "ai-agent": { color: "#D946EF", icon: "agent" },
  "external-service": { color: "#FFFFFF", icon: "external" },
  cluster: { color: "#475569", icon: "cluster" },
}

export type SeverityToken = { color: string; shape: SeverityShape; icon: string; rank: number }

export const severities: Record<SeverityKey, SeverityToken> = {
  critical: { color: "#DC2626", shape: "diamond", icon: "severity-critical", rank: 6 },
  high: { color: "#F97316", shape: "triangle", icon: "severity-high", rank: 5 },
  medium: { color: "#EAB308", shape: "square", icon: "severity-medium", rank: 4 },
  low: { color: "#3B82F6", shape: "circle", icon: "severity-low", rank: 3 },
  info: { color: "#94A3B8", shape: "ring", icon: "severity-info", rank: 2 },
  remediated: { color: "#22C55E", shape: "check", icon: "severity-remediated", rank: 1 },
  validated: { color: "#14B8A6", shape: "shield", icon: "severity-validated", rank: 0 },
}

export const pills: Record<ThemeMode, { risk: PillStyle; neutral: PillStyle }> = {
  dark: {
    risk: { bg: "rgba(248, 113, 113, 0.18)", text: "#FCA5A5", border: "rgba(248, 113, 113, 0.35)" },
    neutral: { bg: "rgba(148, 163, 184, 0.16)", text: "#CBD5E1", border: "rgba(148, 163, 184, 0.3)" },
  },
  light: {
    risk: { bg: "#FDE2E4", text: "#C81E1E", border: "#FBC4C8" },
    neutral: { bg: "#F1F5F9", text: "#475569", border: "#E2E8F0" },
  },
}

export const sizes = {
  node: 48,
  nodeMin: 6,
  edgeWidth: 1,
  arrowhead: 6,
  externalRingWidth: 1,
  badge: 16,
  languageIcon: 14,
  pillHeight: 16,
  pillGap: 4,
  labelFont: 12,
  mutedLabelFont: 11,
  pillFont: 10,
  edgeLabelFont: 10,
  boundaryStroke: 1,
  dimAlpha: 0.15,
} as const

// Camera ratio is not used here: these are zoom scales where larger means closer.
export const zoom = {
  levels: { L1: 0, L2: 0.6, L3: 1.4, L4: 3 } satisfies Record<ZoomLevelKey, number>,
  // Far: colored dots. Above iconThreshold: icons and badges.
  iconThreshold: 0.6,
  // Above labelThreshold: labels, pills and edge labels.
  labelThreshold: 1.4,
  pillThreshold: 1.4,
  edgeLabelThreshold: 1.8,
} as const

export type FontRole = "sans" | "mono"

const fontVariables: Record<FontRole, string> = {
  sans: "--font-family-sans",
  mono: "--font-family-mono",
}

// Reads the user-chosen family from the CSS variable. The caller reads it once and caches it.
export function readFontFamily(role: FontRole, root: Element = document.documentElement) {
  return getComputedStyle(root).getPropertyValue(fontVariables[role]).trim()
}

export function canvasFont(size: number, family: string, weight = 400) {
  return `${weight} ${size}px ${family}`
}

export function zoomLevel(scale: number): ZoomLevelKey {
  if (scale >= zoom.levels.L4) return "L4"
  if (scale >= zoom.levels.L3) return "L3"
  if (scale >= zoom.levels.L2) return "L2"
  return "L1"
}
