// One texture atlas for every node icon, severity icon, language icon and brand logo.
// It is rasterized once at startup from vector paths (no fonts, no network, no assets),
// then uploaded as a single WebGL texture. The overlay can also drawImage from the same canvas.
import { dark, nodeTypes, severities, sizes, type Palette } from "../theme"

type Mark = {
  // SVG path data in a 24x24 box.
  d: string
  // Stroke color. Defaults to the theme icon stroke.
  stroke?: string
  fill?: string
  width?: number
  // Degrees around the box center.
  rotate?: number
}

export const languageIcons = {
  "C#": "lang-csharp",
  Java: "lang-java",
  Python: "lang-python",
  TypeScript: "lang-typescript",
  Go: "lang-go",
  JavaScript: "lang-javascript",
  SQL: "lang-sql",
} as const

export const brandIcons = {
  Stripe: "brand-stripe",
  Auth0: "brand-auth0",
  OpenAI: "brand-openai",
} as const

const dot = (x: number, y: number) => `M${x} ${y}h.01`
const circle = (cx: number, cy: number, r: number) =>
  `M${cx + r} ${cy}a${r} ${r} 0 1 1 ${-2 * r} 0a${r} ${r} 0 1 1 ${2 * r} 0Z`
const cylinder = [
  "M4 6C4 4.3 7.6 3 12 3S20 4.3 20 6 16.4 9 12 9 4 7.7 4 6Z",
  "M4 6V18C4 19.7 7.6 21 12 21S20 19.7 20 18V6",
  "M4 12C4 13.7 7.6 15 12 15S20 13.7 20 12",
]
const check = "M8 12.5L11 15.5L16.5 9"
const shield = "M12 3L20 6V12C20 16.5 16.5 19.5 12 21C7.5 19.5 4 16.5 4 12V6Z"
const sShape = (dx: number) =>
  `M${18.5 + dx} 11.5C${17 + dx} 10.5 ${14.5 + dx} 11 ${14.5 + dx} 12.5C${14.5 + dx} 15 ${18.5 + dx} 14 ${18.5 + dx} 16.5C${18.5 + dx} 18 ${16 + dx} 18.5 ${14.5 + dx} 17.5`

// White line icons. The shader tints or masks them, so only alpha and white matter.
const lineIcons: Record<string, string[]> = {
  api: ["M8 7L3 12L8 17", "M16 7L21 12L16 17", "M14 5L10 19"],
  module: ["M12 3L20 7.5V16.5L12 21L4 16.5V7.5Z", "M4 7.5L12 12L20 7.5", "M12 12V21"],
  service: ["M4 5H20V11H4Z", "M4 13H20V19H4Z", dot(7.5, 8), dot(7.5, 16)],
  dependency: [
    "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1",
    "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  ],
  package: ["M3 8L12 3L21 8V16L12 21L3 16Z", "M3 8L12 13L21 8", "M12 13V21", "M7.5 5.5L16.5 10.5"],
  "data-model": cylinder,
  framework: ["M12 3L21 8L12 13L3 8Z", "M3 12L12 17L21 12", "M3 16L12 21L21 16"],
  cloud: ["M7 18H17.5A4 4 0 0 0 17.5 10A6 6 0 0 0 6 11.5A3.3 3.3 0 0 0 7 18Z"],
  identity: [circle(12, 8, 4), "M4 21C4 16.5 7.5 14 12 14S20 16.5 20 21"],
  repository: [circle(6, 18, 3), circle(18, 6, 3), "M6 3V15", "M18 9C18 14 12 14 8.5 16.5"],
  file: ["M6 3H14L19 8V21H6Z", "M14 3V8H19", "M9 13H16", "M9 17H16"],
  function: [
    "M9 4C7 4 7 6 7 8C7 10 6 12 4.5 12C6 12 7 14 7 16C7 18 7 20 9 20",
    "M15 4C17 4 17 6 17 8C17 10 18 12 19.5 12C18 12 17 14 17 16C17 18 17 20 15 20",
  ],
  bug: [
    "M8 9C8 6.8 9.8 5 12 5S16 6.8 16 9V15C16 17.2 14.2 19 12 19S8 17.2 8 15Z",
    "M12 9V19",
    "M8 11H4",
    "M8 15H4.5",
    "M16 11H20",
    "M16 15H19.5",
    "M9.5 5.5L8 3.5",
    "M14.5 5.5L16 3.5",
  ],
  shield: [shield, check],
  agent: ["M5 8H19V19H5Z", "M12 8V4", dot(12, 4), dot(9, 13), dot(15, 13), "M9 16.5H15"],
  external: ["M14 4H20V10", "M20 4L11 13", "M18 14V19H5V6H10"],
  cluster: [
    circle(12, 6, 2.5),
    circle(6, 17, 2.5),
    circle(18, 17, 2.5),
    "M11 8.3L7 14.8",
    "M13 8.3L17 14.8",
    "M8.5 17H15.5",
  ],
  "severity-critical": ["M12 3L21 12L12 21L3 12Z", "M12 8V13", dot(12, 16.5)],
  "severity-high": ["M12 3L22 20H2Z", "M12 10V14", dot(12, 17)],
  "severity-medium": ["M4 4H20V20H4Z", "M12 8V13", dot(12, 16.5)],
  "severity-low": [circle(12, 12, 9), "M12 11V16", dot(12, 8)],
  "severity-info": [circle(12, 12, 9)],
  "severity-remediated": [circle(12, 12, 9), check],
  "severity-validated": [shield, "M8.5 12L11 14.5L15.5 9.5", "M12 6V7"],
}

const solid = (fill: string, d: string): Mark => ({ d, fill })
const glyph = (stroke: string, d: string, width = 1.9): Mark => ({ d, stroke, width })
const square = "M3 3H21V21H3Z"

// Colored marks for languages and brands. These are content, not theme tokens.
const colored: Record<string, Mark[]> = {
  "lang-csharp": [
    solid("#7A4DB8", "M12 2L21 7V17L12 22L3 17V7Z"),
    glyph("#FFFFFF", "M11.5 9.2A3.8 3.8 0 1 0 11.5 14.8"),
    glyph("#FFFFFF", "M14.5 9V15", 1.4),
    glyph("#FFFFFF", "M17 9V15", 1.4),
    glyph("#FFFFFF", "M13.5 10.5H18", 1.4),
    glyph("#FFFFFF", "M13.5 13.5H18", 1.4),
  ],
  "lang-java": [
    glyph("#E76F00", "M5 10H16V16A4 4 0 0 1 12 20H9A4 4 0 0 1 5 16Z", 1.8),
    glyph("#E76F00", "M16 11H18A2.5 2.5 0 0 1 18 16H16", 1.8),
    glyph("#5382A1", "M8 3C7 5 9.5 6 8.5 8", 1.6),
    glyph("#5382A1", "M12 3C11 5 13.5 6 12.5 8", 1.6),
    glyph("#E76F00", "M5 22H17", 1.8),
  ],
  "lang-python": [
    solid(
      "#3776AB",
      "M12 3C8 3 8 4.5 8 6V8H12.5V9H6C4 9 3 10.5 3 12.5S4 16 6 16H7.5V13.5C7.5 12 8.5 11 10 11H14C15.5 11 16 10 16 8.5V6C16 4 14.5 3 12 3Z",
    ),
    {
      d: "M12 3C8 3 8 4.5 8 6V8H12.5V9H6C4 9 3 10.5 3 12.5S4 16 6 16H7.5V13.5C7.5 12 8.5 11 10 11H14C15.5 11 16 10 16 8.5V6C16 4 14.5 3 12 3Z",
      fill: "#FFD43B",
      rotate: 180,
    },
    glyph("#FFFFFF", dot(10.2, 5.4), 1.6),
    glyph("#3776AB", dot(13.8, 18.6), 1.6),
  ],
  "lang-typescript": [
    solid("#3178C6", square),
    glyph("#FFFFFF", "M6 11H12"),
    glyph("#FFFFFF", "M9 11V18"),
    glyph("#FFFFFF", sShape(0), 1.7),
  ],
  "lang-javascript": [
    solid("#F7DF1E", square),
    glyph("#1F1F1F", "M10 10V16C10 17.5 8.5 18 7 17.5"),
    glyph("#1F1F1F", sShape(0), 1.7),
  ],
  "lang-go": [
    solid("#00ADD8", square),
    glyph("#FFFFFF", "M10.8 9.8A3.6 3.6 0 1 0 11.5 12H8.5", 1.7),
    glyph("#FFFFFF", "M20 12a3 3.6 0 1 1-6 0a3 3.6 0 1 1 6 0Z", 1.6),
  ],
  "lang-sql": cylinder.map((d) => glyph("#5B8DEF", d, 1.8)),
  "brand-stripe": [
    solid("#635BFF", square),
    glyph("#FFFFFF", "M16 8.5C15 7.5 9 7 9 10.3C9 13.5 16 12 16 15.5C16 18.5 10 18 8 16.5", 2.2),
  ],
  "brand-auth0": [
    solid("#EB5424", "M12 2L21 5L19.5 15C18.8 18.5 15.5 21 12 22C8.5 21 5.2 18.5 4.5 15L3 5Z"),
    solid("#FFFFFF", "M12 7L13.6 11H17.5L14.4 13.4L15.6 17.2L12 14.9L8.4 17.2L9.6 13.4L6.5 11H10.4Z"),
  ],
  // Six-petal rosette: one ellipse rotated three times.
  "brand-openai": [0, 60, 120].map((rotate) => ({
    d: "M12 3A4.5 9 0 0 1 12 21A4.5 9 0 0 1 12 3Z",
    stroke: "#111827",
    width: 1.6,
    rotate,
  })),
}

const keyList = [
  ...new Set([
    ...Object.values(nodeTypes).map((type) => type.icon),
    ...Object.values(severities).map((severity) => severity.icon),
    ...Object.values(languageIcons),
    ...Object.values(brandIcons),
  ]),
]

export type AtlasRect = { x: number; y: number; w: number; h: number }
// Texture coordinates with v measured from the top of the canvas.
export type AtlasUV = { u0: number; v0: number; u1: number; v1: number }
export type AtlasCanvas = HTMLCanvasElement | OffscreenCanvas

export type Atlas = {
  // Undefined when the environment has neither OffscreenCanvas nor a document.
  canvas: AtlasCanvas | undefined
  cell: number
  cols: number
  rows: number
  width: number
  height: number
  keys: readonly string[]
  // Cell index used by the shader, or -1 when the key is unknown.
  index: (key: string) => number
  rect: (key: string) => AtlasRect | undefined
  uv: (key: string) => AtlasUV | undefined
}

export function createAtlas(options: { palette?: Palette; cell?: number; cols?: number } = {}): Atlas {
  const palette = options.palette ?? dark
  const cell = options.cell ?? 64
  const cols = options.cols ?? 8
  const rows = Math.ceil(keyList.length / cols)
  const width = cols * cell
  const height = rows * cell
  const indexes = new Map(keyList.map((key, index) => [key, index]))
  const canvas = createCanvas(width, height)
  const context = canvas?.getContext("2d")
  if (context && typeof Path2D !== "undefined") {
    keyList.forEach((key, index) => {
      context.save()
      context.translate((index % cols) * cell, Math.floor(index / cols) * cell)
      const inset = cell * 0.1
      context.translate(inset, inset)
      context.scale((cell - inset * 2) / 24, (cell - inset * 2) / 24)
      context.lineCap = "round"
      context.lineJoin = "round"
      const marks = colored[key] ?? (lineIcons[key] ?? []).map((d): Mark => ({ d }))
      marks.forEach((mark) => drawMark(context, mark, palette.iconStroke))
      context.restore()
    })
  }
  const rect = (key: string) => {
    const index = indexes.get(key)
    if (index === undefined) return undefined
    return { x: (index % cols) * cell, y: Math.floor(index / cols) * cell, w: cell, h: cell }
  }
  return {
    canvas,
    cell,
    cols,
    rows,
    width,
    height,
    keys: keyList,
    index: (key) => indexes.get(key) ?? -1,
    rect,
    uv: (key) => {
      const area = rect(key)
      if (!area) return undefined
      return { u0: area.x / width, v0: area.y / height, u1: (area.x + area.w) / width, v1: (area.y + area.h) / height }
    },
  }
}

function createCanvas(width: number, height: number): AtlasCanvas | undefined {
  if (typeof OffscreenCanvas !== "undefined") return new OffscreenCanvas(width, height)
  if (typeof document === "undefined") return undefined
  const canvas = document.createElement("canvas")
  canvas.width = width
  canvas.height = height
  return canvas
}

function drawMark(
  context: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D,
  mark: Mark,
  iconStroke: string,
) {
  const path = new Path2D(mark.d)
  context.save()
  if (mark.rotate) {
    context.translate(12, 12)
    context.rotate((mark.rotate * Math.PI) / 180)
    context.translate(-12, -12)
  }
  if (mark.fill) {
    context.fillStyle = mark.fill
    context.fill(path)
  }
  if (!mark.fill || mark.stroke) {
    context.strokeStyle = mark.stroke ?? iconStroke
    context.lineWidth = mark.width ?? sizes.edgeWidth * 1.75
    context.stroke(path)
  }
  context.restore()
}
