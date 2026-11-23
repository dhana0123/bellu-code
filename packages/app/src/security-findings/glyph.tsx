import type { JSX } from "solid-js"

// Thin-stroke 16px icons for the shapes the shared icon set does not have.
const PATHS = {
  bug: "M5.5 4.5a2.5 2.5 0 0 1 5 0M4.5 7.5a3.5 3.5 0 0 1 7 0V10a3.5 3.5 0 0 1-7 0zM8 7v7M2 5.5l2.5 1.5M14 5.5 11.5 7M2 10.5l2.5-.8M14 10.5l-2.5-.8",
  package: "M8 1.5l5.5 3v7L8 14.5l-5.5-3v-7zM2.5 4.5 8 7.5l5.5-3M8 7.5v7",
  history: "M2.5 8a5.5 5.5 0 1 0 1.8-4.1M2.5 2.5v3h3M8 5v3l2 1.5",
  book: "M3 2.5h7a2 2 0 0 1 2 2v9H5a2 2 0 0 1-2-2zM3 11.5a2 2 0 0 1 2-2h7",
  play: "M5.5 3.5l7 4.5-7 4.5z",
  container: "M2 5.5h12v7H2zM2 3.5h12v2M5 5.5v7M8 5.5v7M11 5.5v7",
  serverless: "M9 1.5 3.5 9H8l-1 5.5L12.5 7H8z",
  "virtual-machine": "M2 3h12v7H2zM5.5 13h5M8 10v3",
  repository:
    "M4.5 2.5v11M4.5 10.5a3 3 0 0 0 3-3h1a3 3 0 0 0 3-3M4.5 2.5a1.25 1.25 0 1 0 .01 0M11.5 4.5a1.25 1.25 0 1 0 .01 0M4.5 13.5a1.25 1.25 0 1 0 .01 0",
  cloud: "M4.5 12.5a3 3 0 0 1-.3-6 4 4 0 0 1 7.6 1 2.5 2.5 0 0 1 .2 5z",
  workspace: "M2.5 2.5h4v4h-4zM9.5 2.5h4v4h-4zM2.5 9.5h4v4h-4zM9.5 9.5h4v4h-4z",
  check: "M3 8.5l3.2 3L13 4.5",
  kebab: "M8 3.5v.01M8 8v.01M8 12.5v.01",
  gear: "M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM8 1.5v1.8M8 12.7v1.8M1.5 8h1.8M12.7 8h1.8M3.4 3.4l1.3 1.3M11.3 11.3l1.3 1.3M3.4 12.6l1.3-1.3M11.3 4.7l1.3-1.3",
  search: "M7 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM11 11l3 3",
  close: "M4 4l8 8M12 4l-8 8",
  plus: "M8 3v10M3 8h10",
  chevron: "M4 6l4 4 4-4",
  bell: "M4 11V7.5a4 4 0 0 1 8 0V11l1.5 1.5h-11zM6.5 14h3",
  help: "M8 14.5a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13zM6.2 6.2a1.9 1.9 0 1 1 2.6 1.7c-.5.3-.8.7-.8 1.3M8 11.5v.01",
  info: "M8 14.5a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13zM8 7.5v3.5M8 5v.01",
  refresh: "M13.5 8a5.5 5.5 0 1 1-1.8-4.1M13.5 2.5v3h-3",
  sliders: "M2 4.5h7M12 4.5h2M2 11.5h2M7 11.5h7M10.5 3v3M5.5 10v3",
  external: "M9 2.5h4.5V7M13.5 2.5 7.5 8.5M6 3.5H3.5v9h9V10",
  copy: "M5.5 5.5h8v8h-8zM10.5 5.5v-3h-8v8h3",
  link: "M6.5 9.5a2.5 2.5 0 0 0 3.5 0l2.5-2.5a2.5 2.5 0 0 0-3.5-3.5L8 4.5M9.5 6.5a2.5 2.5 0 0 0-3.5 0L3.5 9a2.5 2.5 0 0 0 3.5 3.5L8 11.5",
  empty: "M3 6l2-3.5h6L13 6v6.5H3zM3 6h3.5l.5 1.5h2L9.5 6H13",
  "arrow-up": "M8 12.5v-9M4.5 7 8 3.5 11.5 7",
  "arrow-down": "M8 3.5v9M4.5 9 8 12.5 11.5 9",
} as const

export type GlyphName = keyof typeof PATHS

export function Glyph(props: { name: GlyphName; class?: string; size?: number; filled?: boolean }): JSX.Element {
  return (
    <svg
      class={props.class}
      width={props.size ?? 16}
      height={props.size ?? 16}
      viewBox="0 0 16 16"
      fill={props.filled || props.name === "play" || props.name === "serverless" ? "currentColor" : "none"}
      stroke="currentColor"
      stroke-width="1.25"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d={PATHS[props.name]} />
    </svg>
  )
}
