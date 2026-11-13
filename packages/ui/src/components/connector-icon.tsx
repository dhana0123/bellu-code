import type { Component, JSX } from "solid-js"
import { splitProps } from "solid-js"
import "./connector-icon.css"

export const connectorIconIDs = [
  "cloudflare",
  "aws",
  "github",
  "gitlab",
  "sentry",
  "mongodb",
  "railway",
  "azure",
  "google-cloud",
  "render",
  "supabase",
] as const

export type ConnectorIconID = (typeof connectorIconIDs)[number]

// Simplified square-cut marks on a 24px grid. They draw only with `currentColor` so the surrounding text color,
// theme and forced-colors mode decide the final color.
const glyphs: Record<ConnectorIconID, JSX.Element> = {
  cloudflare: <path d="M5 18V13H8V9H12V6H16V10H20V18H5Z" fill="currentColor" />,
  aws: (
    <>
      <path d="M4 5H8V12H4V5ZM10 5H14V12H10V5ZM16 5H20V12H16V5Z" fill="currentColor" />
      <path d="M4 16H17V14H21L18 19H4V16Z" fill="currentColor" />
    </>
  ),
  github: (
    <path
      d="M7 3V15M7 15V21M7 15H12C15 15 17 13 17 10V7M5 3H9V7H5V3ZM15 3H19V7H15V3ZM5 17H9V21H5V17Z"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="square"
      fill="none"
    />
  ),
  gitlab: <path d="M12 21L3 13L5 4L8 12H16L19 4L21 13L12 21Z" fill="currentColor" />,
  sentry: (
    <path
      d="M12 3L21 19H15M12 3L3 19H8M12 9L16 16M12 9L8 16"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="square"
      fill="none"
    />
  ),
  mongodb: <path d="M12 2L17 11L12 22L7 11L12 2Z" fill="currentColor" />,
  railway: <path d="M4 5H20V8H4V5ZM4 10.5H20V13.5H4V10.5ZM4 16H20V19H4V16Z" fill="currentColor" />,
  azure: <path d="M3 20L10 4H15L12 11L21 20H3Z" fill="currentColor" />,
  "google-cloud": (
    <path
      d="M6 18V14H8V10H12V7H17V11H20V18H6Z"
      stroke="currentColor"
      stroke-width="2"
      stroke-linejoin="miter"
      fill="none"
    />
  ),
  render: (
    <path
      d="M5 5H19V19H11V13H15V9H5V5Z"
      stroke="currentColor"
      stroke-width="2"
      stroke-linejoin="miter"
      fill="none"
    />
  ),
  supabase: <path d="M13 2L4 14H11L10 22L20 9H13V2Z" fill="currentColor" />,
}

export type ConnectorIconProps = Omit<JSX.SVGElementTags["svg"], "viewBox" | "fill"> & {
  id: ConnectorIconID
}

/**
 * Monochrome service mark for a connector card. Decorative (`aria-hidden`) unless the caller supplies
 * `aria-label` or `aria-labelledby`, which makes it an `img`.
 */
export const ConnectorIcon: Component<ConnectorIconProps> = (props) => {
  const [local, rest] = splitProps(props, ["id", "class", "classList"])
  const named = () => rest["aria-label"] !== undefined || rest["aria-labelledby"] !== undefined

  return (
    <svg
      data-component="connector-icon"
      data-connector={local.id}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role={named() ? "img" : undefined}
      aria-hidden={named() ? undefined : "true"}
      {...rest}
      classList={{
        ...local.classList,
        [local.class ?? ""]: !!local.class,
      }}
    >
      {glyphs[local.id]}
    </svg>
  )
}
