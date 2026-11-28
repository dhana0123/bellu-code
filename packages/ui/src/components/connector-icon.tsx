import type { Component, JSX } from "solid-js"
import { For, splitProps } from "solid-js"
import { connectorLogos } from "../icons/connector-logos"
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
  "bitbucket",
  "kubernetes",
  "render",
  "supabase",
] as const

export type ConnectorIconID = (typeof connectorIconIDs)[number]

export type ConnectorIconProps = Omit<JSX.SVGElementTags["svg"], "viewBox" | "fill"> & {
  id: ConnectorIconID
}

/**
 * Brand logo of a connector's service (generated from simple-icons and devicon, see script/connector-icons.ts). Logos
 * draw in their brand color; dark brand colors use `currentColor` so they follow the text color in dark mode. The mark
 * only identifies the service and stays the trademark of its owner. Decorative (`aria-hidden`) unless the caller supplies
 * `aria-label` or `aria-labelledby`, which makes it an `img`.
 */
export const ConnectorIcon: Component<ConnectorIconProps> = (props) => {
  const [local, rest] = splitProps(props, ["id", "class", "classList"])
  const named = () => rest["aria-label"] !== undefined || rest["aria-labelledby"] !== undefined

  return (
    <svg
      data-component="connector-icon"
      data-connector={local.id}
      viewBox={connectorLogos[local.id].viewBox}
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
      <For each={connectorLogos[local.id].paths}>{(item) => <path d={item.d} fill={item.fill} />}</For>
    </svg>
  )
}
