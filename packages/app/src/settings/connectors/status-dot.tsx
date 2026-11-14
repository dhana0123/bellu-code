import type { Component } from "solid-js"
import "./connectors.css"
export type StatusTone = "success" | "neutral" | "warning" | "critical"
/** Colored dot with the status text, the same dot tokens as the Servers list. */
export const StatusDot: Component<{ tone: StatusTone; label: string; hidden?: string }> = (props) => (
  <span data-component="connector-status" data-tone={props.tone}>
    <span data-slot="connector-status-dot" aria-hidden="true" />
    {props.hidden ? <span class="sr-only">{props.hidden}: </span> : null}
    <span data-slot="connector-status-text">{props.label}</span>
  </span>
)
