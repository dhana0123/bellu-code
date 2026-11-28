import { Badge } from "@bellucode/ui/badge"
import { Button } from "@bellucode/ui/button"
import { ConnectorIcon } from "@bellucode/ui/connector-icon"
import { onMount, Show, type Component, type JSX } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { iconID, serviceKeys, STATE_LABELS } from "./connector-card"
import type { ConnectorCard } from "./machine"
import { StatusDot } from "./status-dot"
import "./connectors.css"
/**
 * Full-page detail of one connector with connections. The connectors page shows it in place of the list, like the
 * connect page. `children` holds the connection rows.
 */
export const ConnectorDetail: Component<{
  card: ConnectorCard
  offline: boolean
  onBack: () => void
  onAdd: (card: ConnectorCard) => void
  children?: JSX.Element
}> = (props) => {
  const language = useLanguage()
  const manifest = () => props.card.manifest
  const name = () => {
    const keys = serviceKeys(manifest())
    return keys ? language.t(keys[0]) : manifest().name
  }
  const description = () => {
    const keys = serviceKeys(manifest())
    return keys ? language.t(keys[1]) : undefined
  }
  let root: HTMLDivElement | undefined
  // The host column keeps its scroll position from the list; start the page at the top.
  onMount(() => root?.scrollIntoView({ block: "start" }))
  return (
    <div ref={root} data-component="connect-page" data-variant="detail">
      <div>
        <Button type="button" variant="ghost" size="small" onClick={props.onBack}>
          {language.t("settings.connectors.page.back")}
        </Button>
      </div>
      <header data-slot="connect-page-header">
        <Show when={iconID(manifest())}>
          {(icon) => <ConnectorIcon id={icon()} data-slot="connect-page-icon" aria-label={name()} />}
        </Show>
        <div data-slot="connector-card-title">
          <h1 data-slot="connect-page-title">{name()}</h1>
          <Show when={description()}>
            <p data-slot="connector-card-description">{description()}</p>
          </Show>
          <div data-slot="connector-card-badges">
            <Badge variant="subtle">{language.t("settings.connectors.readOnly")}</Badge>
            <Show
              when={props.card.state === "connected"}
              fallback={<Badge variant="neutral">{language.t(STATE_LABELS[props.card.state])}</Badge>}
            >
              <StatusDot tone="success" label={language.t(STATE_LABELS[props.card.state])} />
            </Show>
          </div>
        </div>
      </header>
      {props.children}
      <div data-component="connector-detail-actions">
        <Button type="button" variant="neutral" size="small" disabled={props.offline} onClick={() => props.onAdd(props.card)}>
          {language.t("settings.connectors.action.addConnection")}
        </Button>
      </div>
    </div>
  )
}
