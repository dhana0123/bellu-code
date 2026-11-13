import type { Connectors } from "@bellucode/schema/connectors"
import { Badge } from "@bellucode/ui/badge"
import { Button } from "@bellucode/ui/button"
import { ConnectorIcon, connectorIconIDs, type ConnectorIconID } from "@bellucode/ui/connector-icon"
import { createEffect, createUniqueId, on, Show, type Component, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import type { dict } from "@/runtime/i18n/en"
import { selectCardConnectionCount, selectConnectEnabled, type CardState, type ConnectorCard } from "./machine"
import "./connectors.css"

type Key = Extract<keyof typeof dict, string>

const STATE_LABELS = {
  available: "settings.connectors.state.available",
  "coming-soon": "settings.connectors.state.comingSoon",
  connecting: "settings.connectors.state.connecting",
  connected: "settings.connectors.state.connected",
  paused: "settings.connectors.state.paused",
  "needs-attention": "settings.connectors.state.needsAttention",
} as const satisfies Record<CardState, Key>

/** Built-in services have a translated name and a description of at most 120 characters. */
const SERVICES = {
  cloudflare: ["settings.connectors.service.cloudflare", "settings.connectors.service.cloudflare.description"],
  aws: ["settings.connectors.service.aws", "settings.connectors.service.aws.description"],
  github: ["settings.connectors.service.github", "settings.connectors.service.github.description"],
  gitlab: ["settings.connectors.service.gitlab", "settings.connectors.service.gitlab.description"],
  sentry: ["settings.connectors.service.sentry", "settings.connectors.service.sentry.description"],
  mongodb: ["settings.connectors.service.mongodb", "settings.connectors.service.mongodb.description"],
  railway: ["settings.connectors.service.railway", "settings.connectors.service.railway.description"],
  azure: ["settings.connectors.service.azure", "settings.connectors.service.azure.description"],
  "google-cloud": [
    "settings.connectors.service.googleCloud",
    "settings.connectors.service.googleCloud.description",
  ],
  render: ["settings.connectors.service.render", "settings.connectors.service.render.description"],
  supabase: ["settings.connectors.service.supabase", "settings.connectors.service.supabase.description"],
} as const satisfies Record<ConnectorIconID, readonly [Key, Key]>

function iconID(manifest: Connectors.Manifest): ConnectorIconID | undefined {
  return connectorIconIDs.find((id) => id === manifest.icon || id === manifest.id)
}

/** The Connection whose details the card shows: the first one in the card's own state, else the first. */
function featured(card: ConnectorCard): Connectors.Connection | undefined {
  const wanted: Record<CardState, readonly Connectors.Status[]> = {
    "needs-attention": ["EXPIRED", "ERROR"],
    connecting: ["INITIATED", "VERIFYING"],
    connected: ["ACTIVE"],
    paused: ["PAUSED"],
    available: [],
    "coming-soon": [],
  }
  return card.connections.find((connection) => wanted[card.state].includes(connection.status)) ?? card.connections[0]
}

export type ConnectorCardProps = {
  card: ConnectorCard
  /** True while the service does not answer; disables Connect. */
  offline: boolean
  /** Opens the connect dialog for this connector. `reconnect` names the Connection to reconnect. */
  onConnect: (card: ConnectorCard, reconnect?: Connectors.Connection) => void
  /** The connection list (12.7) renders here, below the card summary. */
  children?: JSX.Element
}

export const ConnectorCardView: Component<ConnectorCardProps> = (props) => {
  const language = useLanguage()
  const ids = { name: createUniqueId(), state: createUniqueId() }
  const known = () => SERVICES[iconID(props.card.manifest) ?? ("" as ConnectorIconID)]
  const name = () => {
    const keys = known()
    return keys ? language.t(keys[0]) : props.card.manifest.name
  }
  const description = () => {
    const keys = known()
    return keys ? language.t(keys[1]) : undefined
  }
  const stateLabel = () => language.t(STATE_LABELS[props.card.state])
  const count = () => selectCardConnectionCount(props.card)
  const connection = () => featured(props.card)
  const enabled = () => selectConnectEnabled(props.card, props.offline)
  const attention = () => props.card.state === "needs-attention"
  const lastSync = () => {
    const current = connection()
    const ended = current?.lastSync?.endedAt
    if (!current || !ended) return language.t("settings.connectors.card.neverSynced")
    const date = new Date(ended)
    if (Number.isNaN(date.getTime())) return language.t("settings.connectors.card.neverSynced")
    const time = new Intl.DateTimeFormat(language.intl(), { dateStyle: "medium", timeStyle: "short" }).format(date)
    return language.t("settings.connectors.card.lastSync", { time })
  }
  const entities = () => language.plural("settings.connectors.card.entities", connection()?.lastSync?.entities ?? 0)

  // The live region stays mounted and only its text changes, so assistive technology announces each change.
  const [live, setLive] = createStore({ text: "" })
  createEffect(
    on(
      () => props.card.state,
      (state) => setLive("text", language.t("settings.connectors.state.live", { service: name(), state: language.t(STATE_LABELS[state]) })),
      { defer: true },
    ),
  )

  const action = () => {
    if (attention()) return "settings.connectors.action.reconnect" as const
    if (count() > 0) return "settings.connectors.action.addConnection" as const
    return "settings.connectors.action.connect" as const
  }
  const click = () => {
    const current = connection()
    props.onConnect(props.card, attention() ? current : undefined)
  }

  return (
    <section
      data-component="connector-card"
      data-state={props.card.state}
      data-connector={props.card.manifest.id}
      aria-label={language.t("settings.connectors.card.label", { service: name(), state: stateLabel() })}
    >
      <header data-slot="connector-card-header">
        <Show when={iconID(props.card.manifest)}>
          {(id) => <ConnectorIcon id={id()} data-slot="connector-card-icon" aria-label={name()} />}
        </Show>
        <div data-slot="connector-card-title">
          <h3 id={ids.name} data-slot="connector-card-name">
            {name()}
          </h3>
          <Show when={description()}>
            <p data-slot="connector-card-description">{description()}</p>
          </Show>
        </div>
      </header>
      <div data-slot="connector-card-badges">
        <Badge variant="subtle">{language.t("settings.connectors.readOnly")}</Badge>
        <Badge id={ids.state} variant={props.card.state === "connected" ? "accent" : "neutral"} data-slot="connector-card-state">
          {stateLabel()}
        </Badge>
      </div>
      <Show when={count() > 0}>
        <div data-slot="connector-card-details">
          <span>{language.plural("settings.connectors.card.connections", count())}</span>
          <Show when={props.card.state === "connected" && connection()}>
            {(current) => (
              <>
                <span>{language.t("settings.connectors.card.account", { account: current().accountLabel })}</span>
                <span>
                  {lastSync()}
                  <Show when={(current().lastSync?.entities ?? 0) > 0}>{` · ${entities()}`}</Show>
                </span>
              </>
            )}
          </Show>
          <Show when={attention() && connection()}>
            {(current) => (
              <Show when={current().statusReason}>
                <span data-slot="connector-card-reason">
                  {language.t("settings.connectors.connection.reason", { reason: current().statusReason })}
                </span>
              </Show>
            )}
          </Show>
        </div>
      </Show>
      <div data-slot="connector-card-actions">
        <Button
          variant={attention() || count() === 0 ? "submit" : "neutral"}
          size="small"
          disabled={!enabled()}
          aria-describedby={ids.name}
          onClick={click}
        >
          {language.t(action())}
        </Button>
      </div>
      {props.children}
      <span data-slot="connector-card-live" role="status" aria-live="polite" aria-atomic="true">
        {live.text}
      </span>
    </section>
  )
}
