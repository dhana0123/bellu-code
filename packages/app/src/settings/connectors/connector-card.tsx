import type { Connectors } from "@bellucode/schema/connectors"
import { Badge } from "@bellucode/ui/badge"
import { Button } from "@bellucode/ui/button"
import { ConnectorIcon, connectorIconIDs, type ConnectorIconID } from "@bellucode/ui/connector-icon"
import { createEffect, createUniqueId, on, Show, type Component } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import type { dict } from "@/runtime/i18n/en"
import { selectExpiryWarning } from "./expiry-warning"
import { selectCardConnectionCount, selectConnectEnabled, type CardState, type ConnectorCard } from "./machine"
import { StatusDot } from "./status-dot"
import "./connectors.css"

type Key = Extract<keyof typeof dict, string>

export const STATE_LABELS = {
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
  bitbucket: ["settings.connectors.service.bitbucket", "settings.connectors.service.bitbucket.description"],
  kubernetes: ["settings.connectors.service.kubernetes", "settings.connectors.service.kubernetes.description"],
  render: ["settings.connectors.service.render", "settings.connectors.service.render.description"],
  supabase: ["settings.connectors.service.supabase", "settings.connectors.service.supabase.description"],
} as const satisfies Record<ConnectorIconID, readonly [Key, Key]>

/** Manifest ids or icons that name a logo differently (the Google Cloud manifest is `gcp`). */
const ICON_ALIASES: Record<string, ConnectorIconID> = { gcp: "google-cloud" }

export function iconID(manifest: Connectors.Manifest): ConnectorIconID | undefined {
  return (
    connectorIconIDs.find((id) => id === manifest.icon || id === manifest.id) ??
    ICON_ALIASES[manifest.icon ?? ""] ??
    ICON_ALIASES[manifest.id]
  )
}

/** The translated name and description keys of a built-in service. */
export function serviceKeys(manifest: Connectors.Manifest) {
  return SERVICES[iconID(manifest) ?? ("" as ConnectorIconID)]
}

/** The displayed (translated) name and description of a card, as the card renders them. */
export function cardText(manifest: Connectors.Manifest, t: ReturnType<typeof useLanguage>["t"]) {
  const keys = serviceKeys(manifest)
  return { name: keys ? t(keys[0]) : manifest.name, description: keys ? t(keys[1]) : undefined }
}

export type ConnectorCardProps = {
  card: ConnectorCard
  /** True while the service does not answer; disables Connect. */
  offline: boolean
  /** Opens the connect page for this connector. */
  onConnect: (card: ConnectorCard) => void
  /** Opens the connector detail page of a card that has connections. */
  onManage: (card: ConnectorCard) => void
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
  const enabled = () => selectConnectEnabled(props.card, props.offline)
  // The live region stays mounted and only its text changes, so assistive technology announces each change.
  const [live, setLive] = createStore({ text: "" })
  createEffect(
    on(
      () => props.card.state,
      (state) => setLive("text", language.t("settings.connectors.state.live", { service: name(), state: language.t(STATE_LABELS[state]) })),
      { defer: true },
    ),
  )

  const connected = () => count() > 0
  const summary = () => {
    const connections = props.card.connections
    const account = connections.length === 1 ? connections[0]?.accountLabel : undefined
    return account
      ? language.plural("settings.connectors.card.summary", connections.length, { account })
      : language.plural("settings.connectors.card.connections", connections.length)
  }
  const needsAttention = () =>
    props.card.connections.some(
      (connection) =>
        connection.status === "ERROR" ||
        connection.status === "EXPIRED" ||
        selectExpiryWarning(connection, Date.now()) !== undefined,
    )
  const click = () => (connected() ? props.onManage(props.card) : props.onConnect(props.card))
  return (
    <section
      data-component="connector-card"
      data-state={props.card.state}
      data-connected={connected() ? "" : undefined}
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
        <span id={ids.state} data-slot="connector-card-state">
          <Show
            when={props.card.state === "connected"}
            fallback={<Badge variant="neutral">{stateLabel()}</Badge>}
          >
            <StatusDot tone="success" label={stateLabel()} />
          </Show>
        </span>
      </div>
      <div data-slot="connector-card-summary">
        <Show when={connected()}>
          <span>{summary()}</span>
          <Show when={needsAttention()}>
            <span data-slot="connector-card-reason">{language.t("settings.connectors.state.needsAttention")}</span>
          </Show>
        </Show>
      </div>
      <div data-slot="connector-card-actions">
        <Show when={props.card.state !== "coming-soon"}>
          <Button
            variant={connected() ? "neutral" : "submit"}
            size="small"
            data-slot="connector-card-action"
            disabled={!enabled()}
            aria-describedby={ids.name}
            onClick={click}
          >
            {language.t(connected() ? "settings.connectors.action.manage" : "settings.connectors.action.connect")}
          </Button>
        </Show>
      </div>
      <span data-slot="connector-card-live" role="status" aria-live="polite" aria-atomic="true">
        {live.text}
      </span>
    </section>
  )
}
