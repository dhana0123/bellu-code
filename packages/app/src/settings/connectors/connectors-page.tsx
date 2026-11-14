import type { Connectors } from "@bellucode/schema/connectors"
import { Button } from "@bellucode/ui/button"
import { Loader } from "@bellucode/ui/loader"
import { createMemo, Index, Match, Show, Switch, type Component, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import type { dict } from "@/runtime/i18n/en"
import { createConnectorsData, type ConnectorsData } from "./data"
import { ScopePanel } from "./scope-panel"
import { cardText, ConnectorCardView } from "./connector-card"
import {
  CONNECTOR_FILTERS,
  INITIAL_CONNECTORS_VIEW,
  isFiltering,
  matchesFilter,
  matchesQuery,
  type ConnectorsView,
} from "./connectors-filter"
import { TextField } from "@bellucode/ui/text-field"
import { ConnectorDetail } from "./connector-detail"
import type { ConnectorCard } from "./machine"
import "@/settings/settings.css"
import "./connectors.css"

type Key = Extract<keyof typeof dict, string>

const KEY_SOURCES = {
  "os-keyring": "settings.connectors.vault.keySource.osKeyStore",
  "systemd-creds": "settings.connectors.vault.keySource.systemdCredential",
  "key-file": "settings.connectors.vault.keySource.keyFile",
  passphrase: "settings.connectors.vault.keySource.passphrase",
} as const satisfies Record<string, Key>

/** What the connect dialog (12.8) opens for. `reconnect` is set when it replaces a Connection's credential. */
export type ConnectTarget = { readonly card: ConnectorCard; readonly reconnect?: Connectors.Connection }

export type ConnectorsPageProps = {
  headerAction?: JSX.Element
  /** Renders the connection list (12.7) inside a card. */
  connectionList?: (context: {
    card: ConnectorCard
    data: ConnectorsData
    /** Opens the connect dialog; pass a Connection to reconnect it. */
    open: (card: ConnectorCard, reconnect?: Connectors.Connection) => void
  }) => JSX.Element
  /** Renders the connect dialog (12.8) while a Connect or Reconnect action is open. */
  connectDialog?: (context: { target: ConnectTarget; data: ConnectorsData; close: () => void }) => JSX.Element
}

export const SettingsConnectors: Component<ConnectorsPageProps> = (props) => {
  const language = useLanguage()
  const data = createConnectorsData()
  // `detail` is the connector id whose detail page replaces the list. It survives the connect page, so closing that
  // returns to the detail.
  const [dialog, setDialog] = createStore<{ target?: ConnectTarget; detail?: string }>({})
  const open = (card: ConnectorCard, reconnect?: Connectors.Connection) => setDialog("target", { card, reconnect })
  const connect = (card: ConnectorCard) => setDialog({ target: { card }, detail: undefined })
  const close = () => setDialog({ target: undefined })
  // Looked up by id so the page follows refreshed data. A connector with no connections left has no detail.
  const detailCard = () => {
    const card = data.cards().find((item) => item.manifest.id === dialog.detail)
    return card && card.connections.length > 0 ? card : undefined
  }

  const keySource = createMemo(() => {
    const status = data.status()
    if (!status?.enabled || status.persistent) return
    return "memory" as const
  })
  const warnings = createMemo(() => {
    const status = data.status()
    if (!status?.enabled || !status.persistent) return []
    if (status.keySource === "key-file") return ["settings.connectors.vault.warning.keyFile" as const]
    if (status.keySource === "passphrase") return ["settings.connectors.vault.warning.passphrase" as const]
    return []
  })
  const sourceName = () => {
    const name = data.status()?.keySource ?? ""
    const key = KEY_SOURCES[name as keyof typeof KEY_SOURCES]
    return key ? language.t(key) : name || language.t("settings.connectors.vault.keySource.none")
  }

  const [view, setView] = createStore<ConnectorsView>({ ...INITIAL_CONNECTORS_VIEW })
  const visible = createMemo(() =>
    data.cards().filter((card) => {
      if (!matchesFilter(card, view.filter)) return false
      const text = cardText(card.manifest, (key) => language.t(key))
      return matchesQuery(text.name, text.description, view.query)
    }),
  )
  const page = () => {
    const target = dialog.target
    return target && !target.reconnect ? target : undefined
  }

  return (
    <Show when={page()} keyed fallback={<Show when={detailCard()} fallback={list()}>{(card) => detail(card)}</Show>}>
      {(target) => props.connectDialog?.({ target, data, close })}
    </Show>
  )

  function reconnectDialog() {
    return (
      <Show when={dialog.target?.reconnect ? dialog.target : undefined}>
        {(target) => props.connectDialog?.({ target: target(), data, close })}
      </Show>
    )
  }
  function detail(card: () => ConnectorCard) {
    return (
      <>
        <ConnectorDetail
          card={card()}
          offline={data.offline()}
          onBack={() => setDialog("detail", undefined)}
          onAdd={(item) => open(item)}
        >
          {props.connectionList?.({ card: card(), data, open })}
        </ConnectorDetail>
        {reconnectDialog()}
      </>
    )
  }
  function list() {
    return (
    <>
      <div class="settings-tab-header">
        <div class="settings-tab-header-row">
          <div class="flex min-w-0 flex-col gap-1">
            <h2 class="settings-tab-title">{language.t("settings.connectors.title")}</h2>
            <span class="text-11-regular text-v2-text-text-muted">{language.t("settings.connectors.description")}</span>
          </div>
          <div class="settings-tab-header-actions">{props.headerAction}</div>
        </div>
      </div>
      <div class="settings-tab-body" data-component="connectors-page">
        <Show when={data.offline()}>
          <div data-component="connectors-banner" data-tone="critical" role="alert">
            <strong>{language.t("settings.connectors.offline.title")}</strong>
            <span>{language.t("settings.connectors.offline.description")}</span>
          </div>
        </Show>
        <Show when={data.status()?.enabled}>
          <div data-component="connectors-banner" data-tone={keySource() || warnings().length ? "warning" : "neutral"} role="status">
            <strong>{language.t("settings.connectors.vault.title")}</strong>
            <Show
              when={keySource()}
              fallback={<span>{language.t("settings.connectors.vault.keySource", { source: sourceName() })}</span>}
            >
              <span>{language.t("settings.connectors.vault.memoryOnly")}</span>
            </Show>
            <Index each={warnings()}>{(key) => <span>{language.t(key())}</span>}</Index>
          </div>
        </Show>
        <Switch>
          <Match when={data.phase() === "loading"}>
            <div data-component="connectors-state" role="status">
              <Loader />
              <span>{language.t("settings.connectors.loading")}</span>
            </div>
          </Match>
          <Match when={data.phase() === "failed"}>
            <div data-component="connectors-state" role="alert">
              <span>{language.t("settings.connectors.loadFailed")}</span>
              <Button size="small" onClick={data.retry}>
                {language.t("settings.connectors.action.retry")}
              </Button>
            </div>
          </Match>
          <Match when={data.phase() === "ready"}>
            <div data-component="connectors-toolbar" role="search" aria-label={language.t("settings.connectors.toolbar.label")}>
              <TextField
                data-slot="connectors-search"
                type="search"
                hideLabel
                label={language.t("settings.connectors.search.placeholder")}
                placeholder={language.t("settings.connectors.search.placeholder")}
                autocomplete="off"
                spellcheck={false}
                value={view.query}
                onChange={(value) => setView("query", value)}
              />
              <div data-slot="connectors-filter" role="group" aria-label={language.t("settings.connectors.filter.label")}>
                <Index each={CONNECTOR_FILTERS}>
                  {(option) => (
                    <button
                      type="button"
                      data-slot="connectors-filter-option"
                      aria-pressed={view.filter === option().id}
                      onClick={() => setView("filter", option().id)}
                    >
                      {language.t(option().key)}
                    </button>
                  )}
                </Index>
              </div>
            </div>
            <Show when={visible().length === 0}>
              <div data-component="connectors-state" role="status">
                <span>{language.t("settings.connectors.filter.empty")}</span>
                <Show when={isFiltering(view)}>
                  <Button size="small" onClick={() => setView({ ...INITIAL_CONNECTORS_VIEW })}>
                    {language.t("settings.connectors.filter.clear")}
                  </Button>
                </Show>
              </div>
            </Show>
            <ul data-component="connectors-grid" aria-label={language.t("settings.connectors.title")}>
              <Index each={visible()}>
                {(card) => (
                  <li>
                    <ConnectorCardView card={card()} offline={data.offline()} onConnect={connect}
                      onManage={(item) => setDialog("detail", item.manifest.id)}
                    />
                  </li>
                )}
              </Index>
            </ul>
          </Match>
        </Switch>
        <Show when={data.phase() === "ready"}>
          <ScopePanel data={data} />
        </Show>
        {reconnectDialog()}
      </div>
    </>
    )
  }
}
