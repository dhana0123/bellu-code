import type { Connectors } from "@bellucode/schema/connectors"
import { Button } from "@bellucode/ui/button"
import { Loader } from "@bellucode/ui/loader"
import { createMemo, Index, Match, Show, Switch, type Component, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import type { dict } from "@/runtime/i18n/en"
import { createConnectorsData, type ConnectorsData } from "./data"
import { ScopePanel } from "./scope-panel"
import { ConnectorCardView } from "./connector-card"
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
  const [dialog, setDialog] = createStore<{ target?: ConnectTarget }>({})
  const open = (card: ConnectorCard, reconnect?: Connectors.Connection) => setDialog({ target: { card, reconnect } })
  const close = () => setDialog({ target: undefined })

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
            <ul data-component="connectors-grid" aria-label={language.t("settings.connectors.title")}>
              <Index each={data.cards()}>
                {(card) => (
                  <li>
                    <ConnectorCardView card={card()} offline={data.offline()} onConnect={open}>
                      {props.connectionList?.({ card: card(), data, open })}
                    </ConnectorCardView>
                  </li>
                )}
              </Index>
            </ul>
          </Match>
        </Switch>
        <Show when={data.phase() === "ready"}>
          <ScopePanel data={data} />
        </Show>
        <Show when={dialog.target}>{(target) => props.connectDialog?.({ target: target(), data, close })}</Show>
      </div>
    </>
  )
}
