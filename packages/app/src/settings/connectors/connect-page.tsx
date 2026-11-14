import type { Connectors } from "@bellucode/schema/connectors"
import { Badge } from "@bellucode/ui/badge"
import { Button } from "@bellucode/ui/button"
import { ConnectorIcon } from "@bellucode/ui/connector-icon"
import { TextField } from "@bellucode/ui/text-field"
import { createResource, createSignal, createUniqueId, For, Match, onMount, Show, Switch, untrack, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { AwsPanel } from "./aws-panel"
import { iconID, serviceKeys } from "./connector-card"
import type { ConnectorsData } from "./data"
import { GithubPanel } from "./github-panel"
import { defaultAlias, validateAlias } from "./machine"
import "./connectors.css"

type PanelContext = {
  alias: string
  authConfigId: string | undefined
  data: ConnectorsData
  done: () => void
  close: () => void
}

/** The connect panel of each connector that has one, by connector id. */
const PANELS: Readonly<Record<string, (context: PanelContext) => JSX.Element>> = {
  aws: (context) => (
    <AwsPanel
      alias={context.alias}
      authConfigId={context.authConfigId}
      disabled={context.data.offline()}
      onDone={context.done}
      onCancel={context.close}
    />
  ),
  github: (context) => (
    <GithubPanel
      alias={context.alias}
      authConfigId={context.authConfigId}
      data={context.data}
      onDone={context.done}
      onCancel={context.close}
    />
  ),
}

/**
 * Full-page connect view for a new Connection. The connectors page shows it in place of the connector list;
 * `close` returns to the list. Only the enabled authentication methods of the manifest are shown, whatever the
 * catalog the service serves.
 */
export function ConnectPage(props: { manifest: Connectors.Manifest; data: ConnectorsData; close: () => void }) {
  const language = useLanguage()
  const sdk = useServerSDK()
  const id = createUniqueId()
  const [form, setForm] = createStore({ alias: "", authConfigId: "" })
  const [configs] = createResource(
    () => props.manifest.id,
    async (cid) => (await sdk.api.experimental.connectors.listAuthConfigs({ cid })).items,
  )
  // A failed list leaves only the default; the choice is optional.
  const options = () => (configs.state === "ready" || configs.state === "refreshing" ? (configs.latest ?? []) : [])
  const methods = () => props.manifest.auth_methods.filter((method) => method.enabled)
  // The wizard panels show their own steps, so the list of methods is redundant.
  const hasWizard = () => props.manifest.id === "github" || props.manifest.id === "aws"
  const keys = () => serviceKeys(props.manifest)
  const name = () => {
    const known = keys()
    return known ? language.t(known[0]) : props.manifest.name
  }
  // Only Connections that existed when the page opened count against the name. The Connection this page creates
  // (sign-in stores it before the repository step) must not turn its own name into "taken": that would unmount the
  // panel mid-flow, which cancels the sign-in and deletes the new Connection.
  // Ids, not timestamps: the browser clock and the server clock need not agree.
  const known = new Set(untrack(() => props.data.connections().map((connection) => connection.id)))
  const earlier = () => props.data.connections().filter((connection) => known.has(connection.id))
  // The name is optional: an empty field uses the next free default ("github", "github-2", ...).
  const fallbackAlias = () => defaultAlias(props.manifest.id, earlier())
  const alias = () => form.alias.trim() || fallbackAlias()
  const aliasError = () =>
    validateAlias(alias(), props.manifest.id, earlier()) as ReturnType<typeof validateAlias> | undefined
  const aliasMessage = () => {
    const error = aliasError()
    if (!error) return
    if (error === "taken")
      return language.t("settings.connectors.connection.alias.duplicate", { service: props.manifest.name })
    return language.t("settings.connectors.connection.alias.length")
  }
  // Once the panel is shown it stays mounted: unmounting it ends its work (a sign-in in progress is cancelled and its
  // unsaved Connection deleted). A name that became taken meanwhile is still rejected by the server.
  const [shown, setShown] = createSignal(false)
  const done = () => {
    props.data.refresh()
    props.close()
  }
  let root: HTMLDivElement | undefined
  // The host column keeps its scroll position from the list; start the page at the top.
  onMount(() => root?.scrollIntoView({ block: "start" }))

  const cancel = (
    <Button type="button" variant="neutral" onClick={props.close}>
      {language.t("settings.connectors.action.cancel")}
    </Button>
  )

  return (
    <div ref={root} data-component="connect-page">
      <div>
        <Button type="button" variant="ghost" size="small" onClick={props.close}>
          {language.t("settings.connectors.page.back")}
        </Button>
      </div>
      <header data-slot="connect-page-header">
        <Show when={iconID(props.manifest)}>
          {(icon) => <ConnectorIcon id={icon()} data-slot="connect-page-icon" aria-label={name()} />}
        </Show>
        <div data-slot="connector-card-title">
          <h1 data-slot="connect-page-title">{language.t("settings.connectors.page.title", { service: name() })}</h1>
          <p data-slot="connector-card-description">{language.t("settings.connectors.dialog.connect.description")}</p>
        </div>
      </header>


      <section data-slot="connect-page-section" aria-labelledby={hasWizard() ? undefined : `${id}-auth`}>
        <Show when={!hasWizard()}>
          <h2 id={`${id}-auth`} data-slot="connect-page-section-title">
            {language.t("settings.connectors.page.authentication")}
          </h2>
          <ul data-slot="connect-page-methods">
            <For each={methods()} fallback={<li>{language.t("settings.connectors.dialog.authMethods.none")}</li>}>
              {(method) => (
                <li data-slot="connect-page-method" data-selected={methods().length === 1 ? "" : undefined}>
                  {method.name}
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Switch>
          <Match when={!Object.hasOwn(PANELS, props.manifest.id)}>
            <p role="status" data-slot="connection-note">
              {language.t("settings.connectors.state.comingSoon")}.{" "}
              {language.t("settings.connectors.dialog.comingSoon", { service: props.manifest.name })}
            </p>
            <div data-slot="connect-page-actions">
              {cancel}
              <Button type="button" variant="submit" disabled>
                {language.t("settings.connectors.state.comingSoon")}
              </Button>
            </div>
          </Match>
          <Match when={!shown() && props.data.offline()}>
            <p role="alert" data-slot="connection-error">
              {language.t("settings.connectors.offline.description")}
            </p>
            <div data-slot="connect-page-actions">{cancel}</div>
          </Match>
          <Match when={!shown() && aliasError()}>
            <p data-slot="connection-note">{language.t("settings.connectors.dialog.aliasFirst")}</p>
            <div data-slot="connect-page-actions">{cancel}</div>
          </Match>
          <Match when={PANELS[props.manifest.id]}>
            {(panel) => (
              <div data-slot="connect-page-panel" ref={() => setShown(true)}>
                {/* Built once, untracked: reading the name here would rebuild the panel whenever the Connection list
                    changes (it does right after sign-in), which reset it to "Sign in with GitHub". Getters keep the
                    values live without that. */}
                {untrack(() =>
                  panel()({
                    get alias() {
                      return alias()
                    },
                    get authConfigId() {
                      return form.authConfigId || undefined
                    },
                    data: props.data,
                    done,
                    close: props.close,
                  }),
                )}
              </div>
            )}
          </Match>
        </Switch>
      </section>

      <details data-slot="connect-page-section" data-variant="options" open={aliasError() !== undefined}>
        <summary data-slot="connect-page-section-title">{language.t("settings.connectors.page.options")}</summary>
        <TextField
          label={language.t("settings.connectors.page.name")}
          description={language.t("settings.connectors.page.name.help", { alias: fallbackAlias() })}
          placeholder={fallbackAlias()}
          autocomplete="off"
          spellcheck={false}
          disabled={props.data.offline()}
          value={form.alias}
          validationState={aliasMessage() ? "invalid" : "valid"}
          error={aliasMessage()}
          onChange={(value) => setForm("alias", value)}
        />
        <div data-slot="connection-edit">
          <label for={`${id}-auth-config`}>{language.t("settings.connectors.dialog.authConfig")}</label>
          <select
            id={`${id}-auth-config`}
            aria-describedby={`${id}-auth-config-help`}
            disabled={props.data.offline()}
            value={form.authConfigId}
            onChange={(event) => setForm("authConfigId", event.currentTarget.value)}
          >
            <option value="">{language.t("settings.connectors.dialog.authConfig.default")}</option>
            <For each={options()}>{(config) => <option value={config.id}>{config.name}</option>}</For>
          </select>
          <p id={`${id}-auth-config-help`} data-slot="connection-note">
            {language.t("settings.connectors.dialog.authConfig.help")}
          </p>
        </div>
      </details>

      <details data-slot="connect-page-section" data-variant="permissions">
        <summary data-slot="connect-page-section-title">
          {language.t("settings.connectors.page.permissions")}{" "}
          <Badge variant="subtle">{language.t("settings.connectors.readOnly")}</Badge>
        </summary>
        <ul data-slot="connect-page-list">
          <For each={props.manifest.permissions}>
            {(permission) => (
              <li>
                {permission.name}
                <Show when={permission.description}>
                  {(description) => <span data-slot="connection-note"> {description()}</span>}
                </Show>
              </li>
            )}
          </For>
        </ul>
      </details>

      <Show when={props.manifest.egress.length > 0}>
        <details data-slot="connect-page-section" data-variant="hosts">
          <summary data-slot="connect-page-section-title">{language.t("settings.connectors.dialog.hosts")}</summary>
          <ul data-slot="connect-page-list">
            <For each={props.manifest.egress}>{(host) => <li class="font-mono">{host}</li>}</For>
          </ul>
        </details>
      </Show>
    </div>
  )
}
