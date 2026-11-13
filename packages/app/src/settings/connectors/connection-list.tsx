import type { Connectors } from "@bellucode/schema/connectors"
import { Badge } from "@bellucode/ui/badge"
import { Button } from "@bellucode/ui/button"
import { useDialog } from "@bellucode/ui/context/dialog"
import { Dialog, DialogBody, DialogFooter, DialogTitleGroup } from "@bellucode/ui/dialog"
import { Loader } from "@bellucode/ui/loader"
import { Switch as Toggle } from "@bellucode/ui/switch"
import { TextField } from "@bellucode/ui/text-field"
import { createUniqueId, For, Show, type Component } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import type { dict } from "@/runtime/i18n/en"
import { useConnectorAuditDialog } from "./audit-dialog"
import type { ConnectorMutation, ConnectorsData } from "./data"
import { failureMessage } from "./errors"
import { clearCredentials, expiresSoon, rotationDue, validateAlias, type ConnectorCard } from "./machine"
import "./connectors.css"
type Key = Extract<keyof typeof dict, string>
const STATUS_LABELS = {
  INITIATED: "settings.connectors.connection.status.initiated",
  VERIFYING: "settings.connectors.connection.status.verifying",
  ACTIVE: "settings.connectors.connection.status.active",
  EXPIRED: "settings.connectors.connection.status.expired",
  PAUSED: "settings.connectors.connection.status.paused",
  ERROR: "settings.connectors.connection.status.error",
} as const satisfies Record<Connectors.Status, Key>
/** Where a person revokes a credential at the provider. Connectors without an entry show no link. */
const REVOCATION_URLS: Readonly<Record<string, string>> = {
  aws: "https://console.aws.amazon.com/iam/home#/security_credentials",
  github: "https://github.com/settings/personal-access-tokens",
}
const MIN_INTERVAL_MINUTES = 1
const MAX_INTERVAL_MINUTES = 24 * 60
/** Whole minutes from 1 minute to 24 hours, or `undefined` when the text is not that. */
function parseInterval(text: string) {
  if (!/^\d+$/.test(text.trim())) return
  const minutes = Number(text.trim())
  return minutes >= MIN_INTERVAL_MINUTES && minutes <= MAX_INTERVAL_MINUTES ? minutes : undefined
}
export type CredentialField = {
  readonly name: string
  readonly label: Exclude<Key, `${string}.${"zero" | "one" | "two" | "few" | "many" | "other"}`>
}
/** The write-only fields a rotation sends, by connector. The service validates them. */
export function credentialFields(connection: Connectors.Connection): readonly CredentialField[] {
  if (connection.connectorId === "aws" && connection.method !== "sso") {
    return [
      { name: "access_key_id", label: "settings.connectors.aws.accessKeyId" },
      { name: "secret_access_key", label: "settings.connectors.aws.secretAccessKey" },
    ]
  }
  if (connection.connectorId === "github") return [{ name: "token", label: "settings.connectors.github.token" }]
  return [{ name: "token", label: "settings.connectors.connection.credential" }]
}
function FailureText(props: { mutation: ConnectorMutation }) {
  const language = useLanguage()
  return (
    <Show when={props.mutation.failure()}>
      {(failure) => {
        const message = () => failureMessage(failure())
        return (
          <p role="alert" data-slot="connection-error">
            {language.t(message().key, message().params)}
          </p>
        )
      }}
    </Show>
  )
}
/** Replaces the credential of one Connection. Fields empty after every attempt, so a retry re-enters them. */
const RotateDialog: Component<{ connection: Connectors.Connection; data: ConnectorsData }> = (props) => {
  const language = useLanguage()
  const dialog = useDialog()
  const rotate = props.data.createMutation()
  const fields = credentialFields(props.connection)
  const [values, setValues] = createStore<Connectors.CredentialInput>(
    Object.fromEntries(fields.map((field) => [field.name, ""])),
  )
  const ready = () => fields.every((field) => (values[field.name] ?? "").trim() !== "")
  const submit = async (event: SubmitEvent) => {
    event.preventDefault()
    if (!ready() || rotate.busy()) return
    const credential = { ...values }
    const result = await rotate.run(
      (api, signal) => api.rotateCredential({ id: props.connection.id, credential }, { signal }),
      () => setValues(clearCredentials(values)),
    )
    if (result) dialog.close()
  }
  return (
    <Dialog>
      <DialogTitleGroup title={language.t("settings.connectors.rotate.title", { alias: props.connection.alias })} />
      <DialogBody>
        <form data-component="connection-dialog-form" onSubmit={submit}>
          <For each={fields}>
            {(field) => (
              <TextField
                label={language.t(field.label)}
                type="password"
                autocomplete="off"
                spellcheck={false}
                required
                disabled={rotate.busy()}
                value={values[field.name] ?? ""}
                onChange={(value) => {
                  setValues({ [field.name]: value })
                  rotate.dismiss()
                }}
              />
            )}
          </For>
          <p data-slot="connection-note">{language.t("settings.connectors.dialog.credential.cleared")}</p>
          <Show when={rotate.failure()}>
            {(failure) => (
              <p role="alert" data-slot="connection-error">
                {language.t("settings.connectors.rotate.failed")}{" "}
                {language.t(failureMessage(failure()).key, failureMessage(failure()).params)}
              </p>
            )}
          </Show>
          <DialogFooter>
            <Button type="button" variant="neutral" onClick={() => dialog.close()}>
              {language.t("settings.connectors.action.cancel")}
            </Button>
            <Button type="submit" variant="submit" disabled={!ready() || rotate.busy()}>
              <Show when={rotate.busy()} fallback={language.t("settings.connectors.action.rotate")}>
                <Loader class="size-4" aria-hidden="true" />
              </Show>
            </Button>
          </DialogFooter>
        </form>
      </DialogBody>
    </Dialog>
  )
}
/** Confirms removal. Revoking at the provider is a separate step the dialog says so about. */
const DisconnectDialog: Component<{
  connection: Connectors.Connection
  service: string
  data: ConnectorsData
}> = (props) => {
  const language = useLanguage()
  const dialog = useDialog()
  const remove = props.data.createMutation()
  // The service answers ok:false when the vault could not delete the credential; the Connection stays.
  const [result, setResult] = createStore({ vaultFailed: false })
  const revocation = () => REVOCATION_URLS[props.connection.connectorId]
  const confirm = async () => {
    if (remove.busy()) return
    setResult("vaultFailed", false)
    const response = await remove.run((api, signal) => api.deleteConnection({ id: props.connection.id }, { signal }))
    if (!response) return
    if (!response.ok) return setResult("vaultFailed", true)
    dialog.close()
  }
  const retry = () => result.vaultFailed || remove.failure() !== undefined
  return (
    <Dialog>
      <DialogTitleGroup title={language.t("settings.connectors.disconnect.title", { alias: props.connection.alias })} />
      <DialogBody>
        <div data-component="connection-dialog-form">
          <p data-slot="connection-note">{language.t("settings.connectors.disconnect.description")}</p>
          <p data-slot="connection-note">{language.t("settings.connectors.disconnect.revoke")}</p>
          <Show when={revocation()}>
            {(href) => (
              <a href={href()} target="_blank" rel="noopener noreferrer">
                {language.t("settings.connectors.disconnect.revokeLink", { service: props.service })}
              </a>
            )}
          </Show>
          <Show when={result.vaultFailed}>
            <p role="alert" data-slot="connection-error">
              {language.t("settings.connectors.disconnect.failed")}
            </p>
          </Show>
          <FailureText mutation={remove} />
          <DialogFooter>
            <Button type="button" variant="neutral" onClick={() => dialog.close()}>
              {language.t("settings.connectors.action.cancel")}
            </Button>
            <Button type="button" variant="danger" disabled={remove.busy()} onClick={() => void confirm()}>
              <Show
                when={remove.busy()}
                fallback={language.t(
                  retry() ? "settings.connectors.action.retry" : "settings.connectors.action.disconnect",
                )}
              >
                <Loader class="size-4" aria-hidden="true" />
              </Show>
            </Button>
          </DialogFooter>
        </div>
      </DialogBody>
    </Dialog>
  )
}
type RowProps = {
  connection: Connectors.Connection
  card: ConnectorCard
  service: string
  data: ConnectorsData
  onReconnect: (card: ConnectorCard, connection: Connectors.Connection) => void
}
type RowState = {
  /** Alias text while renaming, otherwise undefined. */
  alias?: string
  /** Interval text in minutes while edited, otherwise undefined. */
  interval?: string
  test?: Connectors.TestResult
  syncStarted: boolean
}
const ConnectionRow: Component<RowProps> = (props) => {
  const language = useLanguage()
  const dialog = useDialog()
  const showAudit = useConnectorAuditDialog()
  const ids = { alias: createUniqueId(), interval: createUniqueId() }
  const [state, setState] = createStore<RowState>({ syncStarted: false })
  const update = props.data.createMutation()
  const test = props.data.createMutation()
  const sync = props.data.createMutation()
  const pause = props.data.createMutation()
  const live = props.data.createMutation()
  const connection = () => props.connection
  const busy = () => update.busy() || test.busy() || sync.busy() || pause.busy() || live.busy()
  const now = () => Date.now()
  const date = (value: string | null | undefined) => {
    const parsed = value ? new Date(value) : undefined
    if (!parsed || Number.isNaN(parsed.getTime())) return
    return new Intl.DateTimeFormat(language.intl(), { dateStyle: "medium", timeStyle: "short" }).format(parsed)
  }
  const lastSync = () => {
    const time = date(connection().lastSync?.endedAt)
    return time
      ? language.t("settings.connectors.card.lastSync", { time })
      : language.t("settings.connectors.card.neverSynced")
  }
  const partial = () => connection().lastSync?.partial ?? []
  const aliasError = () => {
    if (state.alias === undefined) return
    const error = validateAlias(state.alias, connection().connectorId, props.data.connections(), connection().id)
    if (!error) return
    return error === "taken"
      ? language.t("settings.connectors.connection.alias.duplicate", { service: props.service })
      : language.t("settings.connectors.connection.alias.length")
  }
  const intervalMinutes = () => (state.interval === undefined ? undefined : parseInterval(state.interval))
  const saveAlias = async (event: SubmitEvent) => {
    event.preventDefault()
    const alias = state.alias
    if (alias === undefined || aliasError() || update.busy()) return
    if (alias === connection().alias) return setState("alias", undefined)
    const result = await update.run((api, signal) => api.updateConnection({ id: connection().id, alias }, { signal }))
    if (result) setState("alias", undefined)
  }
  const saveInterval = async (event: SubmitEvent) => {
    event.preventDefault()
    const minutes = intervalMinutes()
    if (minutes === undefined || update.busy()) return
    const result = await update.run((api, signal) =>
      api.updateConnection({ id: connection().id, intervalSec: minutes * 60 }, { signal }),
    )
    if (result) setState("interval", undefined)
  }
  const runTest = async () => {
    setState("test", undefined)
    const result = await test.run((api, signal) => api.testConnection({ id: connection().id }, { signal }))
    if (result) setState("test", result)
  }
  const runSync = async () => {
    setState("syncStarted", false)
    const result = await sync.run((api, signal) => api.syncConnection({ id: connection().id }, { signal }))
    if (result) setState("syncStarted", result.started)
  }
  const togglePause = () =>
    void pause.run((api, signal) =>
      connection().status === "PAUSED"
        ? api.resumeConnection({ id: connection().id }, { signal })
        : api.pauseConnection({ id: connection().id }, { signal }),
    )
  const setLive = (allow: boolean) =>
    void live.run((api, signal) =>
      api.updateConnection({ id: connection().id, allowAgentLiveReads: allow }, { signal }),
    )
  const rotate = () => void dialog.show(() => <RotateDialog connection={connection()} data={props.data} />)
  const disconnect = () =>
    void dialog.show(() => <DisconnectDialog connection={connection()} service={props.service} data={props.data} />)
  const canPause = () => connection().status === "ACTIVE" || connection().status === "PAUSED"
  const canSync = () => connection().status === "ACTIVE"
  const idle = () => connection().status !== "INITIATED" && connection().status !== "VERIFYING"
  const reconnectable = () =>
    connection().status === "EXPIRED" || connection().status === "ERROR" || expiresSoon(connection(), now())
  return (
    <li data-component="connection-row" data-status={connection().status}>
      <div data-slot="connection-head">
        <Show
          when={state.alias !== undefined}
          fallback={
            <>
              <strong data-slot="connection-alias">{connection().alias}</strong>
              <Button
                type="button"
                size="small"
                variant="ghost"
                aria-label={language.t("settings.connectors.connection.alias.edit", { alias: connection().alias })}
                disabled={busy()}
                onClick={() => setState("alias", connection().alias)}
              >
                {language.t("settings.connectors.connection.alias")}
              </Button>
            </>
          }
        >
          <form data-slot="connection-edit" onSubmit={saveAlias}>
            <TextField
              id={ids.alias}
              label={language.t("settings.connectors.connection.alias")}
              autocomplete="off"
              spellcheck={false}
              autofocus
              validationState={aliasError() ? "invalid" : "valid"}
              disabled={update.busy()}
              value={state.alias ?? ""}
              onChange={(value) => {
                setState("alias", value)
                update.dismiss()
              }}
              description={language.t("settings.connectors.connection.alias.help")}
            />
            <Show when={aliasError()}>
              {(message) => (
                <p role="alert" data-slot="connection-error">
                  {message()}
                </p>
              )}
            </Show>
            <div data-slot="connection-actions">
              <Button type="submit" size="small" variant="submit" disabled={Boolean(aliasError()) || update.busy()}>
                {language.t("settings.connectors.action.save")}
              </Button>
              <Button
                type="button"
                size="small"
                variant="neutral"
                onClick={() => {
                  setState("alias", undefined)
                  update.dismiss()
                }}
              >
                {language.t("settings.connectors.action.cancel")}
              </Button>
            </div>
          </form>
        </Show>
        <Badge variant={connection().status === "ACTIVE" ? "accent" : "neutral"}>
          <span class="sr-only">{language.t("settings.connectors.connection.status")}: </span>
          {language.t(STATUS_LABELS[connection().status])}
        </Badge>
        <Show when={expiresSoon(connection(), now())}>
          <Badge variant="subtle">{language.t("settings.connectors.badge.expiresSoon")}</Badge>
        </Show>
      </div>
      <div data-slot="connection-details">
        <span>{language.t("settings.connectors.card.account", { account: connection().accountLabel })}</span>
        <span>
          {lastSync()}
          <Show when={(connection().lastSync?.entities ?? 0) > 0}>
            {` · ${language.plural("settings.connectors.card.entities", connection().lastSync?.entities ?? 0)}`}
          </Show>
        </span>
        <Show when={partial().length > 0}>
          <span>{language.t("settings.connectors.connection.partial", { types: partial().join(", ") })}</span>
        </Show>
        <Show when={date(connection().credentialExpiresAt)}>
          {(expires) => <span>{language.t("settings.connectors.connection.expires", { date: expires() })}</span>}
        </Show>
        <Show when={rotationDue(connection(), now())}>
          <span data-slot="connection-warning">
            {language.t("settings.connectors.card.rotationReminder", { days: connection().rotationIntervalDays })}
          </span>
        </Show>
        <Show when={connection().permissionCheck === "unverifiable" && connection().connectorId === "github"}>
          <span>{language.t("settings.connectors.github.permissionsUnverifiable")}</span>
        </Show>
        <Show when={connection().permissionCheck === "ok"}>
          <span>{language.t("settings.connectors.connection.permission.ok")}</span>
        </Show>
        <Show when={connection().permissionCheck === "excess"}>
          <span data-slot="connection-warning">{language.t("settings.connectors.connection.permission.excess")}</span>
        </Show>
        <Show when={connection().statusReason}>
          <span data-slot="connection-warning">
            {language.t("settings.connectors.connection.reason", { reason: connection().statusReason })}
          </span>
        </Show>
      </div>
      <div
        role="group"
        data-slot="connection-actions"
        aria-label={language.t("settings.connectors.connection.actions", { alias: connection().alias })}
      >
        <Button type="button" size="small" variant="neutral" disabled={busy() || !idle()} onClick={() => void runTest()}>
          <Show when={test.busy()} fallback={language.t("settings.connectors.action.test")}>
            <Loader class="size-4" aria-hidden="true" />
          </Show>
        </Button>
        <Button type="button" size="small" variant="neutral" disabled={busy() || !canSync()} onClick={() => void runSync()}>
          <Show when={sync.busy()} fallback={language.t("settings.connectors.action.sync")}>
            <Loader class="size-4" aria-hidden="true" />
          </Show>
        </Button>
        <Show when={canPause()}>
          <Button type="button" size="small" variant="neutral" disabled={busy()} onClick={togglePause}>
            <Show
              when={pause.busy()}
              fallback={language.t(
                connection().status === "PAUSED"
                  ? "settings.connectors.action.resume"
                  : "settings.connectors.action.pause",
              )}
            >
              <Loader class="size-4" aria-hidden="true" />
            </Show>
          </Button>
        </Show>
        <Show when={reconnectable()}>
          <Button
            type="button"
            size="small"
            variant="neutral"
            disabled={busy()}
            onClick={() => props.onReconnect(props.card, connection())}
          >
            {language.t("settings.connectors.action.reconnect")}
          </Button>
        </Show>
        <Show when={idle()}>
          <Button type="button" size="small" variant="neutral" disabled={busy()} onClick={rotate}>
            {language.t("settings.connectors.action.rotate")}
          </Button>
        </Show>
        <Button
          type="button"
          size="small"
          variant="neutral"
          onClick={() => showAudit({ connectionId: connection().id, alias: connection().alias })}
        >
          {language.t("settings.connectors.action.audit")}
        </Button>
        <Button type="button" size="small" variant="ghost-danger" onClick={disconnect}>
          {language.t("settings.connectors.action.disconnect")}
        </Button>
      </div>
      <Toggle
        checked={connection().allowAgentLiveReads}
        disabled={live.busy()}
        onChange={setLive}
        description={language.t("settings.connectors.connection.liveReads.description")}
      >
        {language.t("settings.connectors.connection.liveReads")}
      </Toggle>
      <form data-slot="connection-edit" onSubmit={saveInterval}>
        <TextField
          id={ids.interval}
          label={language.t("settings.connectors.connection.interval")}
          inputMode="numeric"
          autocomplete="off"
          validationState={state.interval !== undefined && intervalMinutes() === undefined ? "invalid" : "valid"}
          disabled={update.busy()}
          value={state.interval ?? String(Math.round(connection().intervalSec / 60))}
          onChange={(value) => {
            setState("interval", value)
            update.dismiss()
          }}
        />
        <Show when={state.interval !== undefined}>
          <Show when={intervalMinutes() === undefined}>
            <p role="alert" data-slot="connection-error">
              {language.t("settings.connectors.connection.interval.range")}
            </p>
          </Show>
          <div data-slot="connection-actions">
            <Button type="submit" size="small" variant="submit" disabled={intervalMinutes() === undefined || update.busy()}>
              {language.t("settings.connectors.action.save")}
            </Button>
            <Button type="button" size="small" variant="neutral" onClick={() => setState("interval", undefined)}>
              {language.t("settings.connectors.action.cancel")}
            </Button>
          </div>
        </Show>
      </form>
      <div role="status" aria-live="polite" data-slot="connection-result">
        <Show when={state.syncStarted}>
          <span>{language.t("settings.connectors.connection.sync.started")}</span>
        </Show>
        <Show when={state.test}>
          {(result) => (
            <div data-slot="connection-test">
              <strong>{language.t("settings.connectors.dialog.test.title")}</strong>
              <span>{language.t("settings.connectors.dialog.test.identity", { identity: result().accountLabel })}</span>
              <Show
                when={result().offenders.length > 0}
                fallback={
                  <Show when={result().permissionCheck === "ok"}>
                    <span>{language.t("settings.connectors.dialog.test.success")}</span>
                  </Show>
                }
              >
                <span data-slot="connection-warning">
                  {language.t("settings.connectors.dialog.test.writeActions", {
                    actions: result().offenders.join(", "),
                  })}
                </span>
              </Show>
              <Show when={result().permissionCheck === "unverifiable" && connection().connectorId === "github"}>
                <span>{language.t("settings.connectors.github.permissionsUnverifiable")}</span>
              </Show>
              <Show when={result().warnings.length > 0}>
                <span>
                  {language.t("settings.connectors.connection.test.warnings")}: {result().warnings.join("; ")}
                </span>
              </Show>
            </div>
          )}
        </Show>
      </div>
      <FailureText mutation={update} />
      <FailureText mutation={test} />
      <FailureText mutation={sync} />
      <FailureText mutation={pause} />
      <FailureText mutation={live} />
    </li>
  )
}
export type ConnectionListProps = {
  card: ConnectorCard
  data: ConnectorsData
  /** Opens the connect dialog to replace the credential of `connection`. */
  onReconnect: (card: ConnectorCard, connection: Connectors.Connection) => void
}
/** The Connections of one connector card, with their status, indicators and actions (Requirements 2, 9, 14). */
export const ConnectionList: Component<ConnectionListProps> = (props) => {
  const language = useLanguage()
  const service = () => props.card.manifest.name
  const connections = () => props.card.connections.filter((connection) => !connection.removed)
  return (
    <Show when={connections().length > 0}>
      <ul data-component="connection-list" aria-label={language.t("settings.connectors.connection.list.label", { service: service() })}>
        <For each={connections()}>
          {(connection) => (
            <ConnectionRow
              connection={connection}
              card={props.card}
              service={service()}
              data={props.data}
              onReconnect={props.onReconnect}
            />
          )}
        </For>
      </ul>
    </Show>
  )
}
