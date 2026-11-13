import { Dialog as Kobalte } from "@kobalte/core/dialog"
import type { Connectors } from "@bellucode/schema/connectors"
import { Button } from "@bellucode/ui/button"
import { Dialog, DialogBody, DialogFooter, DialogTitleGroup } from "@bellucode/ui/dialog"
import { Loader } from "@bellucode/ui/loader"
import { TextField } from "@bellucode/ui/text-field"
import { createResource, createUniqueId, For, Match, Show, Switch } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { AwsPanel } from "./aws-panel"
import { credentialFields } from "./connection-list"
import type { ConnectorsData } from "./data"
import { failureMessage } from "./errors"
import { GithubPanel } from "./github-panel"
import { clearCredentials, validateAlias } from "./machine"
import type { ConnectTarget } from "./connectors-page"
import "./connectors.css"

/**
 * Connect and Reconnect dialog, mounted by the page while a target is open. The page controls visibility, so this
 * supplies the dialog root the shared `Dialog` content needs, with an overlay, and closes through `props.close`.
 */
export function ConnectDialog(props: { target: ConnectTarget; data: ConnectorsData; close: () => void }) {
  return (
    <Kobalte
      open
      modal
      onOpenChange={(open: boolean) => {
        if (!open) props.close()
      }}
    >
      <Kobalte.Portal>
        <Kobalte.Overlay data-component="dialog-overlay" />
        <ConnectDialogContent {...props} />
      </Kobalte.Portal>
    </Kobalte>
  )
}

function ConnectDialogContent(props: { target: ConnectTarget; data: ConnectorsData; close: () => void }) {
  const language = useLanguage()
  const manifest = () => props.target.card.manifest
  return (
    <Dialog size="large">
      <DialogTitleGroup
        title={
          props.target.reconnect
            ? language.t("settings.connectors.dialog.reconnect.title", { alias: props.target.reconnect.alias })
            : language.t("settings.connectors.dialog.connect.title", { service: manifest().name })
        }
        description={language.t("settings.connectors.dialog.connect.description")}
      />
      <DialogBody>
        <Show
          when={props.target.reconnect}
          fallback={<ConnectForm manifest={manifest()} data={props.data} close={props.close} />}
        >
          {(connection) => <ReconnectForm connection={connection()} data={props.data} close={props.close} />}
        </Show>
      </DialogBody>
    </Dialog>
  )
}

/** The manifest's methods, permissions and hosts, exactly as the catalog payload carries them. */
function ManifestSummary(props: { manifest: Connectors.Manifest }) {
  const language = useLanguage()
  const id = createUniqueId()
  return (
    <div data-component="connection-dialog-form">
      <p data-slot="connection-note">{language.t("settings.connectors.readOnly")}</p>
      <section aria-labelledby={`${id}-methods`}>
        <h3 id={`${id}-methods`} class="text-13-medium">
          {language.t("settings.connectors.dialog.authMethod")}
        </h3>
        <ul>
          <For
            each={props.manifest.auth_methods}
            fallback={<li>{language.t("settings.connectors.dialog.authMethods.none")}</li>}
          >
            {(method) => (
              <li>
                {method.name}
                <Show when={!method.enabled}>
                  {" "}
                  <span data-slot="connection-note">{language.t("settings.connectors.badge.laterRelease")}</span>
                </Show>
              </li>
            )}
          </For>
        </ul>
      </section>
      <section aria-labelledby={`${id}-permissions`}>
        <h3 id={`${id}-permissions`} class="text-13-medium">
          {language.t("settings.connectors.dialog.permissions")}
        </h3>
        <ul>
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
      </section>
      <section aria-labelledby={`${id}-hosts`}>
        <h3 id={`${id}-hosts`} class="text-13-medium">
          {language.t("settings.connectors.dialog.hosts")}
        </h3>
        <ul>
          <For each={props.manifest.egress}>{(host) => <li class="font-mono">{host}</li>}</For>
        </ul>
      </section>
    </div>
  )
}

function ConnectForm(props: { manifest: Connectors.Manifest; data: ConnectorsData; close: () => void }) {
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
  const aliasError = () =>
    validateAlias(form.alias, props.manifest.id, props.data.connections()) as
      | ReturnType<typeof validateAlias>
      | undefined
  const aliasMessage = () => {
    const error = aliasError()
    if (!form.alias || !error) return
    if (error === "taken")
      return language.t("settings.connectors.connection.alias.duplicate", { service: props.manifest.name })
    return language.t("settings.connectors.connection.alias.length")
  }
  const authConfigId = () => form.authConfigId || undefined
  const done = () => {
    props.data.refresh()
    props.close()
  }
  return (
    <div data-component="connection-dialog-form">
      <ManifestSummary manifest={props.manifest} />
      <TextField
        label={language.t("settings.connectors.connection.alias")}
        description={language.t("settings.connectors.connection.alias.help")}
        autocomplete="off"
        spellcheck={false}
        required
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
      <Switch>
        <Match when={props.manifest.id !== "aws" && props.manifest.id !== "github"}>
          <p role="status" data-slot="connection-note">
            {language.t("settings.connectors.state.comingSoon")}.{" "}
            {language.t("settings.connectors.dialog.comingSoon", { service: props.manifest.name })}
          </p>
          <DialogFooter>
            <Button type="button" variant="neutral" onClick={props.close}>
              {language.t("settings.connectors.action.cancel")}
            </Button>
            <Button type="button" variant="submit" disabled>
              {language.t("settings.connectors.state.comingSoon")}
            </Button>
          </DialogFooter>
        </Match>
        <Match when={props.data.offline()}>
          <p role="alert" data-slot="connection-error">
            {language.t("settings.connectors.offline.description")}
          </p>
          <DialogFooter>
            <Button type="button" variant="neutral" onClick={props.close}>
              {language.t("settings.connectors.action.cancel")}
            </Button>
          </DialogFooter>
        </Match>
        <Match when={aliasError()}>
          <p data-slot="connection-note">{language.t("settings.connectors.dialog.aliasFirst")}</p>
          <DialogFooter>
            <Button type="button" variant="neutral" onClick={props.close}>
              {language.t("settings.connectors.action.cancel")}
            </Button>
          </DialogFooter>
        </Match>
        <Match when={props.manifest.id === "aws"}>
          <AwsPanel
            alias={form.alias}
            authConfigId={authConfigId()}
            disabled={props.data.offline()}
            onDone={done}
            onCancel={props.close}
          />
        </Match>
        <Match when={props.manifest.id === "github"}>
          <GithubPanel
            alias={form.alias}
            authConfigId={authConfigId()}
            data={props.data}
            onDone={done}
            onCancel={props.close}
          />
        </Match>
      </Switch>
    </div>
  )
}

/** Replaces the credential of one Connection. Fields are emptied after success and after failure. */
function ReconnectForm(props: { connection: Connectors.Connection; data: ConnectorsData; close: () => void }) {
  const language = useLanguage()
  const reconnect = props.data.createMutation()
  const fields = credentialFields(props.connection)
  const [values, setValues] = createStore<Connectors.CredentialInput>(
    Object.fromEntries(fields.map((field) => [field.name, ""])),
  )
  const ready = () => fields.every((field) => (values[field.name] ?? "").trim() !== "")
  const submit = async (event: SubmitEvent) => {
    event.preventDefault()
    if (!ready() || reconnect.busy() || props.data.offline()) return
    const credential = { ...values }
    const result = await reconnect.run(
      (api, signal) => api.reconnectConnection({ id: props.connection.id, credential }, { signal }),
      () => setValues(clearCredentials(values)),
    )
    if (result) props.close()
  }
  return (
    <form data-component="connection-dialog-form" onSubmit={submit}>
      <TextField
        label={language.t("settings.connectors.connection.alias")}
        value={props.connection.alias}
        readOnly
      />
      <For each={fields}>
        {(field) => (
          <TextField
            label={language.t(field.label)}
            type="password"
            autocomplete="off"
            spellcheck={false}
            required
            disabled={reconnect.busy() || props.data.offline()}
            value={values[field.name] ?? ""}
            onChange={(value) => {
              setValues({ [field.name]: value })
              reconnect.dismiss()
            }}
          />
        )}
      </For>
      <p data-slot="connection-note">{language.t("settings.connectors.dialog.credential.cleared")}</p>
      <Show when={props.data.offline()}>
        <p role="alert" data-slot="connection-error">
          {language.t("settings.connectors.offline.description")}
        </p>
      </Show>
      <Show when={reconnect.failure()}>
        {(failure) => {
          const message = () => failureMessage(failure())
          return (
            <p role="alert" data-slot="connection-error">
              {language.t("settings.connectors.dialog.reconnect.failed")}{" "}
              {language.t(message().key, message().params)}
            </p>
          )
        }}
      </Show>
      <DialogFooter>
        <Button type="button" variant="neutral" onClick={props.close}>
          {language.t("settings.connectors.action.cancel")}
        </Button>
        <Button type="submit" variant="submit" disabled={!ready() || reconnect.busy() || props.data.offline()}>
          <Show when={reconnect.busy()} fallback={language.t("settings.connectors.action.reconnect")}>
            <Loader class="size-4" aria-hidden="true" />
          </Show>
        </Button>
      </DialogFooter>
    </form>
  )
}
