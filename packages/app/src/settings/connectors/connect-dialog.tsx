import { Dialog as Kobalte } from "@kobalte/core/dialog"
import type { Connectors } from "@bellucode/schema/connectors"
import { Button } from "@bellucode/ui/button"
import { Dialog, DialogBody, DialogFooter, DialogTitleGroup } from "@bellucode/ui/dialog"
import { Loader } from "@bellucode/ui/loader"
import { TextField } from "@bellucode/ui/text-field"
import { createEffect, For, Match, on, Show, Switch } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { credentialFields } from "./connection-list"
import { CLIENT_HEADERS, type ConnectorsData } from "./data"
import { failureMessage } from "./errors"
import { clearCredentials } from "./machine"
import { createSignIn } from "./signin"
import { selectAnnouncement, selectError, selectPanel, selectPrompt, selectRetryable } from "./signin-machine"
import { DevicePrompt } from "./device-prompt"
import { signInFailureMessage } from "./errors"
import type { ConnectTarget } from "./connectors-page"
import { ConnectPage } from "./connect-page"
import "./connectors.css"

/**
 * Connect and Reconnect dialog, mounted by the page while a target is open. The page controls visibility, so this
 * supplies the dialog root the shared `Dialog` content needs, with an overlay, and closes through `props.close`.
 */
export function ConnectDialog(props: { target: ConnectTarget; data: ConnectorsData; close: () => void }) {
  // A new connection is a full page, hosted by the connectors page in place of its content.
  if (!props.target.reconnect) return <ConnectPage manifest={props.target.card.manifest} data={props.data} close={props.close} />
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
  return (
    <Dialog size="large">
      <DialogTitleGroup
        title={
          props.target.reconnect
            ? language.t("settings.connectors.dialog.reconnect.title", { alias: props.target.reconnect.alias })
            : language.t("settings.connectors.dialog.connect.title", { service: props.target.card.manifest.name })
        }
        description={language.t("settings.connectors.dialog.connect.description")}
      />
      <DialogBody>
        <Show when={props.target.reconnect}>
          {(connection) => <ReconnectForm connection={connection()} data={props.data} close={props.close} />}
        </Show>
      </DialogBody>
    </Dialog>
  )
}

/** Replaces the credential of one Connection. Fields are emptied after success and after failure. */
function ReconnectForm(props: { connection: Connectors.Connection; data: ConnectorsData; close: () => void }) {
  return (
    <Show
      when={props.connection.connectorId === "github" && props.connection.method === "device"}
      fallback={<TokenReconnectForm {...props} />}
    >
      <GithubReconnect {...props} />
    </Show>
  )
}

/** Signs in again with GitHub to replace the sign-in of a device Connection. */
function GithubReconnect(props: { connection: Connectors.Connection; data: ConnectorsData; close: () => void }) {
  const language = useLanguage()
  const signin = createSignIn({ data: props.data, alias: () => props.connection.alias })
  // A cancel also returns the machine to idle; only a finished sign-in closes the dialog.
  const [view, setView] = createStore({ cancelled: false })
  createEffect(
    on(
      () => selectPanel(signin.state()),
      (panel, previous) => {
        if (previous === "prompt" && panel === "signin" && !view.cancelled) props.close()
      },
    ),
  )
  const cancel = () => {
    setView("cancelled", true)
    signin.cancel()
  }
  const start = () => {
    setView("cancelled", false)
    signin.signIn(props.connection.id)
  }
  const error = () => {
    const current = selectError(signin.state())
    if (!current) return
    const message = signInFailureMessage(current.code, current.retryAfterSec)
    return message.plural ? language.plural(message.plural.key, message.plural.count) : language.t(message.key)
  }
  const announcement = () => (selectAnnouncement(signin.state()) === "prompt" ? language.t("settings.connectors.github.signin.announce.codeShown") : "")
  return (
    <div data-component="connection-dialog-form">
      <TextField label={language.t("settings.connectors.connection.alias")} value={props.connection.alias} readOnly />
      <p data-slot="connection-note">{language.t("settings.connectors.github.signin.expiredConnection")}</p>
      <div class="sr-only" role="status" aria-live="polite">
        {announcement()}
      </div>
      <Show when={props.data.offline()}>
        <p role="alert" data-slot="connection-error">
          {language.t("settings.connectors.offline.description")}
        </p>
      </Show>
      <Show when={error()}>
        {(message) => (
          <p role="alert" data-slot="connection-error">
            {language.t("settings.connectors.github.reconnect.failed")} {message()}
          </p>
        )}
      </Show>
      <Switch>
        <Match when={selectPanel(signin.state()) === "starting"}>
          <div class="flex items-center gap-2">
            <Loader class="size-4" aria-hidden="true" />
            {language.t("settings.connectors.github.signin.starting")}
          </div>
        </Match>
        <Match when={selectPrompt(signin.state())} keyed>
          {(prompt) => (
            <DevicePrompt
              userCode={prompt.userCode}
              verificationUri={prompt.verificationUri}
              expiresAt={prompt.expiresAt}
              labels={{
                instructions: language.t("settings.connectors.github.signin.prompt"),
                code: language.t("settings.connectors.github.signin.code.label"),
                copy: language.t("settings.connectors.github.signin.code.copy"),
                copied: language.t("settings.connectors.github.signin.code.copied"),
                copyFailed: language.t("settings.connectors.github.signin.code.copyFailed"),
                open: language.t("settings.connectors.github.signin.open"),
                remaining: (time: string) => language.t("settings.connectors.github.signin.remaining", { time }),
                expiresSoon: language.t("settings.connectors.github.signin.expiresSoon"),
                expired: language.t("settings.connectors.github.signin.expired"),
                waiting: language.t("settings.connectors.github.device.waiting"),
                cancel: language.t("settings.connectors.github.signin.cancel"),
              }}
              onCancel={cancel}
            />
          )}
        </Match>
      </Switch>
      <DialogFooter>
        <Button type="button" variant="neutral" onClick={props.close}>
          {language.t("settings.connectors.action.cancel")}
        </Button>
        <Show when={selectPanel(signin.state()) === "signin" || selectRetryable(signin.state())}>
          <Button type="button" variant="submit" disabled={props.data.offline()} onClick={start}>
            {language.t("settings.connectors.github.signin.action")}
          </Button>
        </Show>
      </DialogFooter>
    </div>
  )
}

function TokenReconnectForm(props: { connection: Connectors.Connection; data: ConnectorsData; close: () => void }) {
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
      (api, signal) => api.reconnectConnection({ id: props.connection.id, credential }, { signal, headers: CLIENT_HEADERS }),
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
