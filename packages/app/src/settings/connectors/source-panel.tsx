import { Button } from "@bellucode/ui/button"
import { Checkbox } from "@bellucode/ui/checkbox"
import { Loader } from "@bellucode/ui/loader"
import { MenuScroll } from "@bellucode/ui/menu-scroll"
import type { Connectors } from "@bellucode/schema/connectors"
import { For, Match, Show, Switch, createEffect, createMemo, createSignal, type Component } from "solid-js"
import { createStore } from "solid-js/store"
import type { dict } from "@/runtime/i18n/en"
import { useLanguage } from "@/runtime/i18n/language"
import { CLIENT_HEADERS, createConnectorsData, type ConnectorsData } from "./data"
import { failureMessage, signInFailureMessage, type FailureMessage } from "./errors"
import { createSignIn } from "./signin"
import { selectDisabled, selectError, selectPanel, selectPrompt, selectRetryable } from "./signin-machine"
import { DevicePrompt } from "./device-prompt"
import type { SourceDescriptor } from "./wizard/descriptor"
import { initialWizardState, transitionWizard, type WizardEvent } from "./wizard/machine"
import { Wizard } from "./wizard/wizard"

type Key = Exclude<Extract<keyof typeof dict, string>, `${string}.${"zero" | "one" | "two" | "few" | "many" | "other"}`>

/** What differs between Sources on the generic panel. */
export type SourcePanelConfig = {
  descriptor: SourceDescriptor
  connectorId: string
  /** The product name shown in the sign-in text, such as "GitLab". */
  serviceName: string
  /** The `credential` record of createConnection from the paste fields. Field ids are the Go credential keys. */
  credential: (values: Readonly<Record<string, string>>) => Record<string, string>
  /** Optional `params` of createConnection, such as a self-managed host. */
  params?: (values: Readonly<Record<string, string>>) => Record<string, string> | undefined
}

export type SourcePanelProps = {
  config: SourcePanelConfig
  /** The Account_Alias the connect page collected. */
  alias: string
  authConfigId?: string
  onDone: (connection?: Connectors.Connection) => void
  onCancel: () => void
  data?: ConnectorsData
}

/** Whether the manifest has an enabled device method with a client id (an empty id means not configured). */
export function deviceSignInConfigured(manifest: Connectors.Manifest | undefined) {
  return (manifest?.auth_methods ?? []).some(
    (method) => method.id === "device" && method.enabled && (method.device?.client_id ?? "") !== "",
  )
}

type Scope = {
  connectionId: string | undefined
  /** Bumped per load so a late answer for an earlier load is ignored. */
  attempt: number
  phase: "idle" | "loading" | "ready" | "failed"
  items: readonly Connectors.ScopeOption[]
  selected: readonly string[]
}

/**
 * One connect panel for every Source on the shared Wizard: choose, then paste (create the connection) or sign in
 * (device flow), then scope (checklist of the Source's items), then the Connected screen.
 */
export const SourcePanel: Component<SourcePanelProps> = (props) => {
  const language = useLanguage()
  const t = (key: string, params?: Record<string, string>) => language.t(key as Key, params)
  const descriptor = props.config.descriptor
  const data = props.data ?? createConnectorsData()
  const connect = data.createMutation()
  const list = data.createMutation()
  const save = data.createMutation()
  const signin = createSignIn({ data, alias: () => props.alias, connectorId: props.config.connectorId })

  const [wizard, setWizard] = createSignal(initialWizardState(descriptor))
  const wizardDispatch = (event: WizardEvent) => setWizard((previous) => transitionWizard(descriptor, previous, event))
  const [values, setValues] = createStore<Record<string, string>>({})
  const [view, setView] = createStore<{ connected: Connectors.Connection | undefined }>({ connected: undefined })
  const [scope, setScope] = createStore<Scope>({
    connectionId: undefined,
    attempt: 0,
    phase: "idle",
    items: [],
    selected: [],
  })

  const method = () => descriptor.methods.find((item) => item.id === wizard().methodId)
  const message = (value: FailureMessage) =>
    value.plural ? language.plural(value.plural.key, value.plural.count) : language.t(value.key, value.params)

  const manifest = () => data.cards().find((card) => card.manifest.id === props.config.connectorId)?.manifest
  const signinMethod = descriptor.methods.find((item) => item.kind === "signin")
  const signInUnavailable = () => signinMethod !== undefined && manifest() !== undefined && !deviceSignInConfigured(manifest())
  // Methods the manifest declares but does not enable (for example Azure's service principal) cannot be chosen.
  const manifestDisabled = (id: string) =>
    (manifest()?.auth_methods ?? []).some((item) => item.id === id && !item.enabled)
  const unavailableIds = () => {
    const ids = new Set<string>()
    if (signInUnavailable() && signinMethod) ids.add(signinMethod.id)
    for (const item of descriptor.methods) if (manifestDisabled(item.id)) ids.add(item.id)
    return ids.size > 0 ? ids : undefined
  }
  createEffect(() => {
    if (!signinMethod || !signInUnavailable() || wizard().methodId !== signinMethod.id) return
    const fallback = descriptor.methods.find((item) => item.kind === "paste" && !manifestDisabled(item.id))
    if (fallback) wizardDispatch({ type: "method.selected", methodId: fallback.id })
  })

  const loadScope = async (connectionId: string) => {
    const attempt = scope.attempt + 1
    setScope({ connectionId, attempt, phase: "loading", items: [], selected: [] })
    const result = await list.run((api, signal) => api.listScopeOptions({ id: connectionId }, { signal }))
    if (scope.attempt !== attempt) return
    if (result) setScope({ phase: "ready", items: result.items })
    else setScope("phase", "failed")
  }

  // Sign-in ends in the machine's `repositories` phase, whatever the Source; the scope list is loaded here.
  const signedInId = createMemo(() => {
    const current = signin.state()
    return current.phase === "repositories" ? current.github.connectionId : undefined
  })
  createEffect(() => {
    const id = signedInId()
    if (!id) return
    wizardDispatch({ type: "verified" })
    void loadScope(id)
  })

  const required = () => (method()?.fields ?? []).filter((field) => !field.optional)
  const pasteReady = () => required().every((field) => (values[field.id] ?? "").trim() !== "")

  const submit = async () => {
    if (!pasteReady() || connect.busy()) return
    const snapshot = { ...values }
    const connection = await connect.run(
      (api, signal) =>
        api.createConnection(
          {
            alias: props.alias,
            connectorId: props.config.connectorId,
            authConfigId: props.authConfigId,
            method: wizard().methodId,
            params: props.config.params?.(snapshot),
            credential: props.config.credential(snapshot),
          },
          { signal, headers: CLIENT_HEADERS },
        ),
      // The response arrived: no pasted secret stays in the fields.
      () => (method()?.fields ?? []).filter((field) => field.secret).forEach((field) => setValues(field.id, "")),
    )
    const failure = connect.failure()
    if (!connection) return failure && wizardDispatch({ type: "failed", reason: message(failureMessage(failure)) })
    wizardDispatch({ type: "verified" })
    void loadScope(connection.id)
  }

  const saveScope = async () => {
    const id = scope.connectionId
    if (!id || scope.selected.length === 0 || save.busy()) return
    const items = [...scope.selected]
    const connection = await save.run((api, signal) =>
      api.updateConnection({ id, selection: { regions: [], repos: [], items } }, { signal }),
    )
    if (connection) return setView("connected", connection)
    const failure = save.failure()
    if (failure) wizardDispatch({ type: "failed", reason: message(failureMessage(failure)) })
  }

  const toggle = (id: string) =>
    setScope("selected", (current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]))

  const service = props.config.serviceName
  const promptLabels = () => ({
    instructions: t("settings.connectors.wizard.signin.prompt", { service }),
    code: t("settings.connectors.wizard.signin.code.label"),
    copy: t("settings.connectors.wizard.signin.code.copy"),
    copied: t("settings.connectors.wizard.signin.code.copied"),
    copyFailed: t("settings.connectors.wizard.signin.code.copyFailed"),
    open: t("settings.connectors.wizard.signin.open", { service }),
    remaining: (time: string) => t("settings.connectors.wizard.signin.remaining", { time }),
    expiresSoon: t("settings.connectors.wizard.signin.expiresSoon"),
    expired: t("settings.connectors.wizard.signin.expired"),
    waiting: t("settings.connectors.wizard.signin.waiting"),
    cancel: t("settings.connectors.wizard.signin.cancel"),
  })

  const authorize = (
    <div class="flex flex-col gap-3">
      <Switch>
        <Match when={selectPanel(signin.state()) === "starting" || selectPanel(signin.state()) === "installing"}>
          <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted">
            <Loader class="size-4" aria-hidden="true" />
            {t("settings.connectors.wizard.signin.starting")}
          </div>
        </Match>
        <Match when={selectPanel(signin.state()) === "prompt" ? selectPrompt(signin.state()) : undefined} keyed>
          {(prompt) => (
            <DevicePrompt
              userCode={prompt.userCode}
              verificationUri={prompt.verificationUri}
              expiresAt={prompt.expiresAt}
              labels={promptLabels()}
              onCancel={signin.cancel}
            />
          )}
        </Match>
        <Match when={selectPanel(signin.state()) === "failed"}>
          <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
            {(() => {
              const error = selectError(signin.state())
              return error ? message(signInFailureMessage(error.code, error.retryAfterSec)) : ""
            })()}
          </p>
          <Show when={selectRetryable(signin.state())}>
            <div>
              <Button type="button" variant="neutral" onClick={() => signin.signIn()}>
                {t("settings.connectors.wizard.signin.tryAgain")}
              </Button>
            </div>
          </Show>
        </Match>
        <Match when={selectPanel(signin.state()) === "signin"}>
          <div>
            <Button type="button" variant="submit" onClick={() => signin.signIn()}>
              {t("settings.connectors.wizard.signin.action", { service })}
            </Button>
          </div>
        </Match>
      </Switch>
    </div>
  )

  const scopeStep = (
    <div class="flex flex-col gap-3">
      <div class="flex flex-col gap-1">
        <h4 class="m-0 text-13-medium text-v2-text-text-base">
          {t(method()?.stepKeys?.scope ?? "settings.connectors.wizard.step.scope")}
        </h4>
        <p class="m-0 text-11-regular text-v2-text-text-muted">{t("settings.connectors.wizard.scope.help")}</p>
      </div>
      <Switch>
        <Match when={scope.phase === "failed"}>
          <div class="flex items-center gap-2">
            <p class="m-0 flex-1 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
              {t("settings.connectors.wizard.scope.failed")}
            </p>
            <Button
              type="button"
              size="small"
              variant="neutral"
              onClick={() => scope.connectionId && void loadScope(scope.connectionId)}
            >
              {t("settings.connectors.action.retry")}
            </Button>
          </div>
        </Match>
        <Match when={scope.phase === "ready"}>
          <Show
            when={scope.items.length > 0}
            fallback={
              <p class="m-0 text-13-regular text-v2-text-text-muted">{t("settings.connectors.wizard.scope.empty")}</p>
            }
          >
            <MenuScroll
              class="max-h-60"
              viewportClass="flex flex-col gap-1 p-1"
              role="group"
              aria-label={t(method()?.stepKeys?.scope ?? "settings.connectors.wizard.step.scope")}
            >
              <For each={scope.items}>
                {(item) => (
                  <Checkbox
                    appearance="compact"
                    checked={scope.selected.includes(item.id)}
                    onChange={() => toggle(item.id)}
                    disabled={save.busy()}
                  >
                    {item.name}
                  </Checkbox>
                )}
              </For>
            </MenuScroll>
          </Show>
        </Match>
        <Match when={true}>
          <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted" role="status">
            <Loader class="size-4" aria-hidden="true" />
            {t("settings.connectors.wizard.scope.loading")}
          </div>
        </Match>
      </Switch>
    </div>
  )

  return (
    <div data-component="connectors-source-panel" data-source={props.config.connectorId}>
      <Wizard
        descriptor={descriptor}
        state={wizard()}
        busy={connect.busy() || selectDisabled(signin.state()) || save.busy()}
        unavailableMethodIds={unavailableIds()}
        values={values}
        onValue={(id, value) => {
          setValues(id, value)
          connect.dismiss()
        }}
        onSelectMethod={(methodId) => wizardDispatch({ type: "method.selected", methodId })}
        onContinue={() => wizardDispatch({ type: "continued" })}
        onVerify={() => (wizard().step === "scope" ? void saveScope() : void submit())}
        onBack={() => wizardDispatch({ type: "back" })}
        onCancel={props.onCancel}
        authorize={authorize}
        scope={scopeStep}
        backDisabled={wizard().step === "scope"}
        cancelOnScope
        verifyDisabled={wizard().step === "scope" ? scope.phase !== "ready" || scope.selected.length === 0 : !pasteReady()}
        connection={view.connected}
        onDone={() => props.onDone(view.connected)}
      />
    </div>
  )
}
