import { Button } from "@bellucode/ui/button"
import { Icon } from "@bellucode/ui/icon"
import { Checkbox } from "@bellucode/ui/checkbox"
import { Loader } from "@bellucode/ui/loader"
import { MenuScroll } from "@bellucode/ui/menu-scroll"
import { TextField } from "@bellucode/ui/text-field"
import type { Connectors } from "@bellucode/schema/connectors"
import { For, Match, Show, Switch, createEffect, createMemo, createSignal, createUniqueId, on, onCleanup, type Component, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { DevicePrompt } from "./device-prompt"
import { CLIENT_HEADERS, createConnectorsData, type ConnectorsData } from "./data"
import { failureMessage, signInFailureMessage, type FailureMessage } from "./errors"
import {
  INITIAL_GITHUB_STATE,
  selectClassicRejected,
  selectPrefixHint,
  selectRepositoriesRequired,
  selectSaveDisabled,
  transitionGithub,
  GITHUB_PAT_PREFIX,
  type GithubEvent,
  type GithubState,
} from "./github-machine"
import { clearCredentials } from "./machine"
import {
  INITIAL_WIZARD_STATE,
  selectCanGoBack,
  selectMethod,
  selectWizardStep,
  transitionWizard,
  type WizardEvent,
  type WizardMethod,
  type WizardStep,
} from "./github-wizard"
import { createSignIn } from "./signin"
import { selectSignInAvailable } from "./signin-availability"
import {
  selectAnnouncement,
  selectDisabled,
  selectError,
  selectPanel,
  selectPrompt,
  selectRetryable,
  type SignInAnnouncement,
} from "./signin-machine"

export type GithubPanelProps = {
  /** The Account_Alias the dialog shell collected. */
  alias: string
  /** The Auth_Config the dialog shell selected, if any. */
  authConfigId?: string
  /** Called once the Connection is saved. The saved Connection is passed when the panel has it. */
  onDone: (connection?: Connectors.Connection) => void
  onCancel: () => void
  /** The shell's data layer. Without it the panel creates its own. */
  data?: ConnectorsData
}

type Repositories = Extract<GithubState, { status: "repositories" }>

/** Whether the catalog's GitHub manifest has a device method with a client id (an empty id means not configured). */
export function githubSignInConfigured(manifest: Connectors.Manifest | undefined) {
  return (manifest?.auth_methods ?? []).some((method) => method.id === "device" && (method.device?.client_id ?? "") !== "")
}

/**
 * GitHub connect panel, a three step wizard: choose how to connect, authorize ("Sign in with GitHub" device
 * authorization or a personal access token), choose repositories. Both methods end in the same repository selection.
 */
export const GithubPanel: Component<GithubPanelProps> = (props) => {
  const language = useLanguage()
  const data = props.data ?? createConnectorsData()
  const connect = data.createMutation()
  const list = data.createMutation()
  const save = data.createMutation()
  const signin = createSignIn({ data, alias: () => props.alias })

  const [state, setState] = createSignal(INITIAL_GITHUB_STATE)
  const dispatch = (event: GithubEvent) => setState((previous) => transitionGithub(previous, event))
  const [fields, setFields] = createStore({ token: "", host: "" })
  const [view, setView] = createStore<{ connected: Connectors.Connection | undefined }>({ connected: undefined })
  const [wizard, setWizard] = createSignal(INITIAL_WIZARD_STATE)
  const wizardDispatch = (event: WizardEvent) => setWizard((previous) => transitionWizard(previous, event))

  // GitHub's verification page opens in a new tab. The tab is opened in the click (browsers block a later popup) and
  // pointed at GitHub once the code arrives; it is closed again when the authorization completes or is abandoned.
  let tab: Window | null = null
  // The tab is opened without an opener (GitHub gets no handle on this page), so once it shows github.com the browser
  // no longer lets this page close or navigate it. Only a tab still on about:blank (sign-in failed before the code
  // arrived) is closed; reading a cross-origin tab's location throws, which means it reached GitHub and stays open.
  const closeTab = () => {
    const current = tab
    tab = null
    if (!current || current.closed) return
    const blank = Promise.try(() => current.location.href === "about:blank")
    void blank.then((isBlank) => isBlank && current.close(), () => undefined)
  }
  const startSignIn = () => {
    closeTab()
    tab = window.open("", "_blank")
    if (tab) tab.opener = null
    signin.signIn()
  }
  createEffect(
    on(
      () => selectPanel(signin.state()),
      (panel) => {
        if (panel === "prompt") {
          const prompt = selectPrompt(signin.state())
          if (prompt && tab && !tab.closed) tab.location.href = prompt.verificationUri
          return
        }
        if (panel === "starting") return
        // Authorized, failed or cancelled: drop the handle (and close the tab if it never reached GitHub).
        closeTab()
        if (panel === "installing") window.focus()
      },
      { defer: true },
    ),
  )
  onCleanup(closeTab)

  const repositories = createMemo(() => {
    const current = state()
    return current.status === "repositories" ? current : undefined
  })
  const signinRepositories = createMemo(() => {
    const current = signin.state()
    return current.phase === "repositories" ? current.github : undefined
  })
  const failure = () => connect.failure() ?? save.failure()

  const manifest = () => data.cards().find((card) => card.manifest.id === "github")?.manifest
  const configured = () => githubSignInConfigured(manifest())
  const method = () => selectMethod(wizard(), configured() || manifest() === undefined)
  const progress = () => ({
    signInBusy: selectDisabled(signin.state()),
    patBusy: connect.busy(),
    repositories: signinRepositories() !== undefined || repositories() !== undefined,
    connected: view.connected !== undefined,
  })
  const wizardStep = createMemo(() => selectWizardStep(wizard(), progress()))
  const canGoBack = () => selectCanGoBack(wizard(), progress())
  const available = () =>
    selectSignInAvailable({
      // The connect page validates the name and only mounts this panel with a valid one.
      aliasError: undefined,
      machine: signin.state(),
      patBusy: connect.busy(),
      // Sign-in is github.com only; the host field belongs to the token form.
      host: "",
    })

  const loadRepos = async (id: string, attempt: number) => {
    const result = await list.run((api, signal) => api.listGithubRepos({ id }, { signal }))
    dispatch(result ? { type: "repos.loaded", attempt, items: result.items } : { type: "repos.failed", attempt })
  }

  const submit = async (event: SubmitEvent) => {
    event.preventDefault()
    const token = fields.token
    const host = fields.host.trim()
    if (!token || connect.busy() || selectDisabled(signin.state())) return
    dispatch({ type: "credentials.submitted", classic: !token.startsWith(GITHUB_PAT_PREFIX) })
    const connection = await connect.run(
      (api, signal) =>
        api.createConnection(
          {
            alias: props.alias,
            connectorId: "github",
            authConfigId: props.authConfigId,
            method: "pat",
            params: host ? { host } : undefined,
            credential: { token },
          },
          { signal, headers: CLIENT_HEADERS },
        ),
      () => setFields("token", clearCredentials({ token: "" }).token),
    )
    if (!connection) return
    dispatch({ type: "connection.created", connectionId: connection.id })
    void loadRepos(connection.id, 1)
  }

  const retry = () => {
    const current = repositories()
    if (!current) return
    dispatch({ type: "repos.retried" })
    void loadRepos(current.connectionId, current.attempt + 1)
  }

  const saveSelection = async () => {
    const current = repositories()
    if (!current || selectSaveDisabled(current)) return
    const connection = await save.run((api, signal) =>
      api.updateConnection({ id: current.connectionId, selection: { regions: [], repos: current.selected } }, { signal }),
    )
    if (connection) setView("connected", connection)
  }

  const saveSignIn = async () => {
    const connection = await signin.save()
    if (connection) setView("connected", connection)
  }

  const message = (value: FailureMessage) =>
    value.plural ? language.plural(value.plural.key, value.plural.count) : language.t(value.key, value.params)

  const errorText = () => {
    const current = failure()
    if (!current) return
    if (current.kind === "connector" && current.code === "validation_failed" && selectClassicRejected(state()))
      return language.t("settings.connectors.github.token.classic")
    return message(failureMessage(current))
  }

  const saveFailureText = () => {
    const current = signin.saveFailure()
    return current ? message(failureMessage(current)) : undefined
  }

  const announcements: Record<SignInAnnouncement, () => string> = {
    starting: () => language.t("settings.connectors.github.signin.starting"),
    prompt: () => language.t("settings.connectors.github.signin.announce.codeShown"),
    installing: () => language.t("settings.connectors.github.signin.checking"),
    repositories: () => language.t("settings.connectors.github.signin.announce.connected"),
    failed: () => {
      const error = selectError(signin.state())
      return error ? message(signInFailureMessage(error.code, error.retryAfterSec)) : ""
    },
  }
  const announcement = () => {
    const current = selectAnnouncement(signin.state())
    return current ? announcements[current]() : ""
  }

  const promptLabels = () => ({
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
  })

  const patForm = (
    <form class="flex flex-col gap-3" onSubmit={submit}>
      <TextField
        label={language.t("settings.connectors.github.token")}
        type="password"
        autocomplete="off"
        spellcheck={false}
        required
        disabled={connect.busy()}
        value={fields.token}
        onChange={(value) => {
          setFields("token", value)
          connect.dismiss()
        }}
        description={language.t("settings.connectors.github.token.help")}
      />
      <Show when={selectPrefixHint(fields.token)}>
        <p class="m-0 text-11-regular text-v2-text-text-muted" role="status">
          {language.t("settings.connectors.github.token.prefixHint")}
        </p>
      </Show>
      <TextField
        label={language.t("settings.connectors.github.host")}
        autocomplete="off"
        spellcheck={false}
        disabled={connect.busy()}
        value={fields.host}
        onChange={(value) => setFields("host", value)}
        description={language.t("settings.connectors.github.host.help")}
      />
      <p class="m-0 text-11-regular text-v2-text-text-muted">
        {language.t("settings.connectors.github.permissionsUnverifiable")}
      </p>
      <Show when={errorText()}>
        {(text) => (
          <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
            {text()}
          </p>
        )}
      </Show>
      <div class="flex justify-end gap-2">
        <Show when={canGoBack()}>
          <Button type="button" variant="ghost" onClick={() => wizardDispatch({ type: "back" })}>
            {language.t("settings.connectors.github.wizard.back")}
          </Button>
        </Show>
        <Button type="button" variant="ghost" onClick={props.onCancel}>
          {language.t("settings.connectors.action.cancel")}
        </Button>
        <Button
          type="submit"
          variant="submit"
          disabled={!fields.token || connect.busy() || selectDisabled(signin.state())}
        >
          <Show when={connect.busy()} fallback={language.t("settings.connectors.action.connect")}>
            <Loader class="size-4" aria-hidden="true" />
            {language.t("settings.connectors.github.connecting")}
          </Show>
        </Button>
      </div>
    </form>
  )

  const signInSection = (
    <div class="flex flex-col gap-3">
      <Switch>
        <Match when={selectPanel(signin.state()) === "starting"}>
          <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted">
            <Loader class="size-4" aria-hidden="true" />
            {language.t("settings.connectors.github.signin.starting")}
          </div>
          <div class="flex justify-end">
            <Button type="button" variant="ghost" onClick={signin.cancel}>
              {language.t("settings.connectors.github.signin.cancel")}
            </Button>
          </div>
        </Match>
        <Match when={selectPanel(signin.state()) === "prompt" ? selectPrompt(signin.state()) : undefined} keyed>
          {(prompt) => (
            <DevicePrompt
              userCode={prompt.userCode}
              verificationUri={prompt.verificationUri}
              expiresAt={prompt.expiresAt}
              labels={promptLabels()}
              notice={tab ? language.t("settings.connectors.github.signin.tabOpened") : undefined}
              onCancel={signin.cancel}
            />
          )}
        </Match>
        <Match when={selectPanel(signin.state()) === "installing"}>
          <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted">
            <Loader class="size-4" aria-hidden="true" />
            {language.t("settings.connectors.github.signin.checking")}
          </div>
        </Match>
        <Match when={selectPanel(signin.state()) === "failed"}>
          <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]">
            {announcements.failed()}
          </p>
          <Show when={selectRetryable(signin.state())}>
            <div>
              <Button type="button" variant="neutral" disabled={!available()} onClick={startSignIn}>
                {language.t("settings.connectors.github.signin.tryAgain")}
              </Button>
            </div>
          </Show>
        </Match>
        <Match when={selectPanel(signin.state()) === "signin"}>
          <Show when={data.status()?.persistent === false}>
            <p class="m-0 text-11-regular text-v2-text-text-muted" role="status">
              {language.t("settings.connectors.github.signin.memoryOnly")}
            </p>
          </Show>
          <div>
            <Button type="button" variant="submit" disabled={!available()} onClick={startSignIn}>
              {language.t("settings.connectors.github.signin.action")}
            </Button>
          </div>
        </Match>
      </Switch>
      <Show when={canGoBack()}>
        <div>
          <Button type="button" variant="ghost" onClick={() => wizardDispatch({ type: "back" })}>
            {language.t("settings.connectors.github.wizard.back")}
          </Button>
        </div>
      </Show>
    </div>
  )

  return (
    <div class="flex flex-col gap-4" data-component="connectors-github-panel">
      <div class="sr-only" role="status" aria-live="polite">
        {announcement()}
      </div>
      <WizardSteps current={wizardStep()} />
      <Switch>
        <Match when={view.connected} keyed>
          {(connection) => <ConnectedStep connection={connection} onDone={() => props.onDone(connection)} />}
        </Match>
        <Match when={wizardStep() === 1}>
          <ChooseStep
            method={method()}
            signInConfigured={configured() || manifest() === undefined}
            unavailable={!configured() && manifest() !== undefined}
            onSelect={(next) => wizardDispatch({ type: "method.selected", method: next })}
            onContinue={() => wizardDispatch({ type: "continued" })}
            onCancel={props.onCancel}
          />
        </Match>
        <Match when={wizardStep() === 2}>
          <Switch>
            <Match when={method() === "signin"}>{signInSection}</Match>
            <Match when={method() === "pat"}>{patForm}</Match>
          </Switch>
        </Match>
        <Match when={signinRepositories()} keyed>
          {(current) => (
            <RepositoryStep
              current={current}
              busy={signin.saving()}
              errorText={saveFailureText()}
              onToggle={signin.toggleRepo}
              onRetry={signin.retryRepos}
              onSave={() => void saveSignIn()}
              onCancel={() => {
                signin.cancel()
                props.onCancel()
              }}
              hint={
                <Show when={signin.installations() === 0 && current.repos.phase === "ready"}>
                  <div class="flex flex-col gap-2">
                    <p class="m-0 text-13-regular text-v2-text-text-base">
                      {language.t("settings.connectors.github.signin.noInstallation")}
                    </p>
                    <p class="m-0 text-11-regular text-v2-text-text-muted">
                      {language.t("settings.connectors.github.signin.noInstallation.approval")}
                    </p>
                    <div class="flex items-center gap-3">
                      <Show when={signin.installUrl()}>
                        {(href) => (
                          <a
                            href={href()}
                            target="_blank"
                            rel="noopener noreferrer"
                            class="text-13-medium text-v2-text-text-base underline"
                          >
                            {language.t("settings.connectors.github.signin.install")}
                          </a>
                        )}
                      </Show>
                      <Button type="button" size="small" variant="neutral" onClick={signin.retryRepos}>
                        {language.t("settings.connectors.github.signin.installations.check")}
                      </Button>
                    </div>
                  </div>
                </Show>
              }
            />
          )}
        </Match>
        <Match when={repositories()} keyed>
          {(current) => (
            <RepositoryStep
              current={current}
              busy={save.busy()}
              errorText={errorText()}
              onToggle={(fullName) => dispatch({ type: "repo.toggled", fullName })}
              onRetry={retry}
              onSave={() => void saveSelection()}
              onCancel={props.onCancel}
            />
          )}
        </Match>
      </Switch>
    </div>
  )
}

/** The repository checklist both sign-in paths end in. */
function RepositoryStep(props: {
  current: Repositories
  busy: boolean
  errorText: string | undefined
  onToggle: (fullName: string) => void
  onRetry: () => void
  onSave: () => void
  onCancel: () => void
  hint?: JSX.Element
}) {
  const language = useLanguage()
  const current = () => props.current
  return (
    <div class="flex flex-col gap-3">
      <div class="flex flex-col gap-1">
        <h4 class="m-0 text-13-medium text-v2-text-text-base">{language.t("settings.connectors.github.repositories")}</h4>
        <p class="m-0 text-11-regular text-v2-text-text-muted">
          {language.t("settings.connectors.github.repositories.help")}
        </p>
      </div>
      <Switch>
        <Match when={current().repos.phase === "loading"}>
          <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted" role="status">
            <Loader class="size-4" aria-hidden="true" />
            {language.t("settings.connectors.github.repositories.loading")}
          </div>
        </Match>
        <Match when={current().repos.phase === "failed"}>
          <div class="flex items-center gap-2">
            <p class="m-0 flex-1 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
              {language.t("settings.connectors.github.repositories.failed")}
            </p>
            <Button type="button" size="small" variant="neutral" onClick={props.onRetry}>
              {language.t("settings.connectors.action.retry")}
            </Button>
          </div>
        </Match>
        <Match
          when={(() => {
            const repos = current().repos
            return repos.phase === "ready" ? repos.items : undefined
          })()}
          keyed
        >
          {(items) => (
            <Show
              when={items.length > 0}
              fallback={
                <p class="m-0 text-13-regular text-v2-text-text-muted">
                  {language.t("settings.connectors.github.repositories.empty")}
                </p>
              }
            >
              <MenuScroll
                class="max-h-60"
                viewportClass="flex flex-col gap-1 p-1"
                role="group"
                aria-label={language.t("settings.connectors.github.repositories")}
              >
                <For each={items}>
                  {(repo) => (
                    <Checkbox
                      appearance="compact"
                      checked={current().selected.includes(repo.fullName)}
                      onChange={() => props.onToggle(repo.fullName)}
                      disabled={props.busy}
                    >
                      {repo.fullName}
                      <Show when={repo.private}>
                        {" "}
                        <span class="text-11-regular text-v2-text-text-muted">
                          {language.t("settings.connectors.github.repositories.private")}
                        </span>
                      </Show>
                    </Checkbox>
                  )}
                </For>
              </MenuScroll>
            </Show>
          )}
        </Match>
      </Switch>
      {props.hint}
      <Show when={selectRepositoriesRequired(current())}>
        <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
          {language.t("settings.connectors.github.repositories.required")}
        </p>
      </Show>
      <Show when={props.errorText}>
        {(text) => (
          <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
            {text()}
          </p>
        )}
      </Show>
      <div class="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={props.onCancel}>
          {language.t("settings.connectors.action.cancel")}
        </Button>
        <Button
          type="button"
          variant="submit"
          disabled={selectSaveDisabled(current()) || props.busy}
          onClick={props.onSave}
        >
          {language.t("settings.connectors.action.save")}
        </Button>
      </div>
    </div>
  )
}

/** Shown once the Connection is saved: who is connected, then back to the list. Shared with the AWS wizard. */
export function ConnectedStep(props: {
  connection: Connectors.Connection
  onDone: () => void
  title?: string
  account?: (account: string) => string
  note?: string
}) {
  const language = useLanguage()
  return (
    <div class="flex flex-col gap-3" data-slot="connect-page-connected" role="status">
      <div class="flex items-center gap-2">
        <Icon name="circle-check" class="size-5 text-[color:var(--v2-state-fg-success)]" aria-hidden="true" />
        <h4 class="m-0 text-14-medium text-v2-text-text-base">
          {props.title ?? language.t("settings.connectors.github.connected.title")}
        </h4>
      </div>
      <Show when={props.connection.accountLabel}>
        {(account) => (
          <p class="m-0 text-13-regular text-v2-text-text-base">
            {props.account?.(account()) ?? language.t("settings.connectors.github.connected.account", { account: account() })}
          </p>
        )}
      </Show>
      <p class="m-0 text-13-regular text-v2-text-text-muted">
        {props.note ?? language.t("settings.connectors.github.connected.repositories")}
      </p>
      <div class="flex justify-end">
        <Button type="button" variant="submit" onClick={props.onDone}>
          {language.t("settings.connectors.github.connected.done")}
        </Button>
      </div>
    </div>
  )
}
const STEPS = [
  { step: 1, key: "settings.connectors.github.wizard.step.choose" },
  { step: 2, key: "settings.connectors.github.wizard.step.authorize" },
  { step: 3, key: "settings.connectors.github.wizard.step.repositories" },
] as const

type StepKey = Parameters<ReturnType<typeof useLanguage>["t"]>[0]
/** The numbered stepper: done steps show a check, the current step is highlighted. Shared with the AWS wizard. */
export function WizardSteps(props: {
  current: WizardStep | 4
  steps?: readonly { readonly step: 1 | 2 | 3 | 4; readonly key: StepKey }[]
  label?: string
}) {
  const language = useLanguage()
  const status = (step: 1 | 2 | 3 | 4) => {
    if (props.current === "done") return "done"
    if (step < props.current) return "done"
    return step === props.current ? "active" : "todo"
  }
  return (
    <ol data-slot="github-wizard-steps" aria-label={props.label ?? language.t("settings.connectors.github.wizard.label")}>
      <For each={props.steps ?? STEPS}>
        {(item) => (
          <li data-slot="github-wizard-step" data-status={status(item.step)} aria-current={status(item.step) === "active" ? "step" : undefined}>
            <span data-slot="github-wizard-circle" aria-hidden="true">
              <Show when={status(item.step) === "done"} fallback={item.step}>
                <Icon name="check" size="small" />
              </Show>
            </span>
            <span data-slot="github-wizard-step-label">{language.t(item.key)}</span>
          </li>
        )}
      </For>
    </ol>
  )
}
/** Step 1: two radio cards. Native radios give arrow-key selection and a single tab stop. */
function ChooseStep(props: {
  method: WizardMethod
  signInConfigured: boolean
  unavailable: boolean
  onSelect: (method: WizardMethod) => void
  onContinue: () => void
  onCancel: () => void
}) {
  const language = useLanguage()
  const name = createUniqueId()
  const options = [
    {
      method: "signin",
      title: "settings.connectors.github.wizard.signin.title",
      text: "settings.connectors.github.wizard.signin.text",
    },
    {
      method: "pat",
      title: "settings.connectors.github.wizard.pat.title",
      text: "settings.connectors.github.wizard.pat.text",
    },
  ] as const
  return (
    <div class="flex flex-col gap-3">
      <fieldset data-slot="github-wizard-options">
        <legend class="sr-only">{language.t("settings.connectors.github.wizard.step.choose")}</legend>
        <For each={options}>
          {(option) => {
            const disabled = () => option.method === "signin" && !props.signInConfigured
            return (
              <label data-slot="github-wizard-option" data-disabled={disabled() ? "" : undefined}>
                <input
                  type="radio"
                  name={name}
                  value={option.method}
                  checked={props.method === option.method}
                  disabled={disabled()}
                  onChange={() => props.onSelect(option.method)}
                />
                <span data-slot="github-wizard-option-body">
                  <span data-slot="github-wizard-option-title">
                    {language.t(option.title)}
                    <Show when={option.method === "signin"}>
                      <span data-slot="github-wizard-recommended">
                        {language.t("settings.connectors.github.wizard.recommended")}
                      </span>
                    </Show>
                  </span>
                  <span data-slot="github-wizard-option-text">{language.t(option.text)}</span>
                </span>
              </label>
            )
          }}
        </For>
      </fieldset>
      <Show when={props.unavailable}>
        <p class="m-0 text-13-regular text-v2-text-text-muted" role="status">
          {language.t("settings.connectors.github.signin.unavailable")}
        </p>
      </Show>
      <div class="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={props.onCancel}>
          {language.t("settings.connectors.action.cancel")}
        </Button>
        <Button type="button" variant="submit" onClick={props.onContinue}>
          {language.t("settings.connectors.github.wizard.continue")}
        </Button>
      </div>
    </div>
  )
}
