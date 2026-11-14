import { Button } from "@bellucode/ui/button"
import { Checkbox } from "@bellucode/ui/checkbox"
import { Loader } from "@bellucode/ui/loader"
import { MenuScroll } from "@bellucode/ui/menu-scroll"
import type { Connectors } from "@bellucode/schema/connectors"
import { For, Match, Show, Switch, createEffect, createMemo, createSignal, on, onCleanup, type Component, type JSX } from "solid-js"
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
import { GITHUB_DESCRIPTOR, GITHUB_PAT_METHOD, GITHUB_SIGNIN_METHOD } from "./descriptors/github"
import { Wizard } from "./wizard/wizard"
import { initialWizardState, transitionWizard, type WizardEvent } from "./wizard/machine"
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
  const [wizard, setWizard] = createSignal(initialWizardState(GITHUB_DESCRIPTOR))
  const wizardDispatch = (event: WizardEvent) => setWizard((previous) => transitionWizard(GITHUB_DESCRIPTOR, previous, event))

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
  // Without a device method with a client id the token is the only choice. An unloaded catalog does not block sign-in.
  const signInUnavailable = () => !configured() && manifest() !== undefined
  createEffect(() => {
    if (signInUnavailable() && wizard().methodId === GITHUB_SIGNIN_METHOD)
      wizardDispatch({ type: "method.selected", methodId: GITHUB_PAT_METHOD })
  })
  // Both paths end in the same repository checklist: the sign-in driver reports it through its phase.
  // A memo of the boolean, so a repository toggle (a new object) does not report `verified` again.
  const signinReached = createMemo(() => signinRepositories() !== undefined)
  createEffect(
    on(
      signinReached,
      (reached) => reached && wizardDispatch({ type: "verified" }),
      { defer: true },
    ),
  )
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

  const submit = async () => {
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
    wizardDispatch({ type: "verified" })
    void loadRepos(connection.id, 1)
  }

  const retry = () => {
    const current = repositories()
    if (!current) return
    dispatch({ type: "repos.retried" })
    void loadRepos(current.connectionId, current.attempt + 1)
  }

  const saveScope = () => (wizard().methodId === GITHUB_SIGNIN_METHOD ? saveSignIn() : saveSelection())

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
    </div>
  )

  const installHint = () => (
    <Show when={signin.installations() === 0 && signinRepositories()?.repos.phase === "ready"}>
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
  )

  const scope = (
    <Switch>
      <Match when={signinRepositories()} keyed>
        {(current) => (
          <RepositoryStep
            current={current}
            busy={signin.saving()}
            errorText={saveFailureText()}
            onToggle={signin.toggleRepo}
            onRetry={signin.retryRepos}
            hint={installHint()}
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
          />
        )}
      </Match>
    </Switch>
  )

  const scopeSaveDisabled = () => {
    const current = signinRepositories() ?? repositories()
    return !current || selectSaveDisabled(current)
  }

  return (
    <div data-component="connectors-github-panel">
      <div class="sr-only" role="status" aria-live="polite">
        {announcement()}
      </div>
      <Wizard
        descriptor={GITHUB_DESCRIPTOR}
        state={wizard()}
        busy={connect.busy() || selectDisabled(signin.state()) || save.busy() || signin.saving()}
        unavailableMethodIds={signInUnavailable() ? new Set([GITHUB_SIGNIN_METHOD]) : undefined}
        values={fields}
        onValue={(id, value) => {
          if (id !== "token" && id !== "host") return
          setFields(id, value)
          if (id === "token") connect.dismiss()
        }}
        onSelectMethod={(methodId) => wizardDispatch({ type: "method.selected", methodId })}
        onContinue={() => wizardDispatch({ type: "continued" })}
        onVerify={() => (wizard().step === "scope" ? void saveScope() : void submit())}
        onBack={() => wizardDispatch({ type: "back" })}
        onCancel={props.onCancel}
        authorize={signInSection}
        pasteExtra={
          <>
            <Show when={selectPrefixHint(fields.token)}>
              <p class="m-0 text-11-regular text-v2-text-text-muted" role="status">
                {language.t("settings.connectors.github.token.prefixHint")}
              </p>
            </Show>
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
          </>
        }
        scope={scope}
        backDisabled={wizard().step === "scope"}
        cancelOnScope
        verifyDisabled={wizard().step === "scope" ? scopeSaveDisabled() : !fields.token || selectDisabled(signin.state())}
        connection={view.connected}
        onDone={() => props.onDone(view.connected)}
      />
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
    </div>
  )
}
