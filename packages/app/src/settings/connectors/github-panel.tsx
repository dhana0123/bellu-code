import { Button } from "@bellucode/ui/button"
import { Checkbox } from "@bellucode/ui/checkbox"
import { Loader } from "@bellucode/ui/loader"
import { MenuScroll } from "@bellucode/ui/menu-scroll"
import { TextField } from "@bellucode/ui/text-field"
import type { Connectors } from "@bellucode/schema/connectors"
import { For, Match, Show, Switch, createMemo, createSignal, type Component } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { createConnectorsData, type ConnectorsData } from "./data"
import { failureMessage } from "./errors"
import {
  INITIAL_GITHUB_STATE,
  selectClassicRejected,
  selectPrefixHint,
  selectRepositoriesRequired,
  selectSaveDisabled,
  transitionGithub,
  GITHUB_PAT_PREFIX,
  type GithubEvent,
} from "./github-machine"
import { clearCredentials } from "./machine"

export type GithubPanelProps = {
  /** The Account_Alias the dialog shell collected. */
  alias: string
  /** The Auth_Config the dialog shell selected, if any. */
  authConfigId?: string
  /** Called with the saved Connection once repositories are selected. */
  onDone: (connection: Connectors.Connection) => void
  onCancel: () => void
  /** The shell's data layer. Without it the panel creates its own. */
  data?: ConnectorsData
}

/**
 * GitHub connect panel (fine-grained PAT only). Step one creates the Connection from the token; step two lists the
 * repositories the token reaches and saves the selection. The token lives only in this component's local store and is
 * emptied when each request settles.
 */
export const GithubPanel: Component<GithubPanelProps> = (props) => {
  const language = useLanguage()
  const data = props.data ?? createConnectorsData()
  const connect = data.createMutation()
  const list = data.createMutation()
  const save = data.createMutation()

  const [state, setState] = createSignal(INITIAL_GITHUB_STATE)
  const dispatch = (event: GithubEvent) => setState((previous) => transitionGithub(previous, event))
  const [fields, setFields] = createStore({ token: "", host: "" })

  const step = createMemo(() => state().status)
  const repositories = createMemo(() => {
    const current = state()
    return current.status === "repositories" ? current : undefined
  })
  const failure = () => connect.failure() ?? save.failure()

  const loadRepos = async (id: string, attempt: number) => {
    const result = await list.run((api, signal) => api.listGithubRepos({ id }, { signal }))
    dispatch(result ? { type: "repos.loaded", attempt, items: result.items } : { type: "repos.failed", attempt })
  }

  const submit = async (event: SubmitEvent) => {
    event.preventDefault()
    const token = fields.token
    const host = fields.host.trim()
    if (!token || connect.busy()) return
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
          { signal },
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
    if (connection) props.onDone(connection)
  }

  const errorText = () => {
    const current = failure()
    if (!current) return
    if (current.kind === "connector" && current.code === "validation_failed" && selectClassicRejected(state()))
      return language.t("settings.connectors.github.token.classic")
    const message = failureMessage(current)
    return language.t(message.key, message.params)
  }

  const methods = [
    { id: "app", key: "settings.connectors.github.method.app", disabled: true },
    { id: "device", key: "settings.connectors.github.method.deviceFlow", disabled: true },
    { id: "pat", key: "settings.connectors.github.method.pat", disabled: false },
  ] as const

  return (
    <div class="flex flex-col gap-4" data-component="connectors-github-panel">
      <fieldset class="m-0 flex min-w-0 flex-col gap-2 border-0 p-0">
        <legend class="mb-2 p-0 text-13-medium text-v2-text-text-base">
          {language.t("settings.connectors.github.methods")}
        </legend>
        <For each={methods}>
          {(method) => (
            <label
              class="flex items-center gap-2 text-13-regular"
              classList={{
                "text-v2-text-text-base": !method.disabled,
                "text-v2-text-text-faint": method.disabled,
              }}
            >
              <input type="radio" name="github-method" disabled={method.disabled} checked={!method.disabled} />
              <span class="min-w-0 flex-1">{language.t(method.key)}</span>
              <Show when={method.disabled}>
                <span class="text-11-regular text-v2-text-text-muted">
                  {language.t("settings.connectors.badge.laterRelease")}
                </span>
              </Show>
            </label>
          )}
        </For>
      </fieldset>

      <Switch>
        <Match when={step() === "credentials"}>
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
              {(message) => (
                <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
                  {message()}
                </p>
              )}
            </Show>
            <div class="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={props.onCancel}>
                {language.t("settings.connectors.action.cancel")}
              </Button>
              <Button type="submit" variant="submit" disabled={!fields.token || connect.busy()}>
                <Show when={connect.busy()} fallback={language.t("settings.connectors.action.connect")}>
                  <Loader class="size-4" aria-hidden="true" />
                  {language.t("settings.connectors.github.connecting")}
                </Show>
              </Button>
            </div>
          </form>
        </Match>
        <Match when={repositories()} keyed>
          {(current) => (
            <div class="flex flex-col gap-3">
              <div class="flex flex-col gap-1">
                <h4 class="m-0 text-13-medium text-v2-text-text-base">
                  {language.t("settings.connectors.github.repositories")}
                </h4>
                <p class="m-0 text-11-regular text-v2-text-text-muted">
                  {language.t("settings.connectors.github.repositories.help")}
                </p>
              </div>
              <Switch>
                <Match when={current.repos.phase === "loading"}>
                  <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted" role="status">
                    <Loader class="size-4" aria-hidden="true" />
                    {language.t("settings.connectors.github.repositories.loading")}
                  </div>
                </Match>
                <Match when={current.repos.phase === "failed"}>
                  <div class="flex items-center gap-2">
                    <p class="m-0 flex-1 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
                      {language.t("settings.connectors.github.repositories.failed")}
                    </p>
                    <Button type="button" size="small" variant="neutral" onClick={retry}>
                      {language.t("settings.connectors.action.retry")}
                    </Button>
                  </div>
                </Match>
                <Match when={current.repos.phase === "ready" ? current.repos.items : undefined} keyed>
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
                              checked={current.selected.includes(repo.fullName)}
                              onChange={() => dispatch({ type: "repo.toggled", fullName: repo.fullName })}
                              disabled={save.busy()}
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
              <Show when={selectRepositoriesRequired(current)}>
                <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
                  {language.t("settings.connectors.github.repositories.required")}
                </p>
              </Show>
              <Show when={errorText()}>
                {(message) => (
                  <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
                    {message()}
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
                  disabled={selectSaveDisabled(current) || save.busy()}
                  onClick={saveSelection}
                >
                  {language.t("settings.connectors.action.save")}
                </Button>
              </div>
            </div>
          )}
        </Match>
      </Switch>
    </div>
  )
}
