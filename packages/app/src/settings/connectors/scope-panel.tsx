import { Button } from "@bellucode/ui/button"
import { Checkbox } from "@bellucode/ui/checkbox"
import { Loader } from "@bellucode/ui/loader"
import { Switch as Toggle } from "@bellucode/ui/switch"
import { For, Match, onMount, Show, Switch, type Component } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { createConnectorsData, type ConnectorsData } from "./data"
import { failureMessage } from "./errors"

/** The principal whose scope this panel edits. */
const PRINCIPAL = "agent"

export type ScopePanelProps = {
  /** The page's data layer. Without it the panel creates its own. */
  data?: ConnectorsData
}

type Draft = {
  phase: "loading" | "failed" | "ready"
  connections: string[]
  /** Allowed read operations, keyed by connector id. */
  operations: Record<string, string[]>
  saved: boolean
}

/**
 * Agent scope editor (Requirement 17). The stored scope is empty by default, which denies every live read. Operations
 * offered are the connector's `read` class operations from the catalog manifest; the server still validates them and
 * names an offending operation when it rejects the save.
 */
export const ScopePanel: Component<ScopePanelProps> = (props) => {
  const language = useLanguage()
  const data = props.data ?? createConnectorsData()
  const load = data.createMutation()
  const save = data.createMutation()
  const toggle = data.createMutation()
  const [draft, setDraft] = createStore<Draft>({ phase: "loading", connections: [], operations: {}, saved: false })

  const refresh = async () => {
    setDraft("phase", "loading")
    const scope = await load.run((api, signal) => api.getScope({ principal: PRINCIPAL }, { signal }))
    if (!scope) return setDraft("phase", "failed")
    setDraft({
      phase: "ready",
      connections: [...scope.connections],
      operations: Object.fromEntries(Object.entries(scope.operations).map(([id, ops]) => [id, [...ops]])),
      saved: false,
    })
  }
  onMount(() => void refresh())

  const cards = () => data.cards().filter((card) => card.connections.length > 0)
  const readOperations = (manifest: { operations: readonly { name: string; class: string }[] }) =>
    manifest.operations.filter((operation) => operation.class === "read").map((operation) => operation.name)

  const toggleConnection = (id: string, on: boolean) => {
    save.dismiss()
    setDraft("saved", false)
    setDraft("connections", (current) => (on ? [...current.filter((item) => item !== id), id] : current.filter((item) => item !== id)))
  }
  const toggleOperation = (connectorId: string, name: string, on: boolean) => {
    save.dismiss()
    setDraft("saved", false)
    setDraft("operations", connectorId, (current = []) =>
      on ? [...current.filter((item) => item !== name), name] : current.filter((item) => item !== name),
    )
  }

  const submit = async () => {
    if (save.busy()) return
    const known = new Set(data.connections().map((connection) => connection.id))
    const connections = draft.connections.filter((id) => known.has(id))
    const operations = Object.fromEntries(Object.entries(draft.operations).filter(([, ops]) => ops.length > 0))
    const connectors = [
      ...new Set([
        ...data.connections().filter((connection) => connections.includes(connection.id)).map((c) => c.connectorId),
        ...Object.keys(operations),
      ]),
    ]
    const result = await save.run((api, signal) =>
      api.putScope({ principal: PRINCIPAL, connectors, connections, operations }, { signal }),
    )
    if (result) setDraft("saved", true)
  }

  const setLiveReads = (id: string, allowAgentLiveReads: boolean) => {
    toggle.dismiss()
    void toggle.run((api, signal) => api.updateConnection({ id, allowAgentLiveReads }, { signal }))
  }

  const errorText = () => {
    const current = save.failure() ?? toggle.failure()
    if (!current) return
    const message = failureMessage(current)
    return language.t(message.key, message.params)
  }

  return (
    <section class="flex flex-col gap-4" data-component="connectors-scope-panel" aria-labelledby="connectors-scope-title">
      <div class="flex flex-col gap-1">
        <h3 id="connectors-scope-title" class="m-0 text-13-medium text-v2-text-text-base">
          {language.t("settings.connectors.scope.title")}
        </h3>
        <p class="m-0 text-11-regular text-v2-text-text-muted">{language.t("settings.connectors.scope.description")}</p>
        <p class="m-0 text-11-regular text-v2-text-text-muted">{language.t("settings.connectors.scope.default")}</p>
      </div>
      <Switch>
        <Match when={draft.phase === "loading"}>
          <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted" role="status">
            <Loader class="size-4" aria-hidden="true" />
            {language.t("settings.connectors.scope.loading")}
          </div>
        </Match>
        <Match when={draft.phase === "failed"}>
          <div class="flex items-center gap-2">
            <p class="m-0 flex-1 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
              {language.t("settings.connectors.scope.loadFailed")}
            </p>
            <Button type="button" size="small" variant="neutral" onClick={() => void refresh()}>
              {language.t("settings.connectors.action.retry")}
            </Button>
          </div>
        </Match>
        <Match when={draft.phase === "ready"}>
          <Show
            when={cards().length > 0}
            fallback={<p class="m-0 text-13-regular text-v2-text-text-muted">{language.t("settings.connectors.scope.empty")}</p>}
          >
            <div class="flex flex-col gap-4">
              <For each={cards()}>
                {(card) => (
                  <fieldset class="m-0 flex min-w-0 flex-col gap-3 border-0 p-0">
                    <legend class="mb-2 p-0 text-13-medium text-v2-text-text-base">{card.manifest.name}</legend>
                    <ul class="m-0 flex list-none flex-col gap-2 p-0" aria-label={language.t("settings.connectors.scope.connections")}>
                      <For each={card.connections}>
                        {(connection) => (
                          <li class="flex flex-wrap items-center justify-between gap-3">
                            <Checkbox
                              appearance="compact"
                              checked={draft.connections.includes(connection.id)}
                              disabled={save.busy()}
                              onChange={(on) => toggleConnection(connection.id, on)}
                            >
                              <span class="sr-only">
                                {language.t("settings.connectors.scope.include", { alias: connection.alias })}
                              </span>
                              <span aria-hidden="true">{connection.alias}</span>
                            </Checkbox>
                            <Toggle
                              checked={connection.allowAgentLiveReads}
                              disabled={toggle.busy()}
                              onChange={(on) => setLiveReads(connection.id, on)}
                              description={language.t("settings.connectors.connection.liveReads.description")}
                            >
                              {language.t("settings.connectors.connection.liveReads")}
                            </Toggle>
                          </li>
                        )}
                      </For>
                    </ul>
                    <div
                      role="group"
                      class="flex flex-col gap-1"
                      aria-label={language.t("settings.connectors.scope.operations", { service: card.manifest.name })}
                    >
                      <span class="text-11-regular text-v2-text-text-muted" aria-hidden="true">
                        {language.t("settings.connectors.scope.operations", { service: card.manifest.name })}
                      </span>
                      <Show
                        when={readOperations(card.manifest).length > 0}
                        fallback={
                          <p class="m-0 text-13-regular text-v2-text-text-muted">
                            {language.t("settings.connectors.scope.operations.empty")}
                          </p>
                        }
                      >
                        <For each={readOperations(card.manifest)}>
                          {(name) => (
                            <Checkbox
                              appearance="compact"
                              checked={(draft.operations[card.manifest.id] ?? []).includes(name)}
                              disabled={save.busy()}
                              onChange={(on) => toggleOperation(card.manifest.id, name, on)}
                            >
                              {name}
                            </Checkbox>
                          )}
                        </For>
                      </Show>
                    </div>
                  </fieldset>
                )}
              </For>
            </div>
          </Show>
          <Show when={errorText()}>
            {(message) => (
              <p class="m-0 text-13-regular text-[color:var(--v2-state-fg-danger)]" role="alert">
                {message()}
              </p>
            )}
          </Show>
          <Show when={draft.saved}>
            <p class="m-0 text-11-regular text-v2-text-text-muted" role="status">
              {language.t("settings.connectors.scope.saved")}
            </p>
          </Show>
          <div class="flex justify-end">
            <Button type="button" variant="submit" disabled={save.busy()} onClick={() => void submit()}>
              <Show when={save.busy()} fallback={language.t("settings.connectors.scope.save")}>
                <Loader class="size-4" aria-hidden="true" />
              </Show>
            </Button>
          </div>
        </Match>
      </Switch>
    </section>
  )
}
