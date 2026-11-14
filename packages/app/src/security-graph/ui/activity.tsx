import { createEffect, For, Match, on, onCleanup, Show, Switch } from "solid-js"
import { createStore, reconcile } from "solid-js/store"
import { Button } from "@bellucode/ui/button"
import { useLanguage } from "@/runtime/i18n/language"
import { createAgentDriver, type AgentDriver, type AgentSnapshot } from "../agents/driver"
import { initialAgentState, view, type AgentState } from "../agents/events"
import type { Driver } from "../driver"
import type { Engine } from "../projection/engine"
import type { Highlight } from "../render/types"
import type { EventStream } from "../source"
import type { ZoomLevelKey } from "../theme"

export type ActivityProps = {
  stream: EventStream
  engine: Engine
  /** The graph driver that receives agent highlights and finding tags. */
  driver: Driver
  level: ZoomLevelKey
  /** Focus and attack-path highlight owned by other panels, merged into every agent highlight update. */
  base?: () => Pick<Highlight, "focus" | "paths">
  /** Receives every agent state snapshot so other panels (Inspector, Agent filter) can read it. */
  onAgents?: (state: AgentState) => void
}

const logLimit = 100

export function Activity(props: ActivityProps) {
  const language = useLanguage()
  const [store, setStore] = createStore<{ snapshot: AgentSnapshot }>({
    snapshot: { state: initialAgentState, playback: "playing" },
  })
  let agents: AgentDriver | undefined

  // One agent driver per stream and graph driver. Disposing it aborts the stream iteration.
  createEffect(
    on(
      () => [props.stream, props.driver, props.engine] as const,
      ([stream, driver, engine]) => {
        setStore("snapshot", { state: initialAgentState, playback: "playing" })
        const next = createAgentDriver({
          stream,
          engine,
          driver,
          findingLabel: language.t("security.graph.activityPanel.finding"),
          base: props.base,
          onSnapshot: (snapshot) => {
            setStore("snapshot", reconcile(snapshot))
            props.onAgents?.(snapshot.state)
          },
        })
        agents = next
        onCleanup(() => {
          next.dispose()
          if (agents === next) agents = undefined
        })
      },
    ),
  )

  const model = () => view(store.snapshot.state, props.level)
  const name = (id: string) => props.engine.entity(id)?.name ?? id
  const log = () => store.snapshot.state.log.slice(-logLimit)
  const playing = () => store.snapshot.playback === "playing"
  const ended = () => store.snapshot.playback === "ended"

  return (
    <section class="flex min-h-0 flex-col" aria-label={language.t("security.graph.activity.title")}>
      <header class="flex items-center gap-2 px-3 py-2">
        <h2 class="min-w-0 flex-1 truncate text-14-medium">{language.t("security.graph.activity.title")}</h2>
        <Show when={props.stream.simulated}>
          <span
            class="rounded-full px-2 text-12-medium"
            style={{ background: "var(--surface-raised-base)" }}
            title={language.t("security.graph.agents.simulated.description")}
          >
            {language.t("security.graph.agents.simulated")}
          </span>
        </Show>
        <Button
          size="small"
          variant="ghost"
          aria-label={language.t(playing() ? "security.graph.activity.pause" : "security.graph.activity.resume")}
          disabled={ended()}
          onClick={() => (playing() ? agents?.pause() : agents?.resume())}
        >
          {language.t(playing() ? "security.graph.activity.pause" : "security.graph.activity.resume")}
        </Button>
        <Button
          size="small"
          variant="ghost"
          aria-label={language.t("security.graph.activity.replay")}
          onClick={() => agents?.replay()}
        >
          {language.t("security.graph.activity.replay")}
        </Button>
      </header>
      <div class="min-h-0 flex-1 overflow-y-auto px-3 pb-3" data-scrollable>
        <Show
          when={store.snapshot.state.log.length > 0}
          fallback={<p class="text-12-regular">{language.t("security.graph.activityPanel.empty")}</p>}
        >
          <Switch>
            <Match when={model().level === "L1" && (model() as Extract<ReturnType<typeof model>, { level: "L1" }>)}>
              {(summary) => (
                <dl class="flex flex-col gap-1 text-13-regular">
                  <div class="flex justify-between gap-2">
                    <dt>{language.t("security.graph.agents.cluster")}</dt>
                    <dd>{summary().activeAgents}</dd>
                  </div>
                  <div class="flex justify-between gap-2">
                    <dt>{language.t("security.graph.activity.findings")}</dt>
                    <dd>{summary().findings}</dd>
                  </div>
                </dl>
              )}
            </Match>
            <Match when={model().level === "L2" || model().level === "L3"}>
              <ul class="flex flex-col gap-1 text-13-regular">
                <For each={(model() as Extract<ReturnType<typeof model>, { level: "L2" | "L3" }>).agents}>
                  {(agent) => (
                    <li class="flex items-center justify-between gap-2">
                      <span class="min-w-0 truncate">{name(agent.id)}</span>
                      <span>{language.t(`security.graph.activityPanel.execution.${agent.execution}`)}</span>
                    </li>
                  )}
                </For>
              </ul>
            </Match>
            <Match when={model().level === "L4"}>
              <ul class="flex flex-col gap-3 text-13-regular">
                <For each={(model() as Extract<ReturnType<typeof model>, { level: "L4" }>).agents}>
                  {(agent) => (
                    <li class="flex flex-col gap-0.5">
                      <div class="flex items-center justify-between gap-2">
                        <span class="min-w-0 truncate text-13-medium">{name(agent.id)}</span>
                        <span>{language.t(`security.graph.activityPanel.execution.${agent.execution}`)}</span>
                      </div>
                      <div>
                        {language.t("security.graph.activity.task")}:{" "}
                        {language.t(`security.graph.activity.event.${agent.task.type}`, { entity: name(agent.task.entityId) })}
                      </div>
                      <Show when={agent.tool}>
                        {(tool) => (
                          <div>
                            {language.t("security.graph.activity.tool")}: {name(tool())}
                          </div>
                        )}
                      </Show>
                      <div>
                        {language.t("security.graph.activity.target")}: {name(agent.target)}
                      </div>
                      <div>
                        {language.t("security.graph.activity.findings")}:{" "}
                        {Object.keys(agent.findings).map(name).join(", ") || "0"}
                      </div>
                    </li>
                  )}
                </For>
              </ul>
            </Match>
          </Switch>
          <Show when={props.level === "L4"}>
            <h3 class="mt-3 text-12-medium">{language.t("security.graph.activityPanel.log")}</h3>
            <ol class="flex flex-col gap-0.5 text-12-regular">
              <For each={log()}>
                {(event) => (
                  <li class="flex gap-2">
                    <span class="min-w-0 flex-1 truncate">
                      {name(event.agentId)}:{" "}
                      {language.t(`security.graph.activity.event.${event.type}`, { entity: name(event.entityId) })}
                    </span>
                  </li>
                )}
              </For>
            </ol>
          </Show>
          <Show when={ended()}>
            <p class="mt-2 text-12-regular">{language.t("security.graph.activityPanel.ended")}</p>
          </Show>
        </Show>
      </div>
    </section>
  )
}
