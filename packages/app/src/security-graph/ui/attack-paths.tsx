// Attack-path section for the Inspector slot: the "Show attack path" action, the list of found and known paths, and
// the detail of the selected one. Selecting a path highlights it end to end through the driver. The detail always
// lists the real steps, whatever the zoom level, because the engine aggregates only what the renderer draws.
import { createEffect, createMemo, For, Match, on, onCleanup, Show, Switch, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { Button } from "@bellucode/ui/button"
import { Tooltip } from "@bellucode/ui/tooltip"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { AttackPath, GraphData } from "../model"
import { crossings, entriesOf, findAttackPaths, toAttackPath, type FoundPath } from "../projection/attack-paths"
import { emptyHighlight, type Highlight } from "../render/types"
import { SeverityIcon } from "./inspector"
import type { ViewStore } from "./store"

type Key = Parameters<ReturnType<typeof useLanguage>["t"]>[0]

export type AttackPathsProps = {
  store: ViewStore
  driver: Driver
  /** The full graph. The search runs against it, not against the projection. */
  data: GraphData
  /** Highlight parts owned by the caller (agent glow, lit edges). The selected path is merged into it. */
  baseHighlight?: Highlight
}

export function AttackPaths(props: AttackPathsProps) {
  const language = useLanguage()
  const t = (key: string, params?: Record<string, string | number>) => language.t(`security.graph.attackPathUi.${key}` as Key, params)
  const [local, setLocal] = createStore<{ kinds: Record<string, FoundPath["kind"]> }>({ kinds: {} })
  const base = () => props.baseHighlight ?? emptyHighlight
  const names = createMemo(() => new Map(props.data.entities.map((entity) => [entity.id, entity])))
  const name = (id: string) => names().get(id)?.name ?? id
  const selectedEntity = () => props.store.state.selection
  const exposed = createMemo(() => new Set(entriesOf(props.data).map((entity) => entity.id)))
  const canShow = () => {
    const id = selectedEntity()
    return id !== undefined && exposed().has(id)
  }
  const known = () => props.data.attackPaths.filter((path) => !props.store.state.attackPaths.some((item) => item.id === path.id))
  const found = () => props.store.state.attackPaths.filter((path) => local.kinds[path.id] !== undefined)
  const all = () => [...props.store.state.attackPaths, ...known()]
  const selected = () => all().find((path) => path.id === props.store.state.selectedPathId)
  const visibleFound = () => found().filter((path) => path.entry === selectedEntity())

  function show() {
    const id = selectedEntity()
    if (id === undefined) return
    const results = findAttackPaths(props.data, id)
    const paths = results.map((item) =>
      toAttackPath(item, {
        evidence: (step) =>
          t("evidence", {
            from: step.fromName,
            relation: language.t(`security.graph.relation.${step.relation}` as Key),
            to: step.toName,
          }),
        remediation: t("remediation", { entry: name(item.entry), target: name(item.target) }),
      }),
    )
    setLocal("kinds", Object.fromEntries(results.map((item) => [item.id, item.kind])))
    props.store.showAttackPaths(paths)
    // The engine draws only the paths it knows, so the transient ones go in as a delta.
    props.driver.applyDelta({ attackPaths: paths })
  }

  function hide() {
    props.store.selectPath(undefined)
    props.store.showAttackPaths([])
    setLocal("kinds", {})
  }

  let applied = false
  createEffect(
    on([selected, base], ([path, caller]) => {
      if (!path) {
        if (applied) props.driver.setHighlight(caller)
        applied = false
        return
      }
      const nodes = [path.entry, path.target, ...path.steps.flatMap(endpoints)]
      props.driver.setHighlight({
        ...caller,
        focus: Array.from(new Set([...caller.focus, ...nodes])),
        paths: Array.from(new Set([...caller.paths, path.id])),
      })
      applied = true
    }),
  )
  onCleanup(() => {
    if (applied) props.driver.setHighlight(base())
  })
  function endpoints(step: string) {
    const rel = props.driver.engine.relationship(step)
    return rel ? [rel.source, rel.target] : []
  }

  return (
    <section data-component="security-graph-attack-paths" class="flex flex-col gap-2">
      <h3 class="m-0 text-12-medium text-text-weak">{language.t("security.graph.inspector.section.attackPaths")}</h3>
      <Switch>
        <Match when={selected()}>
          {(path) => (
            <Detail
              path={path()}
              data={props.data}
              driver={props.driver}
              name={name}
              onBack={() => props.store.selectPath(undefined)}
              onHide={hide}
            />
          )}
        </Match>
        <Match when={true}>
          <div class="flex flex-wrap gap-2">
            <Tooltip value={t("notExposed")} inactive={canShow()}>
              {/* A disabled button gets no pointer events, so the wrapper carries the tooltip trigger. */}
              <span class="inline-flex">
                <Button size="small" disabled={!canShow()} onClick={show}>
                  {t("show")}
                </Button>
              </span>
            </Tooltip>
            <Show when={props.store.state.attackPaths.length > 0 || props.store.state.selectedPathId !== undefined}>
              <Button size="small" variant="ghost" onClick={hide}>
                {t("hide")}
              </Button>
            </Show>
          </div>
          <Show when={visibleFound().length > 0}>
            <PathList
              label={t("list")}
              paths={visibleFound()}
              kinds={local.kinds}
              name={name}
              onSelect={props.store.selectPath}
            />
          </Show>
          <Show
            when={known().length > 0}
            fallback={
              <Show when={visibleFound().length === 0}>
                <span class="text-13-regular text-text-weak">{language.t("security.graph.empty.attackPaths")}</span>
              </Show>
            }
          >
            <PathList label={t("known")} paths={known()} kinds={local.kinds} name={name} onSelect={props.store.selectPath} />
          </Show>
        </Match>
      </Switch>
    </section>
  )
}

function PathList(props: {
  label: string
  paths: AttackPath[]
  kinds: Record<string, FoundPath["kind"]>
  name: (id: string) => string
  onSelect: (id: string) => void
}) {
  const language = useLanguage()
  return (
    <div class="flex flex-col gap-1">
      <span class="text-12-regular text-text-weak">{props.label}</span>
      <ul class="m-0 flex list-none flex-col gap-1 p-0">
        <For each={props.paths}>
          {(path) => (
            <li>
              <button
                type="button"
                class="flex w-full cursor-pointer flex-col gap-1 rounded-md border border-border-weak-base bg-transparent px-2 py-1 text-left hover:bg-background-stronger"
                onClick={() => props.onSelect(path.id)}
              >
                <span class="flex items-center gap-2 text-13-regular text-text-strong" style={{ "line-height": "var(--line-height-compact)" }}>
                  <SeverityIcon severity={path.severity} />
                  <span class="sr-only">{language.t(`security.graph.severity.${path.severity}` as Key)}</span>
                  <span class="min-w-0 break-words">
                    {language.t("security.graph.attackPathUi.entryToTarget" as Key, {
                      entry: props.name(path.entry),
                      target: props.name(path.target),
                    })}
                  </span>
                </span>
                <span class="flex gap-2 text-12-regular text-text-weak">
                  <span>{language.plural("security.graph.attackPathUi.steps", path.steps.length)}</span>
                  <Show when={props.kinds[path.id]}>
                    {(kind) => <span>{language.t(`security.graph.attackPathUi.kind.${kind()}` as Key)}</span>}
                  </Show>
                </span>
              </button>
            </li>
          )}
        </For>
      </ul>
    </div>
  )
}

function Detail(props: {
  path: AttackPath
  data: GraphData
  driver: Driver
  name: (id: string) => string
  onBack: () => void
  onHide: () => void
}) {
  const language = useLanguage()
  const t = (key: string) => language.t(`security.graph.attackPath.${key}` as Key)
  const steps = createMemo(() =>
    props.path.steps.flatMap((id) => {
      const rel = props.driver.engine.relationship(id)
      return rel ? [rel] : []
    }),
  )
  const typeOf = (id: string) => props.driver.engine.entity(id)?.type
  const isIdentity = (rel: (typeof steps extends () => (infer R)[] ? R : never)) =>
    rel.relation === "assumes" || typeOf(rel.source) === "identity" || typeOf(rel.target) === "identity"
  const intermediates = () => {
    const ends = new Set([props.path.entry, props.path.target])
    return Array.from(new Set(steps().flatMap((rel) => [rel.source, rel.target]))).filter((id) => !ends.has(id))
  }
  const crossed = createMemo(() => {
    const marks = new Set(crossings(props.data, props.path))
    return steps().filter((rel) => marks.has(rel.id))
  })
  const relation = (rel: { relation: string }) => language.t(`security.graph.relation.${rel.relation}` as Key)
  const edge = (rel: (typeof steps extends () => (infer R)[] ? R : never)) =>
    `${props.name(rel.source)} ${relation(rel)} ${props.name(rel.target)}`

  return (
    <div class="flex flex-col gap-3" role="group" aria-label={language.t("security.graph.attackPathUi.detail" as Key)}>
      <div class="flex flex-wrap gap-2">
        <Button size="small" variant="ghost" onClick={props.onBack}>
          {language.t("security.graph.attackPathUi.back" as Key)}
        </Button>
        <Button size="small" variant="ghost" onClick={props.onHide}>
          {language.t("security.graph.attackPathUi.hide" as Key)}
        </Button>
      </div>
      <Block title={t("entry")}>
        <span class="break-words">{props.name(props.path.entry)}</span>
      </Block>
      <Block title={t("intermediate")}>
        <Show when={intermediates().length > 0} fallback={<None />}>
          <ul class="m-0 flex list-disc flex-col gap-1 pl-4">
            <For each={intermediates()}>{(id) => <li class="break-words">{props.name(id)}</li>}</For>
          </ul>
        </Show>
      </Block>
      <Block title={t("identity")}>
        <Show when={steps().filter(isIdentity).length > 0} fallback={<None />}>
          <ul class="m-0 flex list-disc flex-col gap-1 pl-4">
            <For each={steps().filter(isIdentity)}>
              {(rel) => (
                <li class="break-words">
                  {language.t(
                    (rel.relation === "assumes"
                      ? "security.graph.attackPathUi.edge.identity"
                      : "security.graph.attackPathUi.edge.permission") as Key,
                  )}
                  : {edge(rel)}
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Block>
      <Block title={t("target")}>
        <span class="break-words">{props.name(props.path.target)}</span>
      </Block>
      <Block title={t("steps")}>
        <ol class="m-0 flex list-decimal flex-col gap-1 pl-5">
          <For each={steps()}>
            {(rel, index) => (
              <li class="break-words" aria-label={language.t("security.graph.attackPath.step", { index: index() + 1 })}>
                {edge(rel)}
                <Show when={crossed().includes(rel)}>
                  <span class="ml-2 inline-flex items-center gap-1 text-text-weak" data-marker="crossing">
                    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
                      <path d="M6 0.5 11.5 6 6 11.5 0.5 6Z" fill="none" stroke="currentColor" stroke-width="1.5" />
                    </svg>
                    {language.t("security.graph.attackPathUi.crossing" as Key, {
                      from: props.name(rel.source),
                      to: props.name(rel.target),
                    })}
                  </span>
                </Show>
              </li>
            )}
          </For>
        </ol>
      </Block>
      <Block title={t("crossings")}>
        <Show when={crossed().length > 0} fallback={<span class="text-text-weak">{language.t("security.graph.attackPathUi.crossing.none" as Key)}</span>}>
          <ul class="m-0 flex list-none flex-col gap-1 p-0">
            <For each={crossed()}>
              {(rel) => (
                <li class="break-words">
                  {language.t("security.graph.attackPathUi.crossing" as Key, {
                    from: props.name(rel.source),
                    to: props.name(rel.target),
                  })}
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Block>
      <Block title={t("evidence")}>
        <Show when={props.path.evidence.length > 0} fallback={<None />}>
          <ul class="m-0 flex list-disc flex-col gap-1 pl-4">
            <For each={props.path.evidence}>{(line) => <li class="break-words">{line}</li>}</For>
          </ul>
        </Show>
      </Block>
      <Block title={t("risk")}>
        <span class="inline-flex items-start gap-2 break-words">
          <SeverityIcon severity={props.path.severity} />
          {language.plural("security.graph.attackPathUi.risk", props.path.steps.length, {
            severity: language.t(`security.graph.severity.${props.path.severity}` as Key),
            entry: props.name(props.path.entry),
            target: props.name(props.path.target),
          })}
        </span>
      </Block>
      <Block title={t("remediation")}>
        <Show when={props.path.remediation} fallback={<None />}>
          <p class="m-0 break-words">{props.path.remediation}</p>
        </Show>
      </Block>
    </div>
  )
}

function Block(props: { title: string; children: JSX.Element }) {
  return (
    <div class="flex flex-col gap-1">
      <span class="text-12-regular text-text-weak">{props.title}</span>
      <div class="text-13-regular text-text-base">{props.children}</div>
    </div>
  )
}

function None() {
  const language = useLanguage()
  return <span class="text-text-weak">{language.t("security.graph.inspector.none")}</span>
}
