import { For, Match, Show, Switch, type JSX } from "solid-js"
import { Button } from "@bellucode/ui/button"
import { Tooltip } from "@bellucode/ui/tooltip"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { Entity, Relationship, Severity } from "../model"
import { severities, type SeverityShape } from "../theme"
import type { ViewStore } from "./store"

type Key = Parameters<ReturnType<typeof useLanguage>["t"]>[0]

export type InspectorActions = {
  /** Each action is disabled, with a tooltip, until its callback is given. */
  onAskAgent?: (entity: Entity) => void
  onGenerateFix?: (entity: Entity) => void
  onValidateFix?: (entity: Entity) => void
  onOpenEditor?: (entity: Entity) => void
}

export type InspectorProps = InspectorActions & {
  store: ViewStore
  /** Provides the engine and the camera. Without it the related entities are not clickable. */
  driver?: Driver
  /** Slot for the attack path section (task 6.4). */
  attackPaths?: JSX.Element
}

// The shapes the atlas draws, so the Inspector reads the same as the canvas without relying on color.
const shapes: Record<SeverityShape, string> = {
  diamond: "M6 0.5 11.5 6 6 11.5 0.5 6Z",
  triangle: "M6 1 11.5 11 0.5 11Z",
  square: "M1.5 1.5h9v9h-9Z",
  circle: "M6 0.5a5.5 5.5 0 1 0 0.01 0Z",
  ring: "M6 1.5a4.5 4.5 0 1 0 0.01 0Z",
  check: "M1.5 6.5 4.5 9.5 10.5 2.5",
  shield: "M6 0.5 10.5 2v4c0 2.5-2 4.5-4.5 5.5C3.500 10.500 1.500 8.500 1.500 6V2Z",
}

export function SeverityIcon(props: { severity: Severity }) {
  const token = () => severities[props.severity]
  const stroked = () => token().shape === "ring" || token().shape === "check"
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true" data-shape={token().shape} class="shrink-0">
      <path
        d={shapes[token().shape]}
        fill={stroked() ? "none" : token().color}
        stroke={token().color}
        stroke-width={stroked() ? 1.75 : 1}
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    </svg>
  )
}

export function Inspector(props: InspectorProps) {
  const language = useLanguage()
  const t = (key: string) => language.t(key as Key)
  const engine = () => props.driver?.engine
  const entity = () => {
    const id = props.store.state.selection
    return id === undefined ? undefined : engine()?.entity(id)
  }

  return (
    <aside
      data-component="security-graph-inspector"
      aria-label={t("security.graph.inspector.title")}
      class="flex h-full min-h-0 flex-col bg-background-base"
    >
      <header class="shrink-0 px-4 py-3 text-14-medium text-text-strong">{t("security.graph.inspector.title")}</header>
      <div class="min-h-0 flex-1 overflow-y-auto px-4 pb-4" data-scrollable>
        <Switch>
          <Match when={entity()}>
            {(item) => (
              <EntityDetails
                entity={item()}
                store={props.store}
                driver={props.driver}
                actions={props}
                attackPaths={props.attackPaths}
              />
            )}
          </Match>
          <Match when={true}>
            <p class="text-13-regular text-text-weak">{t("security.graph.empty.inspector")}</p>
            {props.attackPaths}
          </Match>
        </Switch>
      </div>
    </aside>
  )
}

function EntityDetails(props: {
  entity: Entity
  store: ViewStore
  driver?: Driver
  actions: InspectorActions
  attackPaths?: JSX.Element
}) {
  const language = useLanguage()
  const t = (key: string) => language.t(key as Key)
  const related = () => {
    const engine = props.driver?.engine
    if (!engine) return { incoming: [], outgoing: [] }
    const rels = engine.relationshipsOf(props.entity.id)
    return {
      incoming: rels.filter((rel) => rel.target === props.entity.id && rel.source !== props.entity.id),
      outgoing: rels.filter((rel) => rel.source === props.entity.id),
    }
  }
  const paths = () =>
    props.store.state.attackPaths.filter(
      (path) =>
        path.entry === props.entity.id ||
        path.target === props.entity.id ||
        path.steps.some((id) => {
          const rel = props.driver?.engine.relationship(id)
          return rel?.source === props.entity.id || rel?.target === props.entity.id
        }),
    )
  const evidence = () => paths().flatMap((path) => path.evidence)
  const remediation = () => Array.from(new Set(paths().map((path) => path.remediation).filter(Boolean)))
  const agents = () => {
    const state = props.store.state.agents
    return Object.values(state.agents)
      .filter((agent) => agent.accessed.includes(props.entity.id))
      .map((agent) => ({
        id: agent.id,
        execution: agent.execution,
        current: agent.target === props.entity.id,
        findings: (state.findings[props.entity.id] ?? []).filter((item) => item.agentId === agent.id).length,
      }))
  }
  // Credentials are references. Only `secretRef` keys are shown, and only as text.
  const credentials = () =>
    Object.entries(props.entity.metadata)
      .filter(([key]) => key === "secretRef" || key.endsWith("SecretRef") || key.endsWith(".secretRef"))
      .map(([key, value]) => ({ key, value: String(value) }))
  const details = () =>
    Object.entries(props.entity.metadata).filter(([key]) => !credentials().some((item) => item.key === key))

  return (
    <div class="flex flex-col gap-4">
      <div class="flex flex-col gap-1">
        <h2 class="text-14-medium text-text-strong break-words">{props.entity.name}</h2>
        <span class="text-13-regular text-text-weak">
          {t(`security.graph.tooltip.kind.${props.entity.type}`)}
        </span>
      </div>

      <Section title={t("security.graph.inspector.section.severity")}>
        <Show
          when={props.entity.severity}
          fallback={<span class="text-13-regular text-text-weak">{t("security.graph.inspector.severity.none")}</span>}
        >
          {(severity) => (
            <span class="inline-flex items-center gap-2 text-13-regular text-text-base">
              <SeverityIcon severity={severity()} />
              {t(`security.graph.severity.${severity()}`)}
            </span>
          )}
        </Show>
      </Section>

      <Section title={t("security.graph.inspector.section.description")}>
        <Show
          when={typeof props.entity.metadata.description === "string" && props.entity.metadata.description}
          fallback={<None />}
        >
          {(text) => <p class="text-13-regular text-text-base break-words">{String(text())}</p>}
        </Show>
      </Section>

      <Section title={t("security.graph.inspector.section.source")}>
        <Show when={props.entity.sourceLocation} fallback={<span class="text-13-regular text-text-weak">{t("security.graph.inspector.source.none")}</span>}>
          {(location) => (
            // The app ships no standalone code viewer, so the location is a code-font block.
            <pre
              data-component="security-graph-source"
              class="m-0 overflow-x-auto rounded-md bg-background-stronger px-3 py-2 font-mono text-13-regular text-text-base"
              data-scrollable
            >
              <code>
                {language.t("security.graph.inspector.source.line", {
                  path: location().path,
                  line: location().line,
                })}
              </code>
            </pre>
          )}
        </Show>
      </Section>

      <Section title={t("security.graph.inspector.section.tags")}>
        <Show when={props.entity.tags.length > 0} fallback={<None />}>
          <ul class="m-0 flex list-none flex-wrap gap-1 p-0">
            <For each={props.entity.tags}>
              {(tag) => (
                <li
                  data-tone={tag.severity}
                  class="rounded-full border border-border-weak-base px-2 text-12-regular text-text-base"
                  style={{ "line-height": "var(--line-height-compact)" }}
                >
                  {tag.label}
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Section>

      <Section title={t("security.graph.inspector.section.related")}>
        <Show when={related().incoming.length + related().outgoing.length > 0} fallback={<None />}>
          <RelatedList
            label={t("security.graph.inspector.related.outgoing")}
            rels={related().outgoing}
            self={props.entity.id}
            driver={props.driver}
          />
          <RelatedList
            label={t("security.graph.inspector.related.incoming")}
            rels={related().incoming}
            self={props.entity.id}
            driver={props.driver}
          />
        </Show>
      </Section>

      <Section title={t("security.graph.inspector.section.evidence")}>
        <Show when={evidence().length > 0} fallback={<None />}>
          <ul class="m-0 flex list-disc flex-col gap-1 pl-4 text-13-regular text-text-base">
            <For each={evidence()}>{(line) => <li class="break-words">{line}</li>}</For>
          </ul>
        </Show>
      </Section>

      <Section title={t("security.graph.inspector.section.provenance")}>
        <div class="flex flex-col gap-1 text-13-regular text-text-base">
          <span class="break-words">
            {language.t("security.graph.inspector.provenance.source", { source: props.entity.provenance.source })}
          </span>
          <span>
            {language.t("security.graph.inspector.provenance.observed", {
              time: new Intl.DateTimeFormat(language.intl(), { dateStyle: "medium", timeStyle: "short" }).format(
                props.entity.provenance.observedAt,
              ),
            })}
          </span>
        </div>
      </Section>

      <Section title={t("security.graph.inspector.section.remediation")}>
        <Show when={remediation().length > 0} fallback={<None />}>
          <For each={remediation()}>{(text) => <p class="m-0 text-13-regular text-text-base break-words">{text}</p>}</For>
        </Show>
      </Section>

      <Section title={t("security.graph.inspector.section.agents")}>
        <Show when={agents().length > 0} fallback={<span class="text-13-regular text-text-weak">{t("security.graph.empty.activity")}</span>}>
          <ul class="m-0 flex list-none flex-col gap-1 p-0 text-13-regular text-text-base">
            <For each={agents()}>
              {(agent) => (
                <li class="flex items-baseline justify-between gap-2">
                  <span class="break-words">{agent.id}</span>
                  <span class="text-text-weak">
                    {agent.current ? t(`security.graph.inspector.execution.${agent.execution}`) : ""}
                    {agent.findings > 0 ? ` ${t("security.graph.activity.findings")}: ${agent.findings}` : ""}
                  </span>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Section>

      <Show when={credentials().length > 0}>
        <Section title={t("security.graph.inspector.section.credential")}>
          <p class="m-0 text-13-regular text-text-weak">{t("security.graph.inspector.credential.reference")}</p>
          <ul class="m-0 flex list-none flex-col gap-1 p-0">
            <For each={credentials()}>
              {(item) => (
                <li>
                  <code class="font-mono text-13-regular text-text-base break-all">{item.value}</code>
                </li>
              )}
            </For>
          </ul>
        </Section>
      </Show>

      <Show when={details().length > 0}>
        <Section title={t("security.graph.inspector.section.details")}>
          <dl class="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-13-regular">
            <For each={details()}>
              {([key, value]) => (
                <>
                  <dt class="text-text-weak break-words">{key}</dt>
                  <dd class="m-0 text-text-base break-words">{String(value)}</dd>
                </>
              )}
            </For>
          </dl>
        </Section>
      </Show>

      {props.attackPaths}

      <Section title={t("security.graph.inspector.actions")}>
        <div class="flex flex-wrap gap-2">
          <Action label="security.graph.action.askAgent" run={props.actions.onAskAgent} entity={props.entity} />
          <Action label="security.graph.action.generateFix" run={props.actions.onGenerateFix} entity={props.entity} />
          <Action label="security.graph.action.validateFix" run={props.actions.onValidateFix} entity={props.entity} />
          <Action label="security.graph.action.openEditor" run={props.actions.onOpenEditor} entity={props.entity} />
        </div>
      </Section>
    </div>
  )
}

function Section(props: { title: string; children: JSX.Element }) {
  return (
    <section class="flex flex-col gap-2">
      <h3 class="m-0 text-12-medium text-text-weak">{props.title}</h3>
      {props.children}
    </section>
  )
}

function None() {
  const language = useLanguage()
  return <span class="text-13-regular text-text-weak">{language.t("security.graph.inspector.none")}</span>
}

function RelatedList(props: { label: string; rels: Relationship[]; self: string; driver?: Driver }) {
  const language = useLanguage()
  return (
    <Show when={props.rels.length > 0}>
      <div class="flex flex-col gap-1">
        <span class="text-12-regular text-text-weak">{props.label}</span>
        <ul class="m-0 flex list-none flex-col gap-1 p-0">
          <For each={props.rels}>
            {(rel) => {
              const otherId = rel.source === props.self ? rel.target : rel.source
              const other = () => props.driver?.engine.entity(otherId)
              return (
                <li class="flex items-center gap-2 text-13-regular">
                  <span class="shrink-0 text-text-weak">
                    {language.t(`security.graph.relation.${rel.relation}` as Key)}
                  </span>
                  <button
                    type="button"
                    class="min-w-0 cursor-pointer truncate border-0 bg-transparent p-0 text-left text-text-interactive-base hover:underline"
                    style={{ "line-height": "var(--line-height-compact)" }}
                    onClick={() => props.driver?.focusEntity(otherId)}
                  >
                    {other()?.name ?? otherId}
                  </button>
                </li>
              )
            }}
          </For>
        </ul>
      </div>
    </Show>
  )
}

function Action(props: { label: string; run?: (entity: Entity) => void; entity: Entity }) {
  const language = useLanguage()
  return (
    <Tooltip
      value={language.t("security.graph.inspector.action.unavailable")}
      inactive={props.run !== undefined}
    >
      {/* A disabled button gets no pointer events, so the wrapper carries the tooltip trigger. */}
      <span class="inline-flex">
        <Button
          size="small"
          disabled={props.run === undefined}
          onClick={() => props.run?.(props.entity)}
        >
          {language.t(props.label as Key)}
        </Button>
      </span>
    </Tooltip>
  )
}
