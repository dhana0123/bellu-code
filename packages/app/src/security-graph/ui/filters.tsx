import { createEffect, createMemo, createSignal, createUniqueId, For, onCleanup, Show } from "solid-js"
import { Button } from "@bellucode/ui/button"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import { createFilter, options } from "../filters"
import type { GraphData } from "../model"
import { activeFilterCount, filterDimensions, type FilterDimension, type ViewStore } from "./store"

type Key = Parameters<ReturnType<typeof useLanguage>["t"]>[0]
type PluralKey = Parameters<ReturnType<typeof useLanguage>["plural"]>[0]

export type FiltersProps = {
  store: ViewStore
  /** Receives the predicate whenever the store filters or the agent state change. */
  driver: Driver
  /** Current graph data. The option lists follow it. */
  data: () => GraphData
}

const titles: Record<FilterDimension, string> = {
  repository: "security.graph.filters.repository",
  service: "security.graph.filters.service",
  environment: "security.graph.filters.environment",
  type: "security.graph.filters.nodeType",
  tag: "security.graph.filters.tag",
  severity: "security.graph.filters.severity",
  boundary: "security.graph.filters.boundary",
  agent: "security.graph.filters.agent",
}

// Entity types that have a localized label. The rest show their id.
const typeLabels: Record<string, string> = {
  api: "security.graph.type.api",
  module: "security.graph.type.module",
  service: "security.graph.type.service",
  dependency: "security.graph.type.dependency",
  "data-model": "security.graph.type.dataModel",
  framework: "security.graph.type.framework",
  "cloud-resource": "security.graph.type.cloud",
  file: "security.graph.type.file",
  function: "security.graph.type.function",
  vulnerability: "security.graph.type.vulnerability",
  "ai-agent": "security.graph.type.agent",
  "external-service": "security.graph.type.external",
}

export function Filters(props: FiltersProps) {
  const language = useLanguage()
  const t = (key: string) => language.t(key as Key)
  const id = createUniqueId()
  const [open, setOpen] = createSignal<Partial<Record<FilterDimension, boolean>>>({})
  const state = props.store.state
  const all = createMemo(() => options(props.data(), state.agents))
  const total = () => activeFilterCount(state.filters)

  const label = (dimension: FilterDimension, value: string, text: string) => {
    if (dimension === "severity") return t(`security.graph.severity.${value}`)
    if (dimension === "type") return typeLabels[value] ? t(typeLabels[value]) : text
    return text
  }

  createEffect(() => {
    // createFilter reads every selected value now, so the effect re-runs when any of them changes.
    props.driver.setFilter(createFilter(state.filters, { boundaries: props.data().boundaries, agents: state.agents }))
  })
  onCleanup(() => props.driver.setFilter(undefined))

  const toggle = (dimension: FilterDimension, value: string, checked: boolean) =>
    props.store.setFilter(
      dimension,
      checked ? [...state.filters[dimension], value] : state.filters[dimension].filter((item) => item !== value),
    )

  return (
    <section class="flex min-h-0 flex-col" aria-label={t("security.graph.filters.title")}>
      <header class="flex items-center gap-2 px-3 py-2">
        <h2 class="min-w-0 flex-1 truncate text-14-medium">{t("security.graph.filters.title")}</h2>
        <Show when={total() > 0}>
          <span
            class="rounded-full px-2 text-12-medium"
            style={{ background: "var(--surface-raised-base)" }}
            role="status"
            data-component="security-graph-filter-count"
          >
            {language.plural("security.graph.filtersPanel.active" as PluralKey, total())}
          </span>
        </Show>
        <Button
          size="small"
          variant="ghost"
          disabled={total() === 0}
          aria-label={t("security.graph.filters.clear")}
          onClick={() => props.store.clearFilters()}
        >
          {t("security.graph.filters.clear")}
        </Button>
      </header>
      <div class="min-h-0 flex-1 overflow-y-auto px-3 pb-3" data-scrollable>
        <For each={filterDimensions}>
          {(dimension) => {
            const panel = `${id}-${dimension}`
            const selected = () => state.filters[dimension].length
            return (
              <div class="border-b border-border-weak-base last:border-b-0">
                <button
                  type="button"
                  class="flex w-full items-center gap-2 py-2 text-left text-13-medium"
                  style={{ "line-height": "var(--line-height-compact)" }}
                  aria-expanded={open()[dimension] === true}
                  aria-controls={panel}
                  onClick={() => setOpen((prev) => ({ ...prev, [dimension]: !prev[dimension] }))}
                >
                  <span aria-hidden="true" class="w-3 shrink-0">
                    {open()[dimension] ? "▾" : "▸"}
                  </span>
                  <span class="min-w-0 flex-1 truncate">{t(titles[dimension])}</span>
                  <Show when={selected() > 0}>
                    <span class="rounded-full px-2 text-12-medium" style={{ background: "var(--surface-raised-base)" }}>
                      {selected()}
                    </span>
                  </Show>
                </button>
                <Show when={open()[dimension] === true}>
                  <ul id={panel} class="flex flex-col pb-2" role="group" aria-label={t(titles[dimension])}>
                    <For each={all()[dimension]}>
                      {(option) => (
                        <li>
                          <label
                            class="flex cursor-pointer items-center gap-2 py-1 text-13-regular"
                            style={{ "line-height": "var(--line-height-base)" }}
                          >
                            <input
                              type="checkbox"
                              checked={state.filters[dimension].includes(option.value)}
                              onChange={(event) => toggle(dimension, option.value, event.currentTarget.checked)}
                            />
                            <span class="min-w-0 flex-1 truncate">{label(dimension, option.value, option.label)}</span>
                            <span class="text-12-regular text-text-weak">{option.count}</span>
                          </label>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </div>
            )
          }}
        </For>
      </div>
    </section>
  )
}
