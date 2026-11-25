import { createMemo, For, Show } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { categoryLabelKey, severityLabelKey, statusLabelKey, typeLabelKey } from "./badges"
import { Glyph } from "./glyph"
import type { FilterState, ViewMode } from "./model"
import { Segmented } from "./segmented"
import { hasActiveFilters } from "./use-filters"

type Chip = { key: string; label: string; remove: () => void }

/** The applied filters as removable chips, plus the Table and Treemap switch, which is always visible. */
export function ActiveFilters(props: {
  filters: FilterState
  view: ViewMode
  onChange: (patch: Partial<FilterState>) => void
  onClear: () => void
  onView: (view: ViewMode) => void
}) {
  const language = useLanguage()

  const chips = createMemo<Chip[]>(() => {
    const filters = props.filters
    return [
      ...(filters.search
        ? [
            {
              key: "search",
              label: language.t("security.findings.chip.search", { value: filters.search }),
              remove: () => props.onChange({ search: "" }),
            },
          ]
        : []),
      ...(filters.severity === "all"
        ? []
        : [
            {
              key: "severity",
              label: language.t("security.findings.chip.severity", {
                value: language.t(severityLabelKey(filters.severity)),
              }),
              remove: () => props.onChange({ severity: "all" }),
            },
          ]),
      ...filters.types.map((value) => ({
        key: `type-${value}`,
        label: language.t("security.findings.chip.type", { value: language.t(typeLabelKey(value)) }),
        remove: () => props.onChange({ types: filters.types.filter((item) => item !== value) }),
      })),
      ...filters.statuses.map((value) => ({
        key: `status-${value}`,
        label: language.t("security.findings.chip.status", { value: language.t(statusLabelKey(value)) }),
        remove: () => props.onChange({ statuses: filters.statuses.filter((item) => item !== value) }),
      })),
      ...filters.categories.map((value) => ({
        key: `cat-${value}`,
        label: language.t("security.findings.chip.category", { value: language.t(categoryLabelKey(value)) }),
        remove: () => props.onChange({ categories: filters.categories.filter((item) => item !== value) }),
      })),
      ...(filters.asset
        ? [
            {
              key: "asset",
              label: language.t("security.findings.chip.asset", { value: filters.asset }),
              remove: () => props.onChange({ asset: undefined }),
            },
          ]
        : []),
    ]
  })

  return (
    <div data-slot="active-filters">
      <ul data-slot="chips" aria-label={language.t("security.findings.active.label")}>
        <Show when={hasActiveFilters(props.filters)}>
          <For each={chips()}>
            {(chip) => (
              <li data-slot="filter-chip">
                {chip.label}
                <button
                  type="button"
                  aria-label={language.t("security.findings.chip.remove", { name: chip.label })}
                  onClick={() => chip.remove()}
                >
                  <Glyph name="close" size={12} />
                </button>
              </li>
            )}
          </For>
          <li>
            <button type="button" data-slot="link" onClick={() => props.onClear()}>
              {language.t("security.findings.clearAll")}
            </button>
          </li>
        </Show>
      </ul>
      <Segmented
        name="security-findings-view"
        label={language.t("security.findings.view.label")}
        value={props.view}
        options={[
          { value: "table", label: language.t("security.findings.view.table") },
          { value: "treemap", label: language.t("security.findings.view.treemap") },
        ]}
        onChange={props.onView}
      />
    </div>
  )
}
