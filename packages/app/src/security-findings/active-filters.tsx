import { createMemo, For, Show } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { resourceTypeLabelKey, severityLabelKey } from "./badges"
import { Glyph } from "./glyph"
import type { FilterState, ViewMode } from "./model"
import { Segmented } from "./segmented"
import { hasActiveFilters } from "./use-filters"

type Chip = { key: string; label: string; remove: () => void }

/** The applied filters as removable chips, plus the Table and Treemap switch, which is always visible. */
export function ActiveFilters(props: {
  filters: FilterState
  componentLabel?: string
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
      ...(filters.hasFix
        ? [
            {
              key: "fix",
              label: language.t("security.findings.filter.hasFix"),
              remove: () => props.onChange({ hasFix: false }),
            },
          ]
        : []),
      ...(filters.hasExploit
        ? [
            {
              key: "exploit",
              label: language.t("security.findings.filter.hasExploit"),
              remove: () => props.onChange({ hasExploit: false }),
            },
          ]
        : []),
      ...filters.resourceTypes.map((value) => ({
        key: `res-${value}`,
        label: language.t("security.findings.chip.resource", { value: language.t(resourceTypeLabelKey(value)) }),
        remove: () => props.onChange({ resourceTypes: filters.resourceTypes.filter((item) => item !== value) }),
      })),
      ...filters.dependencyTypes.map((value) => ({
        key: `dep-${value}`,
        label: language.t("security.findings.chip.dependency", {
          value: language.t(`security.findings.dependency.${value}`),
        }),
        remove: () => props.onChange({ dependencyTypes: filters.dependencyTypes.filter((item) => item !== value) }),
      })),
      ...filters.relatedSeverities.map((value) => ({
        key: `rel-${value}`,
        label: language.t("security.findings.chip.related", { value: language.t(severityLabelKey(value)) }),
        remove: () => props.onChange({ relatedSeverities: filters.relatedSeverities.filter((item) => item !== value) }),
      })),
      ...(filters.component
        ? [
            {
              key: "component",
              label: language.t("security.findings.chip.component", {
                value: props.componentLabel ?? filters.component,
              }),
              remove: () => props.onChange({ component: undefined }),
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
