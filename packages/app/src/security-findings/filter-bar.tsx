import { createEffect, createSignal, on, onCleanup, Show } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { severityLabelKey } from "./badges"
import { Glyph } from "./glyph"
import { MoreFiltersPopover } from "./more-filters-popover"
import { SEVERITIES, type FilterState } from "./model"
import { Segmented } from "./segmented"

const DEBOUNCE_MS = 250

/** One search box, a severity control, two switches and a single "More filters" panel. */
export function FilterBar(props: {
  filters: FilterState
  count: number
  loading: boolean
  onChange: (patch: Partial<FilterState>) => void
  onRefresh: () => void
}) {
  const language = useLanguage()
  const [text, setText] = createSignal(props.filters.search)
  // The last value this box wrote or read. It keeps a URL update that echoes our own write from resetting the field.
  let committed = props.filters.search
  let timer: ReturnType<typeof setTimeout> | undefined

  const commit = (value: string) => {
    clearTimeout(timer)
    committed = value
    props.onChange({ search: value })
  }

  createEffect(
    on(
      () => props.filters.search,
      (value) => {
        if (value === committed) return
        clearTimeout(timer)
        committed = value
        setText(value)
      },
      { defer: true },
    ),
  )
  onCleanup(() => clearTimeout(timer))

  return (
    <div data-slot="filter-bar">
      <label data-slot="search">
        <Glyph name="search" />
        <input
          type="text"
          value={text()}
          placeholder={language.t("security.findings.filter.search.placeholder")}
          aria-label={language.t("security.findings.filter.search.label")}
          onInput={(event) => {
            setText(event.currentTarget.value)
            clearTimeout(timer)
            timer = setTimeout(() => commit(text()), DEBOUNCE_MS)
          }}
        />
        <Show when={text() !== ""}>
          <button
            type="button"
            aria-label={language.t("security.findings.filter.search.clear")}
            onClick={() => {
              setText("")
              commit("")
            }}
          >
            <Glyph name="close" size={14} />
          </button>
        </Show>
      </label>
      <Segmented
        name="security-findings-severity"
        label={language.t("security.findings.filter.severity")}
        value={props.filters.severity}
        options={[
          { value: "all", label: language.t("security.findings.filter.all") },
          ...SEVERITIES.map((severity) => ({
            value: severity,
            label: language.t(severityLabelKey(severity)),
            dot: severity,
          })),
        ]}
        onChange={(severity) => props.onChange({ severity })}
      />
      <Toggle
        label={language.t("security.findings.filter.hasFix")}
        checked={props.filters.hasFix}
        onChange={(hasFix) => props.onChange({ hasFix })}
      />
      <Toggle
        label={language.t("security.findings.filter.hasExploit")}
        checked={props.filters.hasExploit}
        onChange={(hasExploit) => props.onChange({ hasExploit })}
      />
      <MoreFiltersPopover filters={props.filters} onApply={props.onChange} />
      <div data-slot="filter-result">
        <span role="status" aria-live="polite">
          {props.loading
            ? language.t("security.findings.count.loading")
            : language.plural("security.findings.count", props.count, { total: props.count.toLocaleString() })}
        </span>
        <button
          type="button"
          data-slot="icon-button"
          aria-label={language.t("security.findings.filter.refresh")}
          disabled={props.loading}
          onClick={() => props.onRefresh()}
        >
          <Glyph name="refresh" />
        </button>
      </div>
    </div>
  )
}

function Toggle(props: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.checked}
      data-slot="switch"
      onClick={() => props.onChange(!props.checked)}
    >
      <span data-slot="switch-track" aria-hidden="true">
        <span data-slot="switch-thumb" />
      </span>
      {props.label}
    </button>
  )
}
