import { createEffect, createSignal, For, onCleanup, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { resourceTypeLabelKey, severityLabelKey } from "./badges"
import { Glyph } from "./glyph"
import {
  DEPENDENCY_TYPES,
  RESOURCE_TYPES,
  SEVERITIES,
  type DependencyType,
  type FilterState,
  type ResourceType,
  type Severity,
} from "./model"

type Draft = {
  resourceTypes: ResourceType[]
  dependencyTypes: DependencyType[]
  relatedSeverities: Severity[]
}

const FOCUSABLE = "input, button:not([disabled]), [href], [tabindex]:not([tabindex='-1'])"

export const selectedCount = (filters: Draft) =>
  filters.resourceTypes.length + filters.dependencyTypes.length + filters.relatedSeverities.length

/**
 * The "More filters" panel. Choices stay in a draft until Apply, so closing the panel discards them. On narrow screens
 * it is a bottom sheet. Focus stays inside while it is open, and Esc closes it and returns focus to the button.
 */
export function MoreFiltersPopover(props: { filters: FilterState; onApply: (patch: Partial<FilterState>) => void }) {
  const language = useLanguage()
  const [open, setOpen] = createSignal(false)
  const [draft, setDraft] = createStore<Draft>({ resourceTypes: [], dependencyTypes: [], relatedSeverities: [] })
  let trigger!: HTMLButtonElement
  let panel: HTMLDivElement | undefined

  const applied = () => selectedCount(props.filters)

  const show = () => {
    setDraft({
      resourceTypes: [...props.filters.resourceTypes],
      dependencyTypes: [...props.filters.dependencyTypes],
      relatedSeverities: [...props.filters.relatedSeverities],
    })
    setOpen(true)
  }
  const close = (restore: boolean) => {
    setOpen(false)
    if (restore) trigger.focus()
  }

  createEffect(() => {
    if (!open()) return
    queueMicrotask(() => panel?.querySelector<HTMLElement>("input")?.focus({ preventScroll: true }))
    const outside = (event: PointerEvent) => {
      const target = event.target as Node
      if (!panel?.contains(target) && !trigger.contains(target)) close(false)
    }
    document.addEventListener("pointerdown", outside, true)
    onCleanup(() => document.removeEventListener("pointerdown", outside, true))
  })

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      event.preventDefault()
      event.stopPropagation()
      return close(true)
    }
    if (event.key !== "Tab" || !panel) return
    const items = [...panel.querySelectorAll<HTMLElement>(FOCUSABLE)]
    const first = items[0]
    const last = items[items.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    }
    if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  }

  return (
    <div data-slot="more-filters">
      <button
        ref={trigger}
        type="button"
        class="sf-button"
        data-variant="outline"
        aria-haspopup="dialog"
        aria-expanded={open()}
        onClick={() => (open() ? close(false) : show())}
      >
        <Glyph name="sliders" />
        {applied() > 0
          ? language.t("security.findings.more.buttonCount", { count: applied() })
          : language.t("security.findings.more.button")}
      </button>
      <Show when={open()}>
        <div data-slot="sheet-scrim" onClick={() => close(true)} />
        <div
          ref={panel}
          data-slot="popover"
          role="dialog"
          aria-label={language.t("security.findings.more.title")}
          onKeyDown={onKeyDown}
        >
          <div data-slot="popover-body">
            <Group
              legend={language.t("security.findings.more.resourceType")}
              options={RESOURCE_TYPES.map((value) => ({ value, label: language.t(resourceTypeLabelKey(value)) }))}
              selected={draft.resourceTypes}
              onChange={(next) => setDraft("resourceTypes", next)}
            />
            <Group
              legend={language.t("security.findings.more.dependencyType")}
              options={DEPENDENCY_TYPES.map((value) => ({
                value,
                label: language.t(`security.findings.dependency.${value}`),
              }))}
              selected={draft.dependencyTypes}
              onChange={(next) => setDraft("dependencyTypes", next)}
            />
            <Group
              legend={language.t("security.findings.more.relatedSeverity")}
              options={SEVERITIES.map((value) => ({ value, label: language.t(severityLabelKey(value)) }))}
              selected={draft.relatedSeverities}
              onChange={(next) => setDraft("relatedSeverities", next)}
            />
          </div>
          <div data-slot="popover-footer">
            <button
              type="button"
              class="sf-button"
              data-variant="text"
              onClick={() => setDraft({ resourceTypes: [], dependencyTypes: [], relatedSeverities: [] })}
            >
              {language.t("security.findings.clearAll")}
            </button>
            <button
              type="button"
              class="sf-button"
              data-variant="primary"
              onClick={() => {
                props.onApply({
                  resourceTypes: [...draft.resourceTypes],
                  dependencyTypes: [...draft.dependencyTypes],
                  relatedSeverities: [...draft.relatedSeverities],
                })
                close(true)
              }}
            >
              {language.t("security.findings.more.apply")}
            </button>
          </div>
        </div>
      </Show>
    </div>
  )
}

function Group<T extends string>(props: {
  legend: string
  options: { value: T; label: string }[]
  selected: T[]
  onChange: (next: T[]) => void
}) {
  return (
    <fieldset data-slot="group">
      <legend>{props.legend}</legend>
      <For each={props.options}>
        {(option) => (
          <label>
            <input
              type="checkbox"
              checked={props.selected.includes(option.value)}
              onChange={(event) =>
                props.onChange(
                  event.currentTarget.checked
                    ? [...props.selected, option.value]
                    : props.selected.filter((value) => value !== option.value),
                )
              }
            />
            {option.label}
          </label>
        )}
      </For>
    </fieldset>
  )
}
