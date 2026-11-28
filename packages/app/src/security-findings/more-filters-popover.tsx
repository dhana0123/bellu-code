import { createEffect, createSignal, For, onCleanup, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { categoryLabelKey, statusLabelKey, typeLabelKey } from "./badges"
import { Glyph } from "./glyph"
import {
  CATEGORIES,
  FINDING_TYPES,
  STATUSES,
  type Category,
  type FilterState,
  type FindingType,
  type Status,
} from "./model"
type Draft = {
  types: FindingType[]
  statuses: Status[]
  categories: Category[]
}
const FOCUSABLE = "input, button:not([disabled]), [href], [tabindex]:not([tabindex='-1'])"

export const selectedCount = (filters: Draft) =>
  filters.types.length + filters.statuses.length + filters.categories.length

/**
 * The "More filters" panel. Choices stay in a draft until Apply, so closing the panel discards them. On narrow screens
 * it is a bottom sheet. Focus stays inside while it is open, and Esc closes it and returns focus to the button.
 */
export function MoreFiltersPopover(props: { filters: FilterState; onApply: (patch: Partial<FilterState>) => void }) {
  const language = useLanguage()
  const [open, setOpen] = createSignal(false)
  const [draft, setDraft] = createStore<Draft>({ types: [], statuses: [], categories: [] })
  let trigger!: HTMLButtonElement
  let panel: HTMLDivElement | undefined

  const applied = () => selectedCount(props.filters)

  const show = () => {
    setDraft({
      types: [...props.filters.types],
      statuses: [...props.filters.statuses],
      categories: [...props.filters.categories],
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
              legend={language.t("security.findings.more.type")}
              options={FINDING_TYPES.map((value) => ({ value, label: language.t(typeLabelKey(value)) }))}
              selected={draft.types}
              onChange={(next) => setDraft("types", next)}
            />
            <Group
              legend={language.t("security.findings.more.status")}
              options={STATUSES.map((value) => ({ value, label: language.t(statusLabelKey(value)) }))}
              selected={draft.statuses}
              onChange={(next) => setDraft("statuses", next)}
            />
            <Group
              legend={language.t("security.findings.more.category")}
              options={CATEGORIES.map((value) => ({ value, label: language.t(categoryLabelKey(value)) }))}
              selected={draft.categories}
              onChange={(next) => setDraft("categories", next)}
            />
          </div>
          <div data-slot="popover-footer">
            <button
              type="button"
              class="sf-button"
              data-variant="text"
              onClick={() => setDraft({ types: [], statuses: [], categories: [] })}
            >
              {language.t("security.findings.clearAll")}
            </button>
            <button
              type="button"
              class="sf-button"
              data-variant="primary"
              onClick={() => {
                props.onApply({
                  types: [...draft.types],
                  statuses: [...draft.statuses],
                  categories: [...draft.categories],
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
