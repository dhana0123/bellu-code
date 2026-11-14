import { createEffect, createMemo, createSignal, For, on, Show } from "solid-js"
import { Icon } from "@bellucode/ui/icon"
import { IconButton } from "@bellucode/ui/icon-button"
import { MenuScroll } from "@bellucode/ui/menu-scroll"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { ViewStore } from "./store"
export type SearchProps = {
  /** The driver of the loaded graph, or `undefined` while none is loaded. */
  driver: Driver | undefined
  store: ViewStore
}
const limit = 20
const listId = "security-graph-search-list"
const optionId = (index: number) => `security-graph-search-option-${index}`
export function Search(props: SearchProps) {
  const language = useLanguage()
  const [open, setOpen] = createSignal(false)
  const [active, setActive] = createSignal(0)
  let viewport: HTMLDivElement | undefined
  const query = () => props.store.state.query
  const results = createMemo(() => {
    const driver = props.driver
    if (!driver || !query().trim()) return []
    return driver.engine.search(query(), limit).map((entity) => ({
      id: entity.id,
      name: entity.name,
      type: entity.type,
      path: driver.engine
        .ancestors(entity.id)
        .reverse()
        .map((id) => driver.engine.entity(id)?.name ?? id),
    }))
  })
  createEffect(on(query, () => setActive(0)))
  // Keep the active option in view for keyboard users.
  createEffect(() => {
    if (!open()) return
    viewport?.querySelector<HTMLElement>(`#${optionId(active())}`)?.scrollIntoView({ block: "nearest" })
  })
  const kind = (type: string) => language.t(`security.graph.tooltip.kind.${type}` as Parameters<typeof language.t>[0])
  const choose = (id: string) => {
    props.driver?.focusEntity(id)
    props.store.focus(id)
    setOpen(false)
  }
  const onKeyDown = (event: KeyboardEvent) => {
    const count = results().length
    if (event.key === "ArrowDown") {
      event.preventDefault()
      if (!open()) return setOpen(true)
      if (count > 0) setActive((active() + 1) % count)
    } else if (event.key === "ArrowUp") {
      event.preventDefault()
      if (!open()) return setOpen(true)
      if (count > 0) setActive((active() - 1 + count) % count)
    } else if (event.key === "Enter") {
      const item = results()[active()]
      if (open() && item) {
        event.preventDefault()
        choose(item.id)
      }
    } else if (event.key === "Escape") {
      if (open()) {
        event.preventDefault()
        event.stopPropagation()
        setOpen(false)
      } else if (query()) {
        event.stopPropagation()
        props.store.setQuery("")
      }
    }
  }
  const showList = () => open() && props.driver !== undefined
  return (
    <div class="relative w-full max-w-80">
      <div class="flex items-center gap-1.5 rounded-md border border-border-weak-base bg-surface-raised-base px-2 focus-within:border-border-focus-base">
        <Icon name="magnifying-glass" size="small" class="shrink-0 text-icon-weak" />
        <input
          type="text"
          role="combobox"
          aria-label={language.t("security.graph.search.label")}
          aria-expanded={showList()}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={showList() && results().length > 0 ? optionId(active()) : undefined}
          class="h-8 min-w-0 flex-1 bg-transparent text-13-regular text-text-strong outline-none placeholder:text-text-weak"
          placeholder={language.t("security.graph.search.placeholder")}
          value={query()}
          onInput={(event) => {
            props.store.setQuery(event.currentTarget.value)
            setOpen(true)
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setOpen(false)}
          onKeyDown={onKeyDown}
        />
        <Show when={query()}>
          <IconButton
            icon="close"
            variant="ghost"
            tabIndex={-1}
            aria-label={language.t("security.graph.search.clear")}
            // Keep focus in the input so the list does not close before the click lands.
            onMouseDown={(event: MouseEvent) => event.preventDefault()}
            onClick={() => props.store.setQuery("")}
          />
        </Show>
      </div>
      <Show when={showList()}>
        <div class="absolute left-0 right-0 top-full z-20 mt-1 rounded-md border border-border-weak-base bg-surface-raised-base shadow-md">
          <MenuScroll class="max-h-72" viewportClass="p-1" viewportRef={(element) => (viewport = element)}>
            <ul id={listId} role="listbox" aria-label={language.t("security.graph.search.results")}>
              <For each={results()}>
                {(item, index) => (
                  <li
                    id={optionId(index())}
                    role="option"
                    aria-selected={index() === active()}
                    class="flex cursor-default flex-col rounded-sm px-2 py-1 leading-[var(--line-height-compact)] data-[active=true]:bg-surface-raised-base-hover"
                    data-active={index() === active()}
                    // Pointer selection must not blur the input first.
                    onMouseDown={(event) => event.preventDefault()}
                    onMouseMove={() => setActive(index())}
                    onClick={() => choose(item.id)}
                  >
                    <span class="flex min-w-0 items-baseline gap-2">
                      <span class="truncate text-13-medium text-text-strong">{item.name}</span>
                      <span class="shrink-0 text-12-regular text-text-weak">{kind(item.type)}</span>
                    </span>
                    <Show when={item.path.length > 0}>
                      <span class="truncate text-12-regular text-text-weak" title={item.path.join(" > ")}>
                        {item.path.join(" > ")}
                      </span>
                    </Show>
                  </li>
                )}
              </For>
            </ul>
            <Show when={results().length === 0}>
              <div class="px-2 py-2 text-12-regular text-text-weak" role="status">
                {query().trim() ? language.t("security.graph.empty.search") : language.t("security.graph.searchBox.hint")}
              </div>
            </Show>
          </MenuScroll>
        </div>
      </Show>
    </div>
  )
}
