import { createSignal, For, onCleanup, Show, createEffect } from "solid-js"
import { IconButton } from "@bellucode/ui/icon-button"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { Model } from "../machine"
import { selectCanBack, selectCanForward } from "./graph-view"
export type BreadcrumbProps = {
  /** The driver of the loaded graph, or `undefined` while none is loaded. */
  driver: Driver | undefined
}
// Chains longer than this keep the first crumb and the last ones, and fold the middle behind an ellipsis.
const maxCrumbs = 5
const keepTail = 3
// The entity the history currently points at.
export const selectFocused = (model: Model) => model.history.entries[model.history.index]?.id
type Crumb = { id?: string; label: string }
export function Breadcrumb(props: BreadcrumbProps) {
  const language = useLanguage()
  const [model, setModel] = createSignal<Model | undefined>()
  createEffect(() => {
    const driver = props.driver
    setModel(driver?.state())
    if (!driver) return
    onCleanup(driver.onState(setModel))
  })
  const chain = (): Crumb[] => {
    const driver = props.driver
    const current = model()
    const root: Crumb = { label: language.t("security.graph.breadcrumb.root") }
    const id = current ? selectFocused(current) : undefined
    if (!driver || !id) return [root]
    const ids = [...driver.engine.ancestors(id).reverse(), id]
    return [root, ...ids.map((item) => ({ id: item, label: driver.engine.entity(item)?.name ?? item }))]
  }
  const shown = () => {
    const all = chain()
    if (all.length <= maxCrumbs) return all.map((crumb) => ({ crumb, folded: false }))
    return [
      { crumb: all[0], folded: false },
      { crumb: { label: "…" }, folded: true },
      ...all.slice(all.length - keepTail).map((crumb) => ({ crumb, folded: false })),
    ]
  }
  const full = () => chain().map((crumb) => crumb.label).join(" > ")
  const last = () => chain().length - 1
  return (
    <div class="flex min-w-0 items-center gap-1">
      <IconButton
        icon="arrow-left"
        variant="ghost"
        aria-label={language.t("security.graph.breadcrumb.back")}
        disabled={!props.driver || !selectCanBack(model() ?? props.driver.state())}
        onClick={() => props.driver?.back()}
      />
      <IconButton
        icon="arrow-right"
        variant="ghost"
        aria-label={language.t("security.graph.breadcrumb.forward")}
        disabled={!props.driver || !selectCanForward(model() ?? props.driver.state())}
        onClick={() => props.driver?.forward()}
      />
      <nav aria-label={language.t("security.graph.breadcrumb.label")} class="min-w-0" title={full()}>
        <ol class="flex min-w-0 items-center gap-1 text-13-regular leading-[var(--line-height-compact)]">
          <For each={shown()}>
            {(item, index) => (
              <>
                <Show when={index() > 0}>
                  <li aria-hidden="true" class="shrink-0 text-text-weak">
                    ›
                  </li>
                </Show>
                <li class="min-w-0 truncate" classList={{ "shrink-0": item.folded }}>
                  <Show
                    when={item.crumb.id !== undefined && !item.folded}
                    fallback={
                      <span
                        class="text-text-weak"
                        classList={{ "text-text-strong": !item.folded && item.crumb === chain()[last()] }}
                        aria-current={!item.folded && item.crumb === chain()[last()] ? "location" : undefined}
                      >
                        {item.crumb.label}
                      </span>
                    }
                  >
                    <button
                      type="button"
                      class="max-w-40 truncate rounded-sm text-text-base hover:text-text-strong focus-visible:outline-2"
                      title={item.crumb.label}
                      onClick={() => props.driver?.focusEntity(item.crumb.id!)}
                    >
                      {item.crumb.label}
                    </button>
                  </Show>
                </li>
              </>
            )}
          </For>
        </ol>
      </nav>
    </div>
  )
}
