import { createEffect, For, onCleanup, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { useTheme } from "@bellucode/ui/theme"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { Model } from "../machine"
import { pills, severities } from "../theme"

export type TooltipProps = {
  /** The driver of the loaded graph, or `undefined` while none is loaded. */
  driver: Driver | undefined
  /** The element the pointer moves over. The tooltip is positioned relative to it. */
  container: HTMLElement | undefined
}

const offset = 14
const margin = 8
const width = 240
const maxTags = 3

// Only a settled hover shows a tooltip. Panning, dragging and animations hide it.
export const selectHover = (model: Model) => {
  const state = model.state
  if (state.type === "hovering") return state.id
  return state.type === "selected" ? state.hover : undefined
}

export function Tooltip(props: TooltipProps) {
  const language = useLanguage()
  const theme = useTheme()
  const [at, setAt] = createStore({ x: 0, y: 0, width: 0, height: 0, id: undefined as string | undefined })
  let element: HTMLDivElement | undefined

  createEffect(() => {
    const driver = props.driver
    const container = props.container
    setAt("id", undefined)
    if (!driver || !container) return
    const move = (event: PointerEvent) => {
      const rect = container.getBoundingClientRect()
      setAt({ x: event.clientX - rect.left, y: event.clientY - rect.top, width: rect.width, height: rect.height })
    }
    container.addEventListener("pointermove", move)
    const stop = driver.onState((model) => setAt("id", selectHover(model)))
    onCleanup(() => {
      container.removeEventListener("pointermove", move)
      stop()
    })
  })

  const data = () => {
    const driver = props.driver
    const id = at.id
    if (!driver || !id) return undefined
    const entity = driver.engine.entity(id)
    const node = driver.visible().nodes.find((item) => item.id === id)
    const type = entity?.type ?? node?.type
    if (!type) return undefined
    return {
      type,
      name: entity?.name ?? node?.name ?? id,
      severity: node?.severity ?? entity?.severity,
      tags: (node?.tags ?? entity?.tags.map((tag) => ({ label: tag.label, count: 1 })) ?? []).slice(0, maxTags),
      children: node?.count ?? 0,
    }
  }

  // Flips to the other side of the pointer near the container edges.
  const place = () => {
    const w = Math.min(width, Math.max(0, at.width - margin * 2))
    const h = element?.offsetHeight ?? 0
    const x = at.x + offset + w > at.width - margin ? at.x - offset - w : at.x + offset
    const y = at.y + offset + h > at.height - margin ? at.y - offset - h : at.y + offset
    return `translate(${Math.max(margin, x)}px, ${Math.max(margin, y)}px)`
  }

  return (
    <Show when={data()}>
      {(item) => (
        <div
          ref={element}
          role="tooltip"
          class="pointer-events-none absolute left-0 top-0 z-10 rounded-md border border-border-weak-base bg-surface-raised-base px-2 py-1.5 text-12-regular text-text-base shadow-md"
          style={{ transform: place(), width: `${width}px`, "max-width": `calc(100% - ${margin * 2}px)` }}
        >
          <div class="truncate text-13-medium text-text-strong leading-[var(--line-height-compact)]">{item().name}</div>
          <div class="truncate text-text-weak leading-[var(--line-height-compact)]">
            {language.t(`security.graph.tooltip.kind.${item().type}` as Parameters<typeof language.t>[0])}
          </div>
          <Show when={item().severity}>
            {(severity) => (
              <div class="flex items-center gap-1.5 leading-[var(--line-height-compact)]">
                <span class="size-2 shrink-0 rounded-full" style={{ background: severities[severity()].color }} aria-hidden="true" />
                <span class="sr-only">{language.t("security.graph.tooltip.severity")}: </span>
                {language.t(`security.graph.severity.${severity()}` as Parameters<typeof language.t>[0])}
              </div>
            )}
          </Show>
          <Show when={item().tags.length > 0}>
            <div class="mt-1 flex flex-wrap gap-1" aria-label={language.t("security.graph.tooltip.tags")}>
              <For each={item().tags}>
                {(tag) => (
                  <span
                    class="rounded-sm border px-1 text-11-regular leading-[var(--line-height-compact)]"
                    style={{
                      background: pills[theme.mode()].risk.bg,
                      color: pills[theme.mode()].risk.text,
                      "border-color": pills[theme.mode()].risk.border,
                    }}
                  >
                    {tag.count > 1 ? `${tag.label} ${tag.count}` : tag.label}
                  </span>
                )}
              </For>
            </div>
          </Show>
          <Show when={item().children > 0}>
            <div class="mt-1 text-text-weak leading-[var(--line-height-compact)]">
              {language.plural("security.graph.tooltip.childCount", item().children)}
            </div>
          </Show>
        </div>
      )}
    </Show>
  )
}
