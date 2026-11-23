import { createMemo, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { severityLabelKey } from "./badges"
import type { TreemapGroup } from "./filters"
import { squarify } from "./treemap-layout"

// The map is laid out in a 100 by 50 box and drawn with percentages, so it scales with its container.
const WIDTH = 100
const HEIGHT = 50

/** Boxes grouped by component, sized by critical plus high findings and colored by the worst severity. */
export function TreemapView(props: { groups: TreemapGroup[]; onSelect: (componentId: string) => void }) {
  const language = useLanguage()
  const [hover, setHover] = createStore<{ id?: string; x: number; y: number }>({ x: 0, y: 0 })
  const boxes = createMemo(() => {
    const rects = squarify(
      props.groups.map((group) => group.value),
      WIDTH,
      HEIGHT,
    )
    return props.groups.map((group, index) => ({ group, rect: rects[index] }))
  })
  const active = () => boxes().find((box) => box.group.component.id === hover.id)?.group

  return (
    <div data-slot="treemap-card">
      <Show
        when={props.groups.length > 0}
        fallback={<p data-slot="card-empty">{language.t("security.findings.treemap.empty")}</p>}
      >
        <div data-slot="treemap" role="list" aria-label={language.t("security.findings.treemap.label")}>
          <For each={boxes()}>
            {(box) => (
              <button
                type="button"
                role="listitem"
                data-severity={box.group.top}
                style={{
                  left: `${(box.rect.x / WIDTH) * 100}%`,
                  top: `${(box.rect.y / HEIGHT) * 100}%`,
                  width: `${(box.rect.w / WIDTH) * 100}%`,
                  height: `${(box.rect.h / HEIGHT) * 100}%`,
                }}
                aria-label={describe(language, box.group)}
                onClick={() => props.onSelect(box.group.component.id)}
                onPointerMove={(event) => {
                  const bounds = event.currentTarget.parentElement!.getBoundingClientRect()
                  setHover({
                    id: box.group.component.id,
                    x: event.clientX - bounds.left,
                    y: event.clientY - bounds.top,
                  })
                }}
                onPointerLeave={() => setHover("id", undefined)}
                onFocus={(event) => {
                  const bounds = event.currentTarget.parentElement!.getBoundingClientRect()
                  const target = event.currentTarget.getBoundingClientRect()
                  setHover({
                    id: box.group.component.id,
                    x: target.left - bounds.left + 8,
                    y: target.top - bounds.top + 8,
                  })
                }}
                onBlur={() => setHover("id", undefined)}
              >
                <span data-slot="box-name">{box.group.component.name}</span>
                <span data-slot="box-meta">
                  {language.t(severityLabelKey(box.group.top))} · {box.group.value.toLocaleString()}
                </span>
              </button>
            )}
          </For>
          <Show when={active()}>
            {(group) => (
              <div data-slot="tooltip" role="tooltip" style={{ left: `${hover.x + 12}px`, top: `${hover.y + 12}px` }}>
                <strong>
                  {group().component.name} {group().component.version}
                </strong>
                <span>
                  {language.t("security.findings.treemap.critical", { count: group().critical.toLocaleString() })}
                </span>
                <span>{language.t("security.findings.treemap.high", { count: group().high.toLocaleString() })}</span>
              </div>
            )}
          </Show>
        </div>
      </Show>
    </div>
  )
}

function describe(language: ReturnType<typeof useLanguage>, group: TreemapGroup) {
  return language.t("security.findings.treemap.box", {
    name: group.component.name,
    version: group.component.version,
    critical: group.critical.toLocaleString(),
    high: group.high.toLocaleString(),
  })
}
