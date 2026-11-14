// The Security Graph page: the graph is the primary surface, with docked, resizable panels around it. Inspector on
// the right, Activity and Filters on the left, and slots for the editor (right of the Inspector) and the terminal
// (below the graph) so they stay reachable. Sizes live in the view store.
import { createEffect, createMemo, createSignal, onCleanup, Show, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { Button } from "@bellucode/ui/button"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { GraphData } from "../model"
import { createMockStream } from "../mock/stream"
import type { Renderer } from "../render/sigma"
import { zoomLevel, type ZoomLevelKey } from "../theme"
import { Activity } from "./activity"
import { AttackPaths } from "./attack-paths"
import { Breadcrumb } from "./breadcrumb"
import { ExportMenu } from "./export-menu"
import { Filters } from "./filters"
import { GraphView } from "./graph-view"
import { Inspector } from "./inspector"
import { Minimap } from "./minimap"
import { Search } from "./search"
import { createViewStore, type PanelId } from "./store"
import { Tooltip } from "./tooltip"

// Agent events arrive this far apart, so motion on the graph is paced and readable.
const liveDelayMs = 600
const keyStep = 16
const keyStepLarge = 64
const limits = {
  inspector: { min: 240, max: 640 },
  activity: { min: 200, max: 560 },
  editor: { min: 280, max: 960 },
  terminal: { min: 120, max: 640 },
} as const satisfies Record<PanelId, { min: number; max: number }>

type Ready = { container: HTMLElement; renderer: Renderer; driver: Driver; data: GraphData }

export type SecurityGraphPageProps = {
  /** Editor panel content. The toolbar shows its toggle only when given. */
  editor?: JSX.Element
  /** Terminal panel content. The toolbar shows its toggle only when given. */
  terminal?: JSX.Element
  /** Extra toolbar content at the start, for example a back button. */
  headerAction?: JSX.Element
}

export function SecurityGraphPage(props: SecurityGraphPageProps) {
  const language = useLanguage()
  const view = createViewStore()
  const [ready, setReady] = createSignal<Ready | undefined>()
  const [open, setOpen] = createStore({
    inspector: true,
    activity: true,
    filters: true,
    minimap: true,
    editor: false,
    terminal: false,
  })
  const [level, setLevel] = createSignal<ZoomLevelKey>("L1")

  createEffect(() => {
    const driver = ready()?.driver
    view.select(undefined)
    view.showAttackPaths([])
    if (!driver) return
    setLevel("L1")
    onCleanup(driver.onSelect((id) => view.select(id)))
    onCleanup(driver.onViewport((viewport) => setLevel(zoomLevel(viewport.scale))))
  })

  // One paced stream per loaded graph, so Activity restarts its agents only when the graph changes.
  const stream = createMemo(() => {
    const current = ready()
    return current ? createMockStream(current.data, liveDelayMs) : undefined
  })
  const leftOpen = () => open.activity || open.filters
  const base = () => ({ focus: [], paths: view.state.selectedPathId ? [view.state.selectedPathId] : [] })

  return (
    <div class="flex min-h-0 min-w-0 flex-1 flex-col" data-component="security-graph-page">
      <div
        class="flex shrink-0 flex-wrap items-center gap-2 px-3 py-2"
        role="toolbar"
        aria-label={language.t("security.graph.panels.toolbar")}
      >
        {props.headerAction}
        <Search driver={ready()?.driver} store={view} />
        <Breadcrumb driver={ready()?.driver} />
        <div class="flex-1" />
        <Toggle label={language.t("security.graph.toolbar.activity")} on={open.activity} set={(on) => setOpen("activity", on)} />
        <Toggle label={language.t("security.graph.toolbar.filters")} on={open.filters} set={(on) => setOpen("filters", on)} />
        <Toggle label={language.t("security.graph.toolbar.inspector")} on={open.inspector} set={(on) => setOpen("inspector", on)} />
        <Toggle label={language.t("security.graph.toolbar.minimap")} on={open.minimap} set={(on) => setOpen("minimap", on)} />
        <Show when={props.editor}>
          <Toggle label={language.t("security.graph.panels.editor")} on={open.editor} set={(on) => setOpen("editor", on)} />
        </Show>
        <Show when={props.terminal}>
          <Toggle label={language.t("security.graph.panels.terminal")} on={open.terminal} set={(on) => setOpen("terminal", on)} />
        </Show>
        <Show when={ready()}>
          {(current) => <ExportMenu driver={current().driver} container={() => current().container} renderer={current().renderer} />}
        </Show>
      </div>
      <div class="flex min-h-0 flex-1">
        <Show when={leftOpen()}>
          <aside
            class="flex min-h-0 shrink-0 flex-col"
            style={{ width: `${view.state.panels.activity}px` }}
            aria-label={language.t("security.graph.panels.activity")}
          >
            <Show when={ready()}>
              {(current) => (
                <>
                  <Show when={open.activity}>
                    <div class="min-h-0 flex-1 overflow-y-auto" data-scrollable>
                      <Activity
                        stream={stream()!}
                        engine={current().driver.engine}
                        driver={current().driver}
                        level={level()}
                        base={base}
                        onAgents={view.setAgents}
                      />
                    </div>
                  </Show>
                  <Show when={open.filters}>
                    <div class="min-h-0 flex-1 overflow-y-auto" data-scrollable>
                      <Filters store={view} driver={current().driver} data={() => current().data} />
                    </div>
                  </Show>
                </>
              )}
            </Show>
          </aside>
          <Separator
            label={language.t("security.graph.panels.resizeSidebar")}
            orientation="vertical"
            panel="activity"
            direction={1}
            value={view.state.panels.activity}
            onChange={(size) => view.resizePanel("activity", size)}
          />
        </Show>
        <div class="flex min-h-0 min-w-0 flex-1 flex-col">
          <div class="relative flex min-h-0 min-w-0 flex-1 flex-col">
            <GraphView
              onDriver={(driver) => {
                if (!driver) setReady(undefined)
              }}
              onReady={setReady}
            />
            <Show when={ready()}>
              {(current) => (
                <>
                  <Show when={open.minimap}>
                    <div class="absolute right-3 top-14">
                      <Minimap driver={current().driver} />
                    </div>
                  </Show>
                  <Tooltip driver={current().driver} container={current().container} />
                </>
              )}
            </Show>
          </div>
          <Show when={props.terminal && open.terminal}>
            <Separator
              label={language.t("security.graph.panels.resizeTerminal")}
              orientation="horizontal"
              panel="terminal"
              direction={-1}
              value={view.state.panels.terminal}
              onChange={(size) => view.resizePanel("terminal", size)}
            />
            <section
              class="min-h-0 shrink-0 overflow-hidden"
              style={{ height: `${view.state.panels.terminal}px` }}
              aria-label={language.t("security.graph.panels.terminal")}
            >
              {props.terminal}
            </section>
          </Show>
        </div>
        <Show when={open.inspector}>
          <Separator
            label={language.t("security.graph.panels.resizeInspector")}
            orientation="vertical"
            panel="inspector"
            direction={-1}
            value={view.state.panels.inspector}
            onChange={(size) => view.resizePanel("inspector", size)}
          />
          <aside class="flex min-h-0 shrink-0 flex-col" style={{ width: `${view.state.panels.inspector}px` }}>
            <Inspector
              store={view}
              driver={ready()?.driver}
              attackPaths={
                <Show when={ready()}>
                  {(current) => <AttackPaths store={view} driver={current().driver} data={current().data} />}
                </Show>
              }
            />
          </aside>
        </Show>
        <Show when={props.editor && open.editor}>
          <Separator
            label={language.t("security.graph.panels.resizeEditor")}
            orientation="vertical"
            panel="editor"
            direction={-1}
            value={view.state.panels.editor}
            onChange={(size) => view.resizePanel("editor", size)}
          />
          <section
            class="min-h-0 shrink-0 overflow-hidden"
            style={{ width: `${view.state.panels.editor}px` }}
            aria-label={language.t("security.graph.panels.editor")}
          >
            {props.editor}
          </section>
        </Show>
      </div>
    </div>
  )
}

function Toggle(props: { label: string; on: boolean; set: (on: boolean) => void }) {
  return (
    <Button size="small" variant={props.on ? "contrast" : "ghost"} aria-pressed={props.on} onClick={() => props.set(!props.on)}>
      {props.label}
    </Button>
  )
}

type Drag = { type: "idle" } | { type: "dragging"; pointer: number; origin: number }
const idle: Drag = { type: "idle" }

// A focusable separator. `direction` is +1 when dragging toward the end of the axis grows the panel (a left dock) and
// -1 when it shrinks it (a right or bottom dock). Arrow keys move the separator the way the arrow points.
function Separator(props: {
  label: string
  orientation: "vertical" | "horizontal"
  panel: PanelId
  direction: 1 | -1
  value: number
  onChange: (size: number) => void
}) {
  const [drag, setDrag] = createSignal<Drag>(idle)
  const limit = () => limits[props.panel]
  const clamp = (size: number) => Math.min(limit().max, Math.max(limit().min, Math.round(size)))
  const vertical = () => props.orientation === "vertical"
  const axis = (event: PointerEvent) => (vertical() ? event.clientX : event.clientY)
  const keys = () => (vertical() ? { back: "ArrowLeft", forward: "ArrowRight" } : { back: "ArrowUp", forward: "ArrowDown" })

  const onKeyDown = (event: KeyboardEvent) => {
    const step = event.shiftKey ? keyStepLarge : keyStep
    const next =
      event.key === keys().forward
        ? props.value + step * props.direction
        : event.key === keys().back
          ? props.value - step * props.direction
          : event.key === "Home"
            ? limit().min
            : event.key === "End"
              ? limit().max
              : undefined
    if (next === undefined) return
    event.preventDefault()
    props.onChange(clamp(next))
  }
  const onPointerDown = (event: PointerEvent & { currentTarget: HTMLElement }) => {
    if (event.button !== 0) return
    event.preventDefault()
    event.currentTarget.setPointerCapture(event.pointerId)
    setDrag({ type: "dragging", pointer: axis(event), origin: props.value })
  }
  const onPointerMove = (event: PointerEvent) => {
    const current = drag()
    if (current.type !== "dragging") return
    props.onChange(clamp(current.origin + (axis(event) - current.pointer) * props.direction))
  }
  const end = () => setDrag(idle)

  return (
    <div
      role="separator"
      tabindex="0"
      aria-label={props.label}
      aria-orientation={props.orientation}
      aria-valuenow={clamp(props.value)}
      aria-valuemin={limit().min}
      aria-valuemax={limit().max}
      data-dragging={drag().type === "dragging" ? "" : undefined}
      class="shrink-0 bg-border-weak-base outline-none hover:bg-border-base focus-visible:bg-border-base data-[dragging]:bg-border-base"
      classList={{
        "w-1 cursor-col-resize": vertical(),
        "h-1 cursor-row-resize": !vertical(),
      }}
      style={{ "touch-action": "none" }}
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={end}
      onPointerCancel={end}
      onLostPointerCapture={end}
    />
  )
}
