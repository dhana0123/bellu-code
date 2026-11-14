import { createEffect, createSignal, For, Match, on, onCleanup, onMount, Show, Switch } from "solid-js"
import { createStore } from "solid-js/store"
import { Button } from "@bellucode/ui/button"
import { IconButton } from "@bellucode/ui/icon-button"
import { Loader } from "@bellucode/ui/loader"
import { useTheme } from "@bellucode/ui/theme"
import { useLanguage } from "@/runtime/i18n/language"
import { createDriver, type Driver } from "../driver"
import { createLayoutClient } from "../layout/client"
import { INITIAL_MODEL, type Model } from "../machine"
import { createMockSource } from "../mock/source"
import { createEngine } from "../projection/engine"
import { createAtlas } from "../render/atlas"
import { createRenderer, type Renderer } from "../render/sigma"
import type { GraphData } from "../model"
import type { GraphSize } from "../source"
import { zoomLevel, type ZoomLevelKey } from "../theme"

const sizeOptions = ["100", "5k", "50k"] as const satisfies readonly GraphSize[]

type LoadState =
  | { type: "loading"; attempt: number }
  | { type: "ready"; warning?: string }
  | { type: "failed"; reason: "load" | "webgl" }

const zoomKeys = {
  L1: "security.graph.zoom.l1",
  L2: "security.graph.zoom.l2",
  L3: "security.graph.zoom.l3",
  L4: "security.graph.zoom.l4",
} as const satisfies Record<ZoomLevelKey, string>

// Selectors over the machine model. The view reads these and never inspects the phase itself.
export const selectBusy = (model: Model) => model.state.type === "animating"
export const selectCanBack = (model: Model) => model.history.index > 0
export const selectCanForward = (model: Model) => model.history.index < model.history.entries.length - 1

export type GraphViewProps = {
  /** Called once per loaded graph with the driver, and with `undefined` when it is torn down. */
  onDriver?: (driver: Driver | undefined) => void
  /** Called right after `onDriver` for a loaded graph, with what the surrounding chrome needs (export, tooltip). */
  onReady?: (ready: { container: HTMLElement; renderer: Renderer; driver: Driver; data: GraphData }) => void
}

export function GraphView(props: GraphViewProps) {
  const language = useLanguage()
  const theme = useTheme()
  const source = createMockSource()
  const [view, setView] = createStore<{ size: GraphSize; load: LoadState; level: ZoomLevelKey }>({
    size: "100",
    load: { type: "loading", attempt: 0 },
    level: "L1",
  })
  // The machine model is replaced whole on every change, so it lives in a signal, not a store.
  const [model, setModel] = createSignal<Model>(INITIAL_MODEL)
  let container!: HTMLDivElement
  let renderer: Renderer | undefined
  let driver: Driver | undefined
  let layout: ReturnType<typeof createLayoutClient> | undefined
  let unsubscribe: (() => void) | undefined

  function teardown() {
    unsubscribe?.()
    driver?.dispose()
    layout?.dispose()
    unsubscribe = undefined
    driver = undefined
    layout = undefined
    props.onDriver?.(undefined)
    setModel(INITIAL_MODEL)
  }

  onMount(() => {
    try {
      renderer = createRenderer(container, {
        mode: theme.mode(),
        atlas: createAtlas(),
        typeLabel: (type) => type,
        relationLabel: (relation) => language.t(`security.graph.relation.${relation}` as Parameters<typeof language.t>[0]),
      })
    } catch {
      setView("load", { type: "failed", reason: "webgl" })
    }
  })

  onCleanup(() => {
    teardown()
    renderer?.dispose()
    renderer = undefined
  })

  createEffect(() => {
    const mode = theme.mode()
    renderer?.setMode(mode)
  })

  // Loads whenever the size or the attempt changes. A result for an older attempt is ignored.
  createEffect(
    on(
      () => [view.size, view.load.type === "loading" ? view.load.attempt : -1] as const,
      ([size, attempt]) => {
        if (attempt < 0 || !renderer) return
        teardown()
        void load(size, attempt, renderer)
      },
    ),
  )

  async function load(size: GraphSize, attempt: number, target: Renderer) {
    const current = () => view.load.type === "loading" && view.load.attempt === attempt && renderer === target
    const client = createLayoutClient()
    try {
      const data = await source.load(size)
      const result = await client.layout(data)
      if (!current()) return client.dispose()
      layout = client
      const next = createDriver(container, {
        renderer: target,
        engine: createEngine(data, result.positions),
        pin: (id, point) => client.set(id, point),
      })
      driver = next
      unsubscribe = source.subscribe((delta) => next.applyDelta(delta))
      next.onState(setModel)
      next.onViewport((viewport) => setView("level", zoomLevel(viewport.scale)))
      props.onDriver?.(next)
      props.onReady?.({ container, renderer: target, driver: next, data })
      setView("load", { type: "ready", warning: result.warning ? language.t("security.graph.error.worker") : undefined })
    } catch {
      client.dispose()
      if (current()) setView("load", { type: "failed", reason: "load" })
    }
  }

  const chooseSize = (size: GraphSize) => {
    if (size === view.size && view.load.type !== "failed") return
    setView({ size, load: { type: "loading", attempt: Date.now() } })
  }
  const retry = () => setView("load", { type: "loading", attempt: Date.now() })
  const dark = () => theme.mode() === "dark"

  return (
    <section class="relative flex min-h-0 min-w-0 flex-1 flex-col" aria-label={language.t("security.graph.title")}>
      <div
        class="flex shrink-0 items-center gap-2 px-3 py-2"
        role="toolbar"
        aria-label={language.t("security.graph.toolbar.label")}
      >
        <div class="flex items-center gap-1" role="group" aria-label={language.t("security.graph.toolbar.source")}>
          <For each={sizeOptions}>
            {(size) => (
              <Button
                size="small"
                variant={view.size === size ? "contrast" : "ghost"}
                aria-pressed={view.size === size}
                onClick={() => chooseSize(size)}
              >
                {language.t(`security.graph.toolbar.source.${size}`)}
              </Button>
            )}
          </For>
        </div>
        <div class="flex-1" />
        <Button size="small" variant="ghost" aria-pressed={dark()} onClick={() => theme.setColorScheme(dark() ? "light" : "dark")}>
          {language.t("security.graph.toolbar.theme")}
        </Button>
      </div>
      <div class="relative min-h-0 flex-1">
        <div
          ref={container}
          class="absolute inset-0 outline-none"
          role="application"
          tabindex="0"
          aria-label={language.t("security.graph.canvas.label")}
        />
        <Switch>
          <Match when={view.load.type === "loading"}>
            <div class="absolute inset-0 flex items-center justify-center gap-2 text-text-weak" role="status">
              <Loader class="size-4" />
              <span>{language.t("security.graph.loading")}</span>
            </div>
          </Match>
          <Match when={view.load.type === "failed" ? view.load : undefined} keyed>
            {(failed) => (
              <div class="absolute inset-0 flex flex-col items-center justify-center gap-3 text-center" role="alert">
                <span>
                  {language.t(failed.reason === "webgl" ? "security.graph.error.webgl" : "security.graph.error.title")}
                </span>
                <Show when={failed.reason === "load"}>
                  <Button size="small" onClick={retry}>
                    {language.t("security.graph.error.retry")}
                  </Button>
                </Show>
              </div>
            )}
          </Match>
        </Switch>
        <Show when={view.load.type === "ready" && view.load.warning}>
          {(warning) => (
            <div class="absolute left-3 top-3 rounded-md bg-surface-raised-base px-2 py-1 text-12-regular" role="status">
              {warning()}
            </div>
          )}
        </Show>
        <Show when={view.load.type === "ready"}>
          <div
            class="absolute bottom-3 right-3 flex flex-col items-center gap-1"
            role="group"
            aria-label={language.t("security.graph.zoom.controls")}
          >
            <IconButton
              icon="plus"
              variant="neutral"
              aria-label={language.t("security.graph.zoom.in")}
              onClick={() => driver?.zoomIn()}
            />
            <IconButton
              icon="minus"
              variant="neutral"
              aria-label={language.t("security.graph.zoom.out")}
              onClick={() => driver?.zoomOut()}
            />
            <IconButton
              icon="expand"
              variant="neutral"
              aria-label={language.t("security.graph.zoom.fit")}
              onClick={() => driver?.fit()}
            />
            <IconButton
              icon="reset"
              variant="neutral"
              aria-label={language.t("security.graph.zoom.reset")}
              onClick={() => driver?.reset()}
            />
          </div>
          <div class="absolute bottom-3 left-3 text-12-regular text-text-weak" aria-live="polite" data-busy={selectBusy(model()) ? "" : undefined}>
            <span class="sr-only">{language.t("security.graph.zoom.level")}: </span>
            {language.t(zoomKeys[view.level])}
          </div>
        </Show>
      </div>
    </section>
  )
}
