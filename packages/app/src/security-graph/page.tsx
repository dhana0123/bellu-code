import type { GraphLens, GraphLensNode, GraphLensRisk } from "@bellucode/client/promise"
import { Loader } from "@bellucode/ui/loader"
import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show, untrack, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { GRAPH_DATA } from "./data"
import { computeLayout, layoutFor, type Layout } from "./layout"
import {
  createLensStorage,
  initial,
  selectFailure,
  selectFollow,
  selectLoading,
  selectSliceError,
  transition,
  type GraphEffect,
  type GraphEvent,
} from "./machine"
import type { GraphData, GraphNode } from "./model"
import { openOverlay, playable } from "./overlay"
import { mountGraph } from "./renderer"
import { toGraphData } from "./slice"
import { KIND_KEY, LENS_KEY } from "./theme"
import "./graph.css"

/** A request that has not answered by then ends in a state instead of leaving the page on "Loading". */
const REQUEST_TIMEOUT_MS = 20_000

type Mount = {
  handle: ReturnType<typeof mountGraph>
  stage: HTMLElement
  overlay: HTMLElement
  nodeIds: ReadonlySet<string>
}
type Details = { node: GraphNode; risk: GraphLensRisk | null }

/**
 * The Security Graph. With a Connection it draws the slice of the selected lens; without one it draws the dummy
 * code-to-cloud graph and hides the lens switcher. Pan and zoom only.
 */
export function SecurityGraphPage(props: { headerAction?: JSX.Element }) {
  const language = useLanguage()
  const sdk = useServerSDK()
  const [lensStore, setLensStore, , lensReady] = createLensStorage()
  const [state, setState] = createSignal(initial)
  const [ui, setUi] = createStore<{ connected: boolean; lenses: readonly GraphLens[] }>({ connected: false, lenses: [] })
  const [selected, setSelected] = createSignal<Details>()
  // One controller per slice attempt. The machine drops the result of any attempt that is no longer current.
  const attempts = new Map<number, AbortController>()
  let frame!: HTMLDivElement
  let current: Mount | undefined
  let details = new Map<string, Details>()

  const dispatch = (event: GraphEvent) => {
    const previous = untrack(state)
    const next = transition(previous, event)
    if (next.state === previous) return
    setState(next.state)
    next.effects.forEach(run)
  }

  const following = createMemo(() => selectFollow(state()))
  const activeLens = createMemo(() => {
    const value = state()
    if (value.type === "loading") return value.lens
    return value.type === "ready" ? (value.pending?.lens ?? value.lens) : undefined
  })

  // While follow mode is on, play the overlay stream on the canvas. Turning it off, or a manual pan, ends the stream.
  createEffect(() => {
    if (!following()) return
    const controller = new AbortController()
    onCleanup(() => {
      controller.abort()
      current?.handle.card(undefined)
      current?.handle.highlight([])
    })
    void play(controller.signal).catch(() => {
      if (!controller.signal.aborted) dispatch({ type: "follow", on: false })
    })
  })

  async function play(signal: AbortSignal) {
    for await (const frame of openOverlay(sdk.api, { replay: "demo", signal })) {
      // Read the mount per frame: a lens switch replaces it while the stream is open.
      const mount = current
      const [event] = playable([frame], mount?.nodeIds ?? new Set())
      if (!event || !mount || signal.aborted) continue
      mount.handle.highlight([event.entity, ...(event.path ?? [])])
      mount.handle.card(event.entity, event.explanation)
      if (event.action === "walk_path" && event.path?.length) await mount.handle.walk(event.path)
      else await mount.handle.focus(event.entity)
    }
  }

  function run(effect: GraphEffect) {
    if (effect.type === "persist-lens") return setLensStore("lens", effect.lens)
    const controller = new AbortController()
    attempts.forEach((older, attempt) => attempt < effect.attempt && older.abort())
    attempts.set(effect.attempt, controller)
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
    void load(effect.attempt, effect.lens, controller.signal)
      .catch(() => dispatch({ type: "slice-failed", attempt: effect.attempt }))
      .finally(() => {
        clearTimeout(timer)
        attempts.delete(effect.attempt)
      })
  }

  async function load(attempt: number, lens: string, signal: AbortSignal) {
    const slice = await sdk.api.experimental.graph.slice({ lens }, { signal })
    const data = toGraphData(slice)
    const layout = await computeLayout(data, signal, layoutFor(lens))
    if (!layout) throw new Error("layout")
    // The previous canvas stays until here. A newer attempt, or a failure, leaves it as it is.
    const value = untrack(state)
    const wanted = value.type === "loading" ? value.attempt : value.type === "ready" ? value.pending?.attempt : undefined
    if (wanted !== attempt) return
    show(data, layout, new Map(slice.nodes.map((node) => [node.id, node])))
    dispatch({ type: "loaded", attempt })
  }

  /** Mounts the new graph beside the old one and kills the old one once the new one stands. */
  function show(data: GraphData, layout: Layout, nodes: ReadonlyMap<string, GraphLensNode>) {
    const stage = document.createElement("div")
    stage.dataset.slot = "stage"
    const overlay = document.createElement("div")
    overlay.dataset.slot = "overlay"
    frame.append(stage, overlay)
    const handle = (() => {
      try {
        return mountGraph({ frame, stage, overlay, data, layout, t: (key) => language.t(key) })
      } catch (error) {
        stage.remove()
        overlay.remove()
        throw error
      }
    })()
    handle.onPan(() => dispatch({ type: "panned" }))
    handle.onSelect((id) => setSelected(id ? details.get(id) : undefined))
    const previous = current
    current = { handle, stage, overlay, nodeIds: new Set(data.nodes.map((node) => node.id)) }
    details = new Map(data.nodes.map((node) => [node.id, { node, risk: nodes.get(node.id)?.risk ?? null }]))
    setSelected(undefined)
    previous?.handle.kill(true)
    previous?.stage.remove()
    previous?.overlay.remove()
  }

  async function start(signal: AbortSignal) {
    // The first load has no earlier canvas to fall back on, so every wait on the server is bounded.
    const first = new AbortController()
    const abort = () => first.abort()
    signal.addEventListener("abort", abort, { once: true })
    const timer = setTimeout(abort, REQUEST_TIMEOUT_MS)
    const connected = await sdk.api.experimental.connectors
      .listConnections({ signal: first.signal })
      .then((result) => result.items.length > 0)
      .catch(() => false)
    const lenses = connected ? await sdk.api.experimental.graph.lenses({ signal: first.signal }) : []
    clearTimeout(timer)
    signal.removeEventListener("abort", abort)
    if (signal.aborted) return
    if (lenses.length === 0) return showDummy(signal)
    await lensReady.promise
    setUi({ connected: true, lenses })
    dispatch({
      type: "lenses-loaded",
      stored: lensStore.lens || undefined,
      lenses: lenses.map((lens) => lens.id),
      defaultLens: (lenses.find((lens) => lens.default) ?? lenses[0]!).id,
    })
  }

  async function showDummy(signal: AbortSignal) {
    const layout = await computeLayout(GRAPH_DATA, signal)
    if (signal.aborted) return
    if (!layout) return dispatch({ type: "failed", reason: "layout" })
    show(GRAPH_DATA, layout, new Map())
    dispatch({ type: "loaded", attempt: 0 })
  }

  onMount(() => {
    const controller = new AbortController()
    onCleanup(() => {
      dispatch({ type: "disposed" })
      controller.abort()
      attempts.forEach((attempt) => attempt.abort())
      current?.handle.kill()
    })
    if (!supportsWebGL2()) return dispatch({ type: "failed", reason: "webgl" })
    void start(controller.signal).catch(() => dispatch({ type: "failed", reason: "layout" }))
  })

  const lensName = (lens: GraphLens) =>
    Object.hasOwn(LENS_KEY, lens.id) ? language.t(LENS_KEY[lens.id as keyof typeof LENS_KEY].name) : lens.name
  const lensDescription = (lens: GraphLens) =>
    Object.hasOwn(LENS_KEY, lens.id) ? language.t(LENS_KEY[lens.id as keyof typeof LENS_KEY].description) : lens.description

  return (
    <div data-component="security-graph-page">
      <header data-slot="security-graph-header">
        {props.headerAction}
        <h1 data-slot="security-graph-title">{language.t("home.security.graph")}</h1>
        <Show when={ui.connected && ui.lenses.length > 0}>
          <div role="group" aria-label={language.t("security.graph.lens.label")} data-slot="security-graph-lenses">
            <For each={ui.lenses}>
              {(lens) => (
                <button
                  type="button"
                  data-slot="security-graph-lens"
                  aria-pressed={activeLens() === lens.id}
                  title={lensDescription(lens)}
                  disabled={state().type !== "ready"}
                  onClick={() => dispatch({ type: "select", lens: lens.id })}
                >
                  {lensName(lens)}
                </button>
              )}
            </For>
          </div>
        </Show>
        <button
          type="button"
          data-slot="security-graph-follow"
          aria-pressed={following()}
          disabled={state().type !== "ready"}
          onClick={() => dispatch({ type: "follow", on: !following() })}
        >
          {language.t(following() ? "security.graph.follow.on" : "security.graph.follow.off")}
        </button>
      </header>
      <Show when={selectSliceError(state())}>
        <p role="alert" data-slot="security-graph-error">
          {language.t("security.graph.error.slice")}
        </p>
      </Show>
      <div
        ref={frame}
        data-component="security-graph"
        data-state={state().type}
        role="img"
        aria-label={language.t("security.graph.canvas.label")}
      >
        <Show when={selectLoading(state())}>
          <div role="status" data-slot="status">
            <Loader class="size-4" />
            <span>{language.t("security.graph.loading")}</span>
          </div>
        </Show>
        <Show when={selectFailure(state())}>
          {(reason) => (
            <p role="alert" data-slot="status">
              {language.t(reason() === "webgl" ? "security.graph.error.webgl" : "security.graph.error.layout")}
            </p>
          )}
        </Show>
        <Show when={selected()}>
          {(item) => (
            <div data-slot="details">
              <div data-slot="details-name">{item().node.name}</div>
              <Show when={item().node.kind !== "service"}>
                <div data-slot="details-kind">
                  {language.t(KIND_KEY[item().node.kind as keyof typeof KIND_KEY])}
                </div>
              </Show>
              <Show when={item().node.kind === "vulnerability" && item().risk}>
                {(risk) => (
                  <dl data-slot="details-risk">
                    <dt>{language.t("security.graph.node.severity")}</dt>
                    <dd>{risk().severity}</dd>
                    <dt>{language.t("security.graph.node.kev")}</dt>
                    <dd>{language.t(risk().kev ? "security.graph.node.kev.yes" : "security.graph.node.kev.no")}</dd>
                    <dt>{language.t("security.graph.node.epss")}</dt>
                    <dd>{`${(Number(risk().epss) * 100).toFixed(1)}%`}</dd>
                  </dl>
                )}
              </Show>
            </div>
          )}
        </Show>
      </div>
    </div>
  )
}

// Sigma draws with WebGL 2. Asking first lets the page say so instead of failing inside the renderer.
function supportsWebGL2() {
  const gl = document.createElement("canvas").getContext("webgl2")
  gl?.getExtension("WEBGL_lose_context")?.loseContext()
  return gl !== null
}
