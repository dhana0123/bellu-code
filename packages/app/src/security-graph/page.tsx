import { Loader } from "@bellucode/ui/loader"
import { createSignal, onCleanup, onMount, Show, type JSX } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { GRAPH_DATA } from "./data"
import { computeLayout } from "./layout"
import { initial, selectFailure, selectLoading, transition, type GraphEvent } from "./machine"
import { mountGraph } from "./renderer"
import "./graph.css"

/** The Security Graph: a dummy code-to-cloud attack-surface graph. Pan and zoom only. */
export function SecurityGraphPage(props: { headerAction?: JSX.Element }) {
  const language = useLanguage()
  const [state, setState] = createSignal(initial)
  const dispatch = (event: GraphEvent) => setState((current) => transition(current, event))
  let frame!: HTMLDivElement
  let stage!: HTMLDivElement
  let overlay!: HTMLDivElement

  onMount(() => {
    const controller = new AbortController()
    let mounted: ReturnType<typeof mountGraph> | undefined
    onCleanup(() => {
      dispatch({ type: "disposed" })
      controller.abort()
      mounted?.kill()
    })
    if (!supportsWebGL2()) return dispatch({ type: "failed", reason: "webgl" })

    void (async () => {
      const layout = await computeLayout(GRAPH_DATA, controller.signal).catch(() => "failed" as const)
      if (controller.signal.aborted) return
      if (!layout || layout === "failed") return dispatch({ type: "failed", reason: "layout" })
      mounted = mountGraph({ frame, stage, overlay, data: GRAPH_DATA, layout, t: (key) => language.t(key) })
      dispatch({ type: "loaded" })
    })().catch(() => dispatch({ type: "failed", reason: "webgl" }))
  })

  return (
    <div data-component="security-graph-page">
      <header data-slot="security-graph-header">
        {props.headerAction}
        <h1 data-slot="security-graph-title">{language.t("home.security.graph")}</h1>
      </header>
      <div
        ref={frame}
        data-component="security-graph"
        data-state={state().type}
        role="img"
        aria-label={language.t("security.graph.canvas.label")}
      >
        <div ref={stage} data-slot="stage" />
        <div ref={overlay} data-slot="overlay" />
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
