import { ClientError } from "@bellucode/client/promise"
import { Loader } from "@bellucode/ui/loader"
import { createEffect, createMemo, createSignal, For, Match, onCleanup, Show, Switch, untrack } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { showToast } from "@/shell/notifications/toast"
import {
  documentInitial,
  documentTransition,
  exportInitial,
  exportTransition,
  type DocumentEvent,
  type ExportEvent,
} from "./machine"
import {
  EXPORT_FORMATS,
  documentExportName,
  isLicenseDenied,
  tally,
  type DocumentKind,
  type ExportFormat,
} from "./model"

/** AI-BOM or Cloud-BOM tab: type counts, components, incomplete-provider banners, findings and a download. */
export function BomDocumentTab(props: { kind: DocumentKind }) {
  const language = useLanguage()
  const sdk = useServerSDK()
  const bom = sdk.api.experimental.bom
  const kind = props.kind
  const [state, setState] = createSignal(documentInitial)
  const [download, setDownload] = createSignal(exportInitial)
  const [format, setFormat] = createSignal<ExportFormat>("cyclonedx")
  const dispatch = (event: DocumentEvent) => {
    const previous = untrack(state)
    const next = documentTransition(previous, event)
    if (next !== previous) setState(next)
  }
  const dispatchDownload = (event: ExportEvent) => {
    const previous = untrack(download)
    const next = exportTransition(previous, event)
    if (next !== previous) setDownload(next)
  }
  onCleanup(() => {
    dispatch({ type: "disposed" })
    dispatchDownload({ type: "disposed" })
  })

  const request = createMemo(() => {
    const current = state()
    return current.type === "loading" ? current.attempt : undefined
  })
  createEffect(() => {
    const attempt = request()
    if (attempt === undefined) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void (kind === "ai" ? bom.ai({ signal: controller.signal }) : bom.cloud({ signal: controller.signal })).then(
      (document) => dispatch({ type: "loaded", attempt, document }),
      (error: unknown) => {
        if (controller.signal.aborted) return
        dispatch({
          type: "failed",
          attempt,
          reason: error instanceof ClientError && error.reason === "UnexpectedStatus" ? "unavailable" : "error",
        })
      },
    )
  })

  const exportRequest = createMemo(() => {
    const current = download()
    return current.type === "exporting" ? current.attempt : undefined
  })
  createEffect(() => {
    const attempt = exportRequest()
    if (attempt === undefined) return
    const chosen = untrack(format)
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    const input = { format: chosen, version: chosen === "spdx" ? "2.3" : "1.5" }
    void (kind === "ai"
      ? bom.aiExport(input, { signal: controller.signal })
      : bom.cloudExport(input, { signal: controller.signal })
    ).then(
      (bytes) => {
        const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: "application/json" }))
        const link = document.createElement("a")
        link.href = url
        link.download = documentExportName(kind, chosen)
        link.click()
        URL.revokeObjectURL(url)
        dispatchDownload({ type: "done", attempt })
      },
      () => {
        if (controller.signal.aborted) return
        dispatchDownload({ type: "failed", attempt })
        showToast({ title: language.t("security.bom.document.export.failed") })
      },
    )
  })

  const ready = createMemo(() => {
    const current = state()
    return current.type === "ready" ? current.document : undefined
  })

  return (
    <Switch>
      <Match when={state().type === "loading"}>
        <div data-slot="bom-loading" role="status">
          <Loader class="size-4" />
          <span>{language.t("security.loading")}</span>
        </div>
      </Match>
      <Match when={state().type === "failed"}>
        <div data-slot="bom-error" role="alert">
          <span>
            {language.t(
              (state() as { reason?: string }).reason === "unavailable"
                ? "security.bom.document.error.unavailable"
                : "security.bom.document.error.failed",
            )}
          </span>
          <button type="button" data-slot="bom-retry" onClick={() => dispatch({ type: "refresh" })}>
            {language.t("security.bom.error.retry")}
          </button>
        </div>
      </Match>
      <Match when={ready()}>
        {(document) => (
          <section data-slot="bom-document" data-kind={kind}>
            <For each={document().incomplete}>
              {(gap) => (
                <div data-slot="bom-incomplete" role="alert">
                  {language.t("security.bom.document.incomplete", { provider: gap.provider, cause: gap.cause })}
                </div>
              )}
            </For>
            <Show
              when={document().components.length > 0}
              fallback={
                <div data-slot="bom-empty">
                  <strong>{language.t(`security.bom.${kind}.empty.title`)}</strong>
                  <p>{language.t(`security.bom.${kind}.empty.description`)}</p>
                </div>
              }
            >
              <div data-slot="bom-detail-head">
                <strong>{language.t("security.bom.document.componentCount", { count: document().components.length })}</strong>
                <label>
                  <span>{language.t("security.bom.export.format")}</span>
                  <select
                    data-slot="bom-format"
                    value={format()}
                    onChange={(event) => setFormat(event.currentTarget.value === "spdx" ? "spdx" : "cyclonedx")}
                  >
                    <For each={EXPORT_FORMATS}>
                      {(item) => <option value={item}>{language.t(`security.bom.export.${item}`)}</option>}
                    </For>
                  </select>
                </label>
                <button
                  type="button"
                  data-slot="bom-download"
                  disabled={download().type === "exporting"}
                  onClick={() => dispatchDownload({ type: "start" })}
                >
                  {language.t("security.bom.export.download")}
                </button>
              </div>
              <ul data-slot="bom-counts" data-kind="type">
                <For each={tally(document().components.map((component) => ({ [component.type]: 1 })))}>
                  {(entry) => (
                    <li data-slot="bom-count">
                      <span>{entry.key}</span>
                      <strong>{entry.count}</strong>
                    </li>
                  )}
                </For>
              </ul>
              <div data-slot="bom-packages" data-scrollable>
                <For each={document().components}>
                  {(component) => (
                    <div data-slot="bom-package" data-license-denied={isLicenseDenied(component) ? "" : undefined}>
                      <span title={component.locations?.join(", ")}>{component.name}</span>
                      <span>{component.version ?? ""}</span>
                      <span>{component.type}</span>
                      <span>
                        {component.licenses?.join(", ")}
                        <Show when={isLicenseDenied(component)}>
                          <strong data-slot="bom-license-denied"> {language.t("security.bom.document.licenseDenied")}</strong>
                        </Show>
                      </span>
                    </div>
                  )}
                </For>
              </div>
            </Show>
            <Show when={document().findings.length > 0}>
              <h2>{language.t("security.bom.document.findings")}</h2>
              <ul data-slot="bom-findings">
                <For each={document().findings}>
                  {(finding) => (
                    <li data-slot="bom-finding" data-severity={finding.Severity}>
                      <strong>{finding.Severity}</strong> {finding.Component} {finding.Version}: {finding.Message}
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>
        )}
      </Match>
    </Switch>
  )
}
