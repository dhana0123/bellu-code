import { ClientError } from "@bellucode/client/promise"
import { createVirtualizer } from "@tanstack/solid-virtual"
import { Loader } from "@bellucode/ui/loader"
import { createEffect, createMemo, createSignal, For, Match, on, onCleanup, Show, Switch, untrack } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { showToast } from "@/shell/notifications/toast"
import {
  assetsInitial,
  assetsTransition,
  exportInitial,
  exportTransition,
  packagesInitial,
  packagesTransition,
  selectFirstLoad,
  selectHasMore,
  selectLoadingMore,
  selectPackages,
  selectedAsset,
  type AssetsEvent,
  type ExportEvent,
  type PackagesEvent,
} from "./machine"
import {
  EXPORT_FORMATS,
  PAGE_LIMIT,
  ROW_HEIGHT,
  UNKNOWN_LICENSE,
  ecosystemCounts,
  exportName,
  licenseCounts,
  tally,
  licenseKey,
  type ExportFormat,
} from "./model"
import "./bom.css"
type Tab = "sbom" | "aibom" | "cloudbom"
const TABS: readonly Tab[] = ["sbom", "aibom", "cloudbom"]
/**
 * BOM page. Only the SBOM tab works. AI-BOM and Cloud-BOM show a placeholder. Assets come from
 * `client.experimental.sbom.list`, packages page in by cursor from `sbom.get`, and a download calls `sbom.export`.
 */
export function SecurityBomPage() {
  const language = useLanguage()
  const sdk = useServerSDK()
  const [tab, setTab] = createSignal<Tab>("sbom")
  const [assets, setAssets] = createSignal(assetsInitial)
  const [packages, setPackages] = createSignal(packagesInitial)
  const [download, setDownload] = createSignal(exportInitial)
  const [format, setFormat] = createSignal<ExportFormat>("cyclonedx")
  const dispatchAssets = (event: AssetsEvent) => {
    const previous = untrack(assets)
    const next = assetsTransition(previous, event)
    if (next !== previous) setAssets(next)
  }
  const dispatchPackages = (event: PackagesEvent) => {
    const previous = untrack(packages)
    const next = packagesTransition(previous, event)
    if (next !== previous) setPackages(next)
  }
  const dispatchDownload = (event: ExportEvent) => {
    const previous = untrack(download)
    const next = exportTransition(previous, event)
    if (next !== previous) setDownload(next)
  }
  onCleanup(() => {
    dispatchAssets({ type: "disposed" })
    dispatchPackages({ type: "disposed" })
    dispatchDownload({ type: "disposed" })
  })
  // Driver: the asset list.
  const assetRequest = createMemo(
    () => {
      const current = assets()
      return current.type === "loading" ? current.attempt : undefined
    },
    undefined,
  )
  createEffect(() => {
    const attempt = assetRequest()
    if (attempt === undefined) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void sdk.api.experimental.sbom.list({ signal: controller.signal }).then(
      (list) => dispatchAssets({ type: "loaded", attempt, assets: list.items }),
      (error: unknown) => {
        if (controller.signal.aborted) return
        dispatchAssets({
          type: "failed",
          attempt,
          reason: error instanceof ClientError && error.reason === "UnexpectedStatus" ? "unavailable" : "error",
        })
      },
    )
  })
  // Driver: the packages of the selected asset.
  const packageRequest = createMemo(
    () => {
      const current = packages()
      return current.type === "loading"
        ? { attempt: current.attempt, assetId: current.assetId, cursor: current.cursor }
        : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt },
  )
  createEffect(() => {
    const request = packageRequest()
    if (!request) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void sdk.api.experimental.sbom
      .get({ assetId: request.assetId, limit: PAGE_LIMIT, cursor: request.cursor }, { signal: controller.signal })
      .then(
        (detail) => dispatchPackages({ type: "loaded", attempt: request.attempt, packages: detail.items, next: detail.nextCursor }),
        () => {
          if (!controller.signal.aborted) dispatchPackages({ type: "failed", attempt: request.attempt })
        },
      )
  })
  // Driver: the download. The file is saved from the bytes the server returns.
  const exportRequest = createMemo(
    () => {
      const current = download()
      return current.type === "exporting" ? current.attempt : undefined
    },
    undefined,
  )
  createEffect(() => {
    const attempt = exportRequest()
    const assetId = untrack(() => selectedAsset(packages()))
    if (attempt === undefined || assetId === undefined) return
    const chosen = untrack(format)
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void sdk.api.experimental.sbom
      .export({ assetId, format: chosen, version: chosen === "spdx" ? "2.3" : "1.5" }, { signal: controller.signal })
      .then(
        (bytes) => {
          const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: "application/json" }))
          const link = document.createElement("a")
          link.href = url
          link.download = exportName(assetId, chosen)
          link.click()
          URL.revokeObjectURL(url)
          dispatchDownload({ type: "done", attempt })
        },
        () => {
          if (controller.signal.aborted) return
          dispatchDownload({ type: "failed", attempt })
          showToast({ title: language.t("security.bom.export.failed") })
        },
      )
  })
  const list = createMemo(() => {
    const current = assets()
    return current.type === "ready" ? current.assets : []
  })
  const selected = createMemo(() => list().find((asset) => asset.assetId === selectedAsset(packages())))
  const licenseLabel = (key: string) => (key === UNKNOWN_LICENSE ? language.t("security.bom.license.unknown") : key)
  let scroller: HTMLDivElement | undefined
  const rows = createMemo(() => selectPackages(packages()))
  const virtualizer = createVirtualizer({
    get count() {
      return rows().length
    },
    getScrollElement: () => scroller ?? null,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  })
  // Reaching the end of the loaded rows asks for the next page.
  createEffect(() => {
    const last = virtualizer.getVirtualItems().at(-1)
    if (last && last.index >= rows().length - 1 && selectHasMore(untrack(packages))) dispatchPackages({ type: "more" })
  })
  createEffect(on(() => selectedAsset(packages()), () => scroller?.scrollTo({ top: 0 })))
  const counts = (entries: { key: string; count: number }[], label: (key: string) => string, kind: string) => (
    <ul data-slot="bom-counts" data-kind={kind}>
      <For each={entries}>
        {(entry) => (
          <li data-slot="bom-count">
            <span>{label(entry.key)}</span>
            <strong>{entry.count}</strong>
          </li>
        )}
      </For>
    </ul>
  )
  return (
    <div data-component="security-bom" class="mx-auto w-full max-w-[1200px] px-6 py-4">
      <h1 data-slot="bom-heading">{language.t("security.nav.bom")}</h1>
      <div role="tablist" data-slot="bom-tabs">
        <For each={TABS}>
          {(item) => (
            <button
              type="button"
              role="tab"
              data-slot="bom-tab"
              aria-selected={tab() === item}
              onClick={() => setTab(item)}
            >
              {language.t(`security.bom.tab.${item}`)}
            </button>
          )}
        </For>
      </div>
      <Show when={tab() === "sbom"} fallback={<p data-slot="bom-soon" role="status">{language.t("security.bom.soon")}</p>}>
        <Switch>
          <Match when={assets().type === "loading"}>
            <div data-slot="bom-loading" role="status">
              <Loader class="size-4" />
              <span>{language.t("security.loading")}</span>
            </div>
          </Match>
          <Match when={assets().type === "failed"}>
            <div data-slot="bom-error" role="alert">
              <span>
                {language.t(
                  (assets() as { reason?: string }).reason === "unavailable"
                    ? "security.bom.error.unavailable"
                    : "security.bom.error.failed",
                )}
              </span>
              <button type="button" data-slot="bom-retry" onClick={() => dispatchAssets({ type: "refresh" })}>
                {language.t("security.bom.error.retry")}
              </button>
            </div>
          </Match>
          <Match when={list().length === 0}>
            <div data-slot="bom-empty">
              <strong>{language.t("security.bom.empty.title")}</strong>
              <p>{language.t("security.bom.empty.description")}</p>
            </div>
          </Match>
          <Match when={true}>
            <section data-slot="bom-summary">
              <h2>{language.t("security.bom.ecosystems")}</h2>
              {counts(ecosystemCounts(list()), (key) => key, "ecosystem")}
              <h2>{language.t("security.bom.licenses")}</h2>
              {counts(licenseCounts(list()), licenseLabel, "license")}
            </section>
            <div data-slot="bom-body">
              <ul data-slot="bom-assets" aria-label={language.t("security.bom.assets")}>
                <For each={list()}>
                  {(asset) => (
                    <li>
                      <button
                        type="button"
                        data-slot="bom-asset"
                        aria-pressed={selectedAsset(packages()) === asset.assetId}
                        onClick={() => dispatchPackages({ type: "select", assetId: asset.assetId })}
                      >
                        <span data-slot="bom-asset-id">{asset.assetId}</span>
                        <span data-slot="bom-asset-meta">
                          {language.t("security.bom.packageCount", { count: asset.packageCount })}
                        </span>
                      </button>
                    </li>
                  )}
                </For>
              </ul>
              <div data-slot="bom-detail">
                <Show
                  when={selected()}
                  keyed
                  fallback={<p data-slot="bom-hint">{language.t("security.bom.select")}</p>}
                >
                  {(asset) => (
                    <>
                      <div data-slot="bom-detail-head">
                        <strong>{asset.assetId}</strong>
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
                      {counts(ecosystemCounts([asset]), (key) => key, "ecosystem")}
                      {counts(
                        tally([asset.licenses], licenseKey),
                        licenseLabel,
                        "license",
                      )}
                      <Show when={packages().type === "failed"}>
                        <div data-slot="bom-error" role="alert">
                          <span>{language.t("security.bom.error.packages")}</span>
                          <button type="button" data-slot="bom-retry" onClick={() => dispatchPackages({ type: "retry" })}>
                            {language.t("security.bom.error.retry")}
                          </button>
                        </div>
                      </Show>
                      <Show when={selectFirstLoad(packages())}>
                        <div data-slot="bom-loading" role="status">
                          <Loader class="size-4" />
                          <span>{language.t("security.loading")}</span>
                        </div>
                      </Show>
                      <div data-slot="bom-packages-head" aria-hidden="true">
                        <span>{language.t("security.bom.column.name")}</span>
                        <span>{language.t("security.bom.column.version")}</span>
                        <span>{language.t("security.bom.column.ecosystem")}</span>
                        <span>{language.t("security.bom.column.license")}</span>
                      </div>
                      <div data-slot="bom-packages" data-scrollable ref={(el) => (scroller = el)}>
                        <div style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative" }}>
                          <For each={virtualizer.getVirtualItems()}>
                            {(item) => {
                              const row = () => rows()[item.index]
                              return (
                                <Show when={row()}>
                                  {(pkg) => (
                                    <div
                                      data-slot="bom-package"
                                      style={{ height: `${ROW_HEIGHT}px`, transform: `translateY(${item.start}px)` }}
                                    >
                                      <span title={pkg().purl}>{pkg().name}</span>
                                      <span>{pkg().version ?? ""}</span>
                                      <span>{pkg().ecosystem ?? pkg().type ?? ""}</span>
                                      <span>
                                        {licenseLabel(
                                          pkg().licenses.length === 0 ? UNKNOWN_LICENSE : pkg().licenses.map(licenseKey).join(", "),
                                        )}
                                      </span>
                                    </div>
                                  )}
                                </Show>
                              )
                            }}
                          </For>
                        </div>
                      </div>
                      <Show when={selectLoadingMore(packages())}>
                        <div data-slot="bom-loading" role="status">
                          <Loader class="size-4" />
                          <span>{language.t("security.bom.loadingMore")}</span>
                        </div>
                      </Show>
                    </>
                  )}
                </Show>
              </div>
            </div>
          </Match>
        </Switch>
      </Show>
    </div>
  )
}
