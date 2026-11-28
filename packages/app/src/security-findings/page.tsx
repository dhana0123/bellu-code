import { Schema } from "effect"
import { createEffect, createMemo, createSignal, on, onCleanup, Show, untrack } from "solid-js"
import { Persistence } from "@/runtime/persistence/schema"
import { Persist, persisted } from "@/runtime/persistence/storage"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { showToast } from "@/shell/notifications/toast"
import { ActiveFilters } from "./active-filters"
import { copyText } from "./clipboard"
import { DetailDrawer } from "./detail-drawer"
import {
  initial as drawerInitial,
  selectOpenId,
  transition as drawerTransition,
  type DrawerEvent,
} from "./drawer-machine"
import { FilterBar } from "./filter-bar"
import { filterFindings, severityCounts, sortFindings, topGroups, treemapGroups } from "./filters"
import { FindingsTable } from "./findings-table"
import { HelpBanner } from "./help-banner"
import { LoadError } from "./load-error"
import {
  initial,
  selectFailure,
  selectHasMore,
  selectLoading,
  selectLoadingMore,
  selectRows,
  selectTruncated,
  transition,
  type FindingsEvent,
} from "./machine"
import type { Finding, Severity } from "./model"
import { PageHeader } from "./page-header"
import { failureReason, rejection, toEvents, toFinding, toListInput } from "./query"
import { SummaryCards } from "./summary-cards"
import { TopBar } from "./top-bar"
import { TreemapView } from "./treemap-view"
import { useFilters } from "./use-filters"
import "./findings.css"

const HelpState = Persistence.struct({
  dismissed: Persistence.fallback(Schema.Boolean, () => false),
  tips: Persistence.fallback(Schema.Boolean, () => true),
})

/**
 * Findings. Rows come from `client.experimental.findings.list` with cursor paging. The severity, type, status, category
 * and asset filters and four of the sort columns run on the server. The search box and the other sort columns work on
 * the rows loaded so far.
 */
export function SecurityFindingsPage() {
  const language = useLanguage()
  const sdk = useServerSDK()
  const state = useFilters()
  const [help, setHelp] = persisted(Persist.global("security-findings.help"), HelpState, {
    dismissed: false,
    tips: true,
  })
  const [machine, setMachine] = createSignal(initial)
  const [drawer, setDrawer] = createSignal(drawerInitial)
  // The row that opened the drawer, so focus can return to it.
  let opener: HTMLElement | undefined

  const dispatch = (event: FindingsEvent) => {
    const previous = untrack(machine)
    const next = transition(previous, event)
    if (next !== previous) setMachine(next)
  }
  const dispatchDrawer = (event: DrawerEvent) => {
    const previous = untrack(drawer)
    const next = drawerTransition(previous, event)
    if (next !== previous) setDrawer(next)
  }
  onCleanup(() => dispatch({ type: "disposed" }))

  // A new filter or sort starts a new query. The search text only filters the loaded rows, so it is not part of it.
  createEffect(
    on(
      () => JSON.stringify(toListInput(state.filters(), state.sort())),
      () => dispatch({ type: "query" }),
      { defer: true },
    ),
  )

  // Driver: each load attempt starts one request, and a stale or disposed attempt aborts it.
  const load = createMemo(
    () => {
      const current = machine()
      return current.type === "loading" ? { attempt: current.attempt, cursor: current.cursor } : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt },
  )
  createEffect(() => {
    const request = load()
    if (!request) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void sdk.api.experimental.findings
      .list(toListInput(untrack(state.filters), untrack(state.sort), request.cursor), { signal: controller.signal })
      .then(
        (page) =>
          dispatch({
            type: "loaded",
            attempt: request.attempt,
            rows: page.items.map(toFinding),
            next: page.nextCursor,
            truncated: page.truncated,
          }),
        (error: unknown) => {
          if (controller.signal.aborted) return
          dispatch({ type: "failed", attempt: request.attempt, reason: failureReason(error) })
        },
      )
  })

  // Driver: the status history of the open finding.
  const history = createMemo(
    () => {
      const current = drawer()
      return current.type === "open" && current.history.type === "loading"
        ? { attempt: current.attempt, id: current.id }
        : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt },
  )
  createEffect(() => {
    const request = history()
    if (!request) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void sdk.api.experimental.findings.get({ id: request.id }, { signal: controller.signal }).then(
      (detail) => dispatchDrawer({ type: "history-loaded", attempt: request.attempt, events: toEvents(detail) }),
      () => {
        if (controller.signal.aborted) return
        dispatchDrawer({ type: "history-failed", attempt: request.attempt })
      },
    )
  })

  // Driver: a status change. It is not aborted when the drawer closes, because the server may already have applied it.
  const saving = createMemo(
    () => {
      const current = drawer()
      return current.type === "open" && current.save.type === "saving"
        ? { attempt: current.attempt, id: current.id, request: current.save.request }
        : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt && a?.request === b?.request },
  )
  createEffect(() => {
    const job = saving()
    if (!job) return
    void sdk.api.experimental.findings.setStatus({ id: job.id, ...job.request }).then(
      (detail) => {
        const finding = toFinding(detail)
        dispatch({ type: "patched", finding })
        dispatchDrawer({ type: "saved", attempt: job.attempt, events: toEvents(detail) })
        showToast({
          title: language.t("security.findings.toast.statusChanged", {
            value: finding.title,
            status: language.t(`security.findings.status.${finding.status}`),
          }),
        })
      },
      (error: unknown) => dispatchDrawer({ type: "save-failed", attempt: job.attempt, ...rejection(error) }),
    )
  })

  const loading = () => selectLoading(machine())
  const failure = () => selectFailure(machine())
  const rows = createMemo(() => selectRows(machine()))
  const filtered = createMemo(() => filterFindings(rows(), state.filters()))
  // The server returns only the chosen severity when one is chosen, so the other rows have no count to show.
  const counts = createMemo(() => {
    const all = severityCounts(filtered())
    const only = state.filters().severity
    return only === "all" ? all : ({ [only]: all[only] } satisfies Partial<Record<Severity, number>>)
  })
  const rules = createMemo(() =>
    topGroups(filtered(), (item) => ({ id: item.ruleId, name: item.title })),
  )
  const assets = createMemo(() => topGroups(filtered(), (item) => ({ id: item.assetId, name: item.assetId })))
  const treemap = createMemo(() => treemapGroups(assets()))
  const sorted = createMemo(() => sortFindings(filtered(), state.sort()))
  const selected = createMemo(() => {
    const id = selectOpenId(drawer())
    return id === undefined ? undefined : rows().find((item) => item.id === id)
  })
  // A reload or a new query replaces the rows, so a drawer whose finding is gone closes.
  createEffect(() => {
    if (drawer().type === "open" && !selected()) dispatchDrawer({ type: "close" })
  })

  const open = (finding: Finding, row: HTMLElement, intent?: "ignored") => {
    opener = row
    dispatchDrawer({ type: "open", id: finding.id, intent })
  }
  const close = () => {
    dispatchDrawer({ type: "close" })
    queueMicrotask(() => opener?.isConnected && opener.focus())
  }

  return (
    <div data-component="security-findings">
      <div data-slot="content">
        <TopBar />
        <PageHeader onShowHelp={() => setHelp("dismissed", false)} />
        <Show when={!help.dismissed}>
          <HelpBanner
            tips={help.tips}
            onTipsChange={(value) => setHelp("tips", value)}
            onClose={() => setHelp("dismissed", true)}
          />
        </Show>
        <FilterBar
          filters={state.filters()}
          count={filtered().length}
          more={selectHasMore(machine())}
          loading={loading()}
          onChange={state.update}
          onRefresh={() => dispatch({ type: "refresh" })}
        />
        <ActiveFilters
          filters={state.filters()}
          view={state.view()}
          onChange={state.update}
          onClear={state.clear}
          onView={state.setView}
        />
        <SummaryCards
          severity={state.filters().severity}
          counts={counts()}
          more={selectHasMore(machine())}
          rules={rules()}
          assets={assets()}
          onSeverity={(severity: Severity) =>
            state.update({ severity: state.filters().severity === severity ? "all" : severity })
          }
        />
        <Show when={failure()}>
          {(reason) => (
            <LoadError
              reason={reason()}
              onRetry={() => dispatch(rows().length > 0 ? { type: "more" } : { type: "refresh" })}
            />
          )}
        </Show>
        <Show when={failure() === undefined || rows().length > 0}>
          <Show
            when={state.view() === "table"}
            fallback={
              <TreemapView groups={treemap()} onSelect={(asset) => state.update({ asset }, "table")} />
            }
          >
            <FindingsTable
              rows={sorted()}
              loading={loading()}
              loadingMore={selectLoadingMore(machine())}
              hasMore={selectHasMore(machine())}
              truncated={selectTruncated(machine())}
              sort={state.sort()}
              page={state.page()}
              pageSize={state.pageSize()}
              onSort={state.setSort}
              onPage={state.setPage}
              onPageSize={state.setPageSize}
              onMore={() => dispatch({ type: "more" })}
              onOpen={(finding, row) => open(finding, row)}
              onIgnore={(finding, row) => open(finding, row, "ignored")}
              onClear={state.clear}
            />
          </Show>
        </Show>
      </div>
      <DetailDrawer
        finding={selected()}
        state={drawer()}
        onClose={close}
        onSave={(request) => dispatchDrawer({ type: "save", request })}
        onCopyLink={(finding) =>
          void copyText(window.location.href).then(() =>
            showToast({ title: language.t("security.findings.toast.linkCopied", { value: finding.title }) }),
          )
        }
      />
    </div>
  )
}
