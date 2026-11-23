import { Schema } from "effect"
import { createEffect, createMemo, createSignal, onCleanup, Show, untrack } from "solid-js"
import { createStore } from "solid-js/store"
import { Persistence } from "@/runtime/persistence/schema"
import { Persist, persisted } from "@/runtime/persistence/storage"
import { useLanguage } from "@/runtime/i18n/language"
import { showToast } from "@/shell/notifications/toast"
import { ActiveFilters } from "./active-filters"
import { copyText } from "./clipboard"
import { DetailDrawer } from "./detail-drawer"
import { FilterBar } from "./filter-bar"
import { filterFindings, severityCounts, sortFindings, topGroups, treemapGroups } from "./filters"
import { FindingsTable } from "./findings-table"
import { HelpBanner } from "./help-banner"
import { initial, selectLoading, transition, type FindingsEvent } from "./machine"
import { getFindings } from "./mock-data"
import type { Finding, Severity } from "./model"
import { PageHeader } from "./page-header"
import { SummaryCards } from "./summary-cards"
import { TopBar } from "./top-bar"
import { TreemapView } from "./treemap-view"
import { useFilters } from "./use-filters"
import "./findings.css"

/** Stands in for a request. A load that has not finished by then still ends in the ready state. */
const LOAD_MS = 600

const HelpState = Persistence.struct({
  dismissed: Persistence.fallback(Schema.Boolean, () => false),
  tips: Persistence.fallback(Schema.Boolean, () => true),
})

/**
 * Vulnerability Findings. UI only: every number comes from `mock-data.ts`, so the layout, filtering and states can be
 * reviewed before a scanner feeds it.
 */
export function SecurityFindingsPage() {
  const language = useLanguage()
  const state = useFilters()
  const [help, setHelp] = persisted(Persist.global("security-findings.help"), HelpState, {
    dismissed: false,
    tips: true,
  })
  const [machine, setMachine] = createSignal(initial)
  const [ui, setUi] = createStore<{ selectedId?: string; ignored: Record<string, true> }>({ ignored: {} })
  // The row that opened the drawer, so focus can return to it.
  let opener: HTMLElement | undefined

  const dispatch = (event: FindingsEvent) => {
    const previous = untrack(machine)
    const next = transition(previous, event)
    if (next !== previous) setMachine(next)
  }

  // Driver: each loading state starts one timer, and a stale or disposed state cancels it.
  createEffect(() => {
    const current = machine()
    if (current.type !== "loading") return
    const timer = setTimeout(() => dispatch({ type: "loaded", attempt: current.attempt }), LOAD_MS)
    onCleanup(() => clearTimeout(timer))
  })
  onCleanup(() => dispatch({ type: "disposed" }))

  const loading = () => selectLoading(machine())
  const all = createMemo(() => getFindings().filter((item) => !ui.ignored[item.id]))
  const filtered = createMemo(() => filterFindings(all(), state.filters()))
  // The severity card counts rows as if no severity were chosen, so every row stays clickable.
  const counts = createMemo(() => severityCounts(filterFindings(all(), state.filters(), "severity")))
  const components = createMemo(() => topGroups(filtered(), (item) => item.component))
  const resources = createMemo(() => topGroups(filtered(), (item) => item.resource))
  const treemap = createMemo(() => treemapGroups(components()))
  const sorted = createMemo(() => sortFindings(filtered(), state.sort()))
  const selected = createMemo(() => all().find((item) => item.id === ui.selectedId))
  const componentLabel = createMemo(() => {
    const id = state.filters().component
    const match = id ? all().find((item) => item.component.id === id)?.component : undefined
    return match ? `${match.name} ${match.version}` : undefined
  })

  const open = (finding: Finding, row: HTMLElement) => {
    opener = row
    setUi("selectedId", finding.id)
  }
  const close = () => {
    setUi("selectedId", undefined)
    queueMicrotask(() => opener?.isConnected && opener.focus())
  }
  const ignore = (finding: Finding) => {
    setUi("ignored", finding.id, true)
    if (ui.selectedId === finding.id) close()
    showToast({ title: language.t("security.findings.toast.ignored", { value: finding.cve }) })
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
          loading={loading()}
          onChange={state.update}
          onRefresh={() => dispatch({ type: "refresh" })}
        />
        <ActiveFilters
          filters={state.filters()}
          componentLabel={componentLabel()}
          view={state.view()}
          onChange={state.update}
          onClear={state.clear}
          onView={state.setView}
        />
        <SummaryCards
          severity={state.filters().severity}
          counts={counts()}
          components={components()}
          resources={resources()}
          onSeverity={(severity: Severity) =>
            state.update({ severity: state.filters().severity === severity ? "all" : severity })
          }
        />
        <Show
          when={state.view() === "table"}
          fallback={<TreemapView groups={treemap()} onSelect={(component) => state.update({ component }, "table")} />}
        >
          <FindingsTable
            rows={sorted()}
            loading={loading()}
            sort={state.sort()}
            page={state.page()}
            pageSize={state.pageSize()}
            onSort={state.setSort}
            onPage={state.setPage}
            onPageSize={state.setPageSize}
            onOpen={open}
            onIgnore={ignore}
            onClear={state.clear}
          />
        </Show>
      </div>
      <DetailDrawer
        finding={selected()}
        onClose={close}
        onIgnore={ignore}
        onCopyLink={(finding) =>
          void copyText(window.location.href).then(() =>
            showToast({ title: language.t("security.findings.toast.linkCopied", { value: finding.cve }) }),
          )
        }
      />
    </div>
  )
}
