import { A, useSearchParams } from "@solidjs/router"
import { Loader } from "@bellucode/ui/loader"
import { createEffect, createMemo, createSignal, For, Match, onCleanup, Show, Switch, untrack } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { showToast } from "@/shell/notifications/toast"
import { securityPath } from "@/security/nav-items"
import {
  CATEGORIES,
  NO_FILTERS,
  PAGE_LIMIT,
  SEVERITIES,
  STATUSES,
  complianceInitial,
  complianceTransition,
  detailInitial,
  detailTransition,
  listInitial,
  listTransition,
  selectFilters,
  selectFirstLoad,
  selectHasMore,
  selectItems,
  selectLoadingMore,
  selectOpenId,
  type ComplianceEvent,
  type DetailEvent,
  type Filters,
  type ListEvent,
} from "./machine"
import "./issues.css"
type Tab = "issues" | "compliance"
const TABS: readonly Tab[] = ["issues", "compliance"]
/** The server encodes a non-finite score as a string. */
const risk = (score: number | string) => (typeof score === "number" ? score.toFixed(1) : score)
/** The Findings page searches by text, so a member finding opens there filtered to its id. */
const findingPath = (id: string) => `${securityPath("findings")}?q=${encodeURIComponent(id)}`
/**
 * Issues page. The table comes from `client.experimental.issues.list` in the server's risk-score order, the detail from
 * `issues.get`, and a status change calls `issues.setStatus`. The Compliance tab reads `rules.compliance`. The open
 * issue lives in the `id` query parameter, so the Overview card can link straight to one.
 */
export function SecurityIssuesPage() {
  const language = useLanguage()
  const sdk = useServerSDK()
  const [params, setParams] = useSearchParams<{ id?: string }>()
  const [tab, setTab] = createSignal<Tab>("issues")
  const [list, setList] = createSignal(listInitial(NO_FILTERS))
  const [detail, setDetail] = createSignal(detailInitial(untrack(() => params.id)))
  const [compliance, setCompliance] = createSignal(complianceInitial)
  const dispatchList = (event: ListEvent) => {
    const previous = untrack(list)
    const next = listTransition(previous, event)
    if (next !== previous) setList(next)
  }
  const dispatchDetail = (event: DetailEvent) => {
    const previous = untrack(detail)
    const next = detailTransition(previous, event)
    if (next !== previous) setDetail(next)
  }
  const dispatchCompliance = (event: ComplianceEvent) => {
    const previous = untrack(compliance)
    const next = complianceTransition(previous, event)
    if (next !== previous) setCompliance(next)
  }
  onCleanup(() => {
    dispatchList({ type: "disposed" })
    dispatchDetail({ type: "disposed" })
    dispatchCompliance({ type: "disposed" })
  })
  // The URL names the open issue. A link with `?id` opens it on load and while the page is already showing.
  createEffect(() => {
    const id = params.id
    dispatchDetail(id ? { type: "open", id } : { type: "close" })
  })
  createEffect(() => {
    if (tab() === "compliance") dispatchCompliance({ type: "start" })
  })

  // Driver: the table.
  const listRequest = createMemo(
    () => {
      const current = list()
      return current.type === "loading"
        ? { attempt: current.attempt, filters: current.filters, cursor: current.cursor }
        : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt },
  )
  createEffect(() => {
    const request = listRequest()
    if (!request) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    const filters = request.filters
    void sdk.api.experimental.issues
      .list(
        {
          category: filters.category ? [filters.category] : undefined,
          severity: filters.severity ? [filters.severity] : undefined,
          status: filters.status ? [filters.status] : undefined,
          asset: filters.asset,
          sort: "-risk_score",
          limit: PAGE_LIMIT,
          cursor: request.cursor,
        },
        { signal: controller.signal },
      )
      .then(
        (page) =>
          dispatchList({
            type: "loaded",
            attempt: request.attempt,
            items: page.items,
            next: page.nextCursor,
            truncated: page.truncated,
          }),
        () => {
          if (!controller.signal.aborted) dispatchList({ type: "failed", attempt: request.attempt })
        },
      )
  })

  // Driver: the open issue.
  const detailRequest = createMemo(
    () => {
      const current = detail()
      return current.type === "loading" ? { attempt: current.attempt, id: current.id } : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt },
  )
  createEffect(() => {
    const request = detailRequest()
    if (!request) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void sdk.api.experimental.issues.get({ id: request.id }, { signal: controller.signal }).then(
      (issue) => dispatchDetail({ type: "loaded", attempt: request.attempt, detail: issue }),
      () => {
        if (!controller.signal.aborted) dispatchDetail({ type: "failed", attempt: request.attempt })
      },
    )
  })

  // Driver: a status change. It is not aborted when the issue closes, because the server may already have applied it,
  // so the row is patched even when the answer is for an issue that is no longer open.
  const saveRequest = createMemo(
    () => {
      const current = detail()
      return current.type === "saving" ? { attempt: current.attempt, id: current.id, status: current.status } : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt && a?.status === b?.status },
  )
  createEffect(() => {
    const request = saveRequest()
    if (!request) return
    void sdk.api.experimental.issues.setStatus({ id: request.id, status: request.status }).then(
      (saved) => {
        dispatchList({ type: "patched", issue: saved })
        dispatchDetail({ type: "saved", attempt: request.attempt, detail: saved })
      },
      () => {
        dispatchDetail({ type: "saveFailed", attempt: request.attempt })
        showToast({ title: language.t("security.issues.status.error") })
      },
    )
  })

  // Driver: compliance. Without a benchmark the call lists them, with one it returns the controls.
  const complianceRequest = createMemo(
    () => {
      const current = compliance()
      return current.type === "loading" ? { attempt: current.attempt, benchmark: current.benchmark } : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt },
  )
  createEffect(() => {
    const request = complianceRequest()
    if (!request) return
    const controller = new AbortController()
    onCleanup(() => controller.abort())
    void sdk.api.experimental.rules.compliance({ benchmark: request.benchmark }, { signal: controller.signal }).then(
      (result) =>
        dispatchCompliance(
          "benchmarks" in result
            ? { type: "benchmarks", attempt: request.attempt, benchmarks: result.benchmarks }
            : { type: "controls", attempt: request.attempt, controls: result.controls },
        ),
      () => {
        if (!controller.signal.aborted) dispatchCompliance({ type: "failed", attempt: request.attempt })
      },
    )
  })

  const filters = createMemo(() => selectFilters(list()))
  const items = createMemo(() => selectItems(list()))
  const setFilter = (patch: Partial<Filters>) => dispatchList({ type: "filter", filters: { ...filters(), ...patch } })
  const pick = <T extends string>(options: readonly T[], value: string) => options.find((option) => option === value)
  const openId = createMemo(() => selectOpenId(detail()))
  const open = (id: string) => setParams({ id })
  const close = () => setParams({ id: undefined })
  const retry = (slot: string, message: string, onRetry: () => void) => (
    <div data-slot={slot} role="alert">
      <span>{message}</span>
      <button type="button" data-slot="issues-retry" onClick={onRetry}>
        {language.t("security.issues.retry")}
      </button>
    </div>
  )
  const loading = (label: string) => (
    <div data-slot="issues-loading" role="status">
      <Loader class="size-4" />
      <span>{label}</span>
    </div>
  )

  return (
    <div data-component="security-issues" class="mx-auto w-full max-w-[1200px] px-6 py-4">
      <h1 data-slot="issues-heading">{language.t("home.security.issues")}</h1>
      <div role="tablist" data-slot="issues-tabs">
        <For each={TABS}>
          {(item) => (
            <button
              type="button"
              role="tab"
              data-slot="issues-tab"
              aria-selected={tab() === item}
              onClick={() => setTab(item)}
            >
              {language.t(`security.issues.tab.${item}`)}
            </button>
          )}
        </For>
      </div>
      <Show
        when={tab() === "issues"}
        fallback={
          <Switch>
            <Match when={compliance().type === "failed"}>
              {retry("issues-error", language.t("security.issues.compliance.error"), () =>
                dispatchCompliance({ type: "retry" }),
              )}
            </Match>
            <Match when={(() => {
              const current = compliance()
              return current.type === "idle" || current.type === "loading"
            })()}>
              {loading(language.t("security.loading"))}
            </Match>
            <Match when={true}>
              {(() => {
                const current = compliance()
                if (current.type !== "ready") return undefined
                return (
                  <section data-slot="compliance">
                    <Show
                      when={current.benchmarks.length > 0}
                      fallback={<p data-slot="issues-hint">{language.t("security.issues.compliance.empty")}</p>}
                    >
                      <label data-slot="issues-filter">
                        <span>{language.t("security.issues.compliance.benchmark")}</span>
                        <select
                          value={current.benchmark}
                          onChange={(event) => dispatchCompliance({ type: "select", benchmark: event.currentTarget.value })}
                        >
                          <For each={current.benchmarks}>{(name) => <option value={name}>{name}</option>}</For>
                        </select>
                      </label>
                      <table data-slot="issues-table">
                        <thead>
                          <tr>
                            <th>{language.t("security.issues.compliance.control")}</th>
                            <th>{language.t("security.issues.compliance.status")}</th>
                            <th>{language.t("security.issues.compliance.failing")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          <For each={current.controls}>
                            {(control) => (
                              <tr>
                                <td>{control.control}</td>
                                <td data-status={control.status}>
                                  {language.t(`security.issues.compliance.status.${control.status}`)}
                                </td>
                                <td>{control.failingEntities}</td>
                              </tr>
                            )}
                          </For>
                        </tbody>
                      </table>
                    </Show>
                  </section>
                )
              })()}
            </Match>
          </Switch>
        }
      >
        <div data-slot="issues-filters">
          <label data-slot="issues-filter">
            <span>{language.t("security.issues.filter.category")}</span>
            <select
              value={filters().category ?? ""}
              onChange={(event) => setFilter({ category: pick(CATEGORIES, event.currentTarget.value) })}
            >
              <option value="">{language.t("security.issues.filter.all")}</option>
              <For each={CATEGORIES}>
                {(item) => <option value={item}>{language.t(`security.findings.category.${item}`)}</option>}
              </For>
            </select>
          </label>
          <label data-slot="issues-filter">
            <span>{language.t("security.issues.filter.severity")}</span>
            <select
              value={filters().severity ?? ""}
              onChange={(event) => setFilter({ severity: pick(SEVERITIES, event.currentTarget.value) })}
            >
              <option value="">{language.t("security.issues.filter.all")}</option>
              <For each={SEVERITIES}>
                {(item) => <option value={item}>{language.t(`home.security.overview.severity.${item}`)}</option>}
              </For>
            </select>
          </label>
          <label data-slot="issues-filter">
            <span>{language.t("security.issues.filter.status")}</span>
            <select
              value={filters().status ?? ""}
              onChange={(event) => setFilter({ status: pick(STATUSES, event.currentTarget.value) })}
            >
              <option value="">{language.t("security.issues.filter.all")}</option>
              <For each={STATUSES}>
                {(item) => <option value={item}>{language.t(`security.findings.status.${item}`)}</option>}
              </For>
            </select>
          </label>
          <label data-slot="issues-filter">
            <span>{language.t("security.issues.filter.asset")}</span>
            <input
              type="search"
              value={filters().asset ?? ""}
              placeholder={language.t("security.issues.filter.assetPlaceholder")}
              onChange={(event) => setFilter({ asset: event.currentTarget.value.trim() || undefined })}
            />
          </label>
        </div>
        <div data-slot="issues-body" data-open={openId() !== undefined}>
          <div data-slot="issues-list">
            <Show when={list().type === "failed"}>
              {retry("issues-error", language.t("security.issues.error"), () => dispatchList({ type: "retry" }))}
            </Show>
            <Show when={selectFirstLoad(list())}>{loading(language.t("security.loading"))}</Show>
            <Show
              when={items().length > 0}
              fallback={
                <Show when={list().type === "ready"}>
                  <div data-slot="issues-empty">
                    <strong>{language.t("security.issues.empty.title")}</strong>
                    <p>{language.t("security.issues.empty.description")}</p>
                  </div>
                </Show>
              }
            >
              <table data-slot="issues-table">
                <thead>
                  <tr>
                    <th>{language.t("security.issues.column.severity")}</th>
                    <th>{language.t("security.issues.column.title")}</th>
                    <th>{language.t("security.issues.column.risk")}</th>
                    <th>{language.t("security.issues.column.category")}</th>
                    <th>{language.t("security.issues.column.status")}</th>
                    <th>{language.t("security.issues.column.findings")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={items()}>
                    {(issue) => (
                      <tr data-slot="issue-row" data-severity={issue.severity} aria-selected={openId() === issue.id}>
                        <td data-slot="issue-severity">{language.t(`home.security.overview.severity.${issue.severity}`)}</td>
                        <td>
                          <button type="button" data-slot="issue-open" title={issue.title} onClick={() => open(issue.id)}>
                            {issue.title}
                          </button>
                          <Show when={issue.includesInferred}>
                            <span data-slot="inferred-badge">{language.t("security.issues.inferred")}</span>
                          </Show>
                        </td>
                        <td>{risk(issue.riskScore)}</td>
                        <td>{language.t(`security.findings.category.${issue.category}`)}</td>
                        <td>{language.t(`security.findings.status.${issue.status}`)}</td>
                        <td>{issue.findingCount}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </Show>
            <Show when={selectLoadingMore(list())}>{loading(language.t("security.issues.loadingMore"))}</Show>
            <Show when={selectHasMore(list())}>
              <button type="button" data-slot="issues-more" onClick={() => dispatchList({ type: "more" })}>
                {language.t("security.issues.more")}
              </button>
            </Show>
          </div>
          <Show when={openId()}>
            <aside data-slot="issue-detail" aria-label={language.t("security.issues.detail")}>
              <button type="button" data-slot="issues-close" onClick={close}>
                {language.t("security.issues.close")}
              </button>
              {(() => {
                const current = detail()
                if (current.type === "loading") return loading(language.t("security.loading"))
                if (current.type === "failed")
                  return retry("issues-error", language.t("security.issues.detail.error"), () =>
                    dispatchDetail({ type: "retry" }),
                  )
                if (current.type !== "ready" && current.type !== "saving") return undefined
                const issue = current.detail
                return (
                  <>
                    <h2 data-slot="issue-title">{issue.title}</h2>
                    <p data-slot="issue-meta">
                      <span data-severity={issue.severity}>
                        {language.t(`home.security.overview.severity.${issue.severity}`)}
                      </span>
                      <span>{language.t("security.issues.column.risk")}: {risk(issue.riskScore)}</span>
                      <span>{issue.ruleId}</span>
                    </p>
                    <label data-slot="issues-filter">
                      <span>{language.t("security.issues.column.status")}</span>
                      <select
                        data-slot="issue-status"
                        value={current.type === "saving" ? current.status : issue.status}
                        disabled={current.type === "saving"}
                        onChange={(event) => {
                          const status = pick(STATUSES, event.currentTarget.value)
                          if (status) dispatchDetail({ type: "setStatus", status })
                        }}
                      >
                        <For each={STATUSES}>
                          {(item) => <option value={item}>{language.t(`security.findings.status.${item}`)}</option>}
                        </For>
                      </select>
                      <Show when={current.type === "saving"}>
                        <span data-slot="issues-muted">{language.t("security.issues.status.saving")}</span>
                      </Show>
                      <Show when={current.type === "ready" && current.saveFailed}>
                        <span data-slot="issues-muted" role="alert">
                          {language.t("security.issues.status.error")}
                        </span>
                      </Show>
                    </label>
                    <h3>{language.t("security.issues.path")}</h3>
                    <ol data-slot="issue-path">
                      <For each={issue.path}>
                        {(hop) => (
                          <li data-slot="issue-hop" data-inferred={hop.inferred}>
                            <div data-slot="hop-head">
                              <Show when={hop.relation}>
                                {(relation) => <span data-slot="hop-relation">{relation()}</span>}
                              </Show>
                              <code data-slot="hop-entity">{hop.entityId}</code>
                              <Show when={hop.inferred}>
                                <span data-slot="inferred-badge">{language.t("security.issues.inferred")}</span>
                              </Show>
                            </div>
                            <Show when={hop.evidence.length > 0}>
                              <ul data-slot="hop-evidence" aria-label={language.t("security.issues.evidence")}>
                                <For each={hop.evidence}>{(entry) => <li>{entry}</li>}</For>
                              </ul>
                            </Show>
                          </li>
                        )}
                      </For>
                    </ol>
                    <h3>{language.t("security.issues.members")}</h3>
                    <Show
                      when={issue.findings.length > 0}
                      fallback={<p data-slot="issues-muted">{language.t("security.issues.members.empty")}</p>}
                    >
                      <ul data-slot="issue-members">
                        <For each={issue.findings}>
                          {(member) => (
                            <li>
                              <A href={findingPath(member.id)} data-slot="member-link">
                                {member.title ?? member.id}
                              </A>
                              <Show when={member.severity}>
                                <span data-slot="issues-muted">{member.severity}</span>
                              </Show>
                            </li>
                          )}
                        </For>
                      </ul>
                    </Show>
                  </>
                )
              })()}
            </aside>
          </Show>
        </div>
      </Show>
    </div>
  )
}
