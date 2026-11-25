import type { IssuesDetail, IssuesIssue, IssuesStatus, RulesControl } from "@bellucode/client/promise"
// Lifecycles of the Issues page. Every request carries an attempt id, and a result for another attempt changes nothing.
export const CATEGORIES = [
  "cloud_infrastructure",
  "identity",
  "vulnerabilities",
  "network_exposure",
  "secrets",
  "data_security",
  "code_and_dependencies",
  "runtime",
  "ai_security",
] as const
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
export const STATUSES = ["open", "resolved", "ignored"] as const
export const PAGE_LIMIT = 50
export type Filters = {
  readonly category?: (typeof CATEGORIES)[number]
  readonly severity?: (typeof SEVERITIES)[number]
  readonly status?: IssuesStatus
  readonly asset?: string
}
export const NO_FILTERS: Filters = {}

// The issue table. A filter change starts a new first page; `more` appends the next cursor page.
type Items = readonly IssuesIssue[]
export type ListState =
  | { type: "loading"; attempt: number; filters: Filters; items: Items; cursor?: string }
  | { type: "ready"; attempt: number; filters: Filters; items: Items; next?: string; truncated: boolean }
  | { type: "failed"; attempt: number; filters: Filters; items: Items; cursor?: string }
  | { type: "disposed" }
export type ListEvent =
  | { type: "filter"; filters: Filters }
  | { type: "more" }
  | { type: "retry" }
  | { type: "loaded"; attempt: number; items: Items; next?: string; truncated: boolean }
  | { type: "failed"; attempt: number }
  /** An issue changed elsewhere (a status action). Keeps the row in step without reloading the page. */
  | { type: "patched"; issue: IssuesIssue }
  | { type: "disposed" }
export const listInitial = (filters: Filters): ListState => ({ type: "loading", attempt: 1, filters, items: [] })
export function listTransition(state: ListState, event: ListEvent): ListState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "filter") {
    if (sameFilters(state.filters, event.filters)) return state
    return { type: "loading", attempt: state.attempt + 1, filters: event.filters, items: [] }
  }
  if (event.type === "more") {
    if (state.type !== "ready" || state.next === undefined) return state
    return { type: "loading", attempt: state.attempt + 1, filters: state.filters, items: state.items, cursor: state.next }
  }
  if (event.type === "retry") {
    if (state.type !== "failed") return state
    return { type: "loading", attempt: state.attempt + 1, filters: state.filters, items: state.items, cursor: state.cursor }
  }
  if (event.type === "patched") {
    if (state.type === "loading" || !state.items.some((item) => item.id === event.issue.id)) return state
    return { ...state, items: state.items.map((item) => (item.id === event.issue.id ? event.issue : item)) }
  }
  if (state.type !== "loading" || state.attempt !== event.attempt) return state
  if (event.type === "failed")
    return { type: "failed", attempt: state.attempt, filters: state.filters, items: state.items, cursor: state.cursor }
  return {
    type: "ready",
    attempt: state.attempt,
    filters: state.filters,
    items: state.cursor === undefined ? event.items : [...state.items, ...event.items],
    next: event.next,
    truncated: event.truncated,
  }
}
const sameFilters = (a: Filters, b: Filters) =>
  a.category === b.category && a.severity === b.severity && a.status === b.status && a.asset === b.asset
export const selectItems = (state: ListState): Items => (state.type === "disposed" ? [] : state.items)
export const selectFilters = (state: ListState): Filters => (state.type === "disposed" ? NO_FILTERS : state.filters)
export const selectFirstLoad = (state: ListState) => state.type === "loading" && state.cursor === undefined
export const selectLoadingMore = (state: ListState) => state.type === "loading" && state.cursor !== undefined
export const selectHasMore = (state: ListState) => state.type === "ready" && state.next !== undefined

// The open issue. Setting the status runs inside `ready`, and a second request while one saves changes nothing.
export type DetailState =
  | { type: "closed"; attempt: number }
  | { type: "loading"; attempt: number; id: string }
  | { type: "ready"; attempt: number; id: string; detail: IssuesDetail; saveFailed: boolean }
  | { type: "saving"; attempt: number; id: string; detail: IssuesDetail; status: IssuesStatus }
  | { type: "failed"; attempt: number; id: string }
  | { type: "disposed" }
export type DetailEvent =
  | { type: "open"; id: string }
  | { type: "close" }
  | { type: "retry" }
  | { type: "loaded"; attempt: number; detail: IssuesDetail }
  | { type: "failed"; attempt: number }
  | { type: "setStatus"; status: IssuesStatus }
  | { type: "saved"; attempt: number; detail: IssuesDetail }
  | { type: "saveFailed"; attempt: number }
  | { type: "disposed" }
export const detailInitial = (id: string | undefined): DetailState =>
  id === undefined ? { type: "closed", attempt: 0 } : { type: "loading", attempt: 1, id }
export function detailTransition(state: DetailState, event: DetailEvent): DetailState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "open") {
    if (state.type !== "closed" && state.id === event.id) return state
    return { type: "loading", attempt: state.attempt + 1, id: event.id }
  }
  if (event.type === "close") return state.type === "closed" ? state : { type: "closed", attempt: state.attempt + 1 }
  if (event.type === "retry") return state.type === "failed" ? { type: "loading", attempt: state.attempt + 1, id: state.id } : state
  if (event.type === "setStatus") {
    if (state.type !== "ready" || state.detail.status === event.status) return state
    return { type: "saving", attempt: state.attempt, id: state.id, detail: state.detail, status: event.status }
  }
  if (event.attempt !== state.attempt) return state
  if (event.type === "loaded")
    return state.type === "loading" ? { type: "ready", attempt: state.attempt, id: state.id, detail: event.detail, saveFailed: false } : state
  if (event.type === "failed") return state.type === "loading" ? { type: "failed", attempt: state.attempt, id: state.id } : state
  if (state.type !== "saving") return state
  return event.type === "saved"
    ? { type: "ready", attempt: state.attempt, id: state.id, detail: event.detail, saveFailed: false }
    : { type: "ready", attempt: state.attempt, id: state.id, detail: state.detail, saveFailed: true }
}
export const selectOpenId = (state: DetailState) =>
  state.type === "closed" || state.type === "disposed" ? undefined : state.id

// The Compliance tab: the benchmark list first, then the controls of the chosen benchmark (the first by default).
export type ComplianceState =
  | { type: "idle" }
  | { type: "loading"; attempt: number; benchmarks: readonly string[]; benchmark?: string }
  | {
      type: "ready"
      attempt: number
      benchmarks: readonly string[]
      benchmark?: string
      controls: readonly RulesControl[]
    }
  | { type: "failed"; attempt: number; benchmarks: readonly string[]; benchmark?: string }
  | { type: "disposed" }
export type ComplianceEvent =
  | { type: "start" }
  | { type: "select"; benchmark: string }
  | { type: "retry" }
  | { type: "benchmarks"; attempt: number; benchmarks: readonly string[] }
  | { type: "controls"; attempt: number; controls: readonly RulesControl[] }
  | { type: "failed"; attempt: number }
  | { type: "disposed" }
export const complianceInitial: ComplianceState = { type: "idle" }
export function complianceTransition(state: ComplianceState, event: ComplianceEvent): ComplianceState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "start") return state.type === "idle" ? { type: "loading", attempt: 1, benchmarks: [] } : state
  if (state.type === "idle") return state
  if (event.type === "select") {
    if (state.benchmark === event.benchmark) return state
    return { type: "loading", attempt: state.attempt + 1, benchmarks: state.benchmarks, benchmark: event.benchmark }
  }
  if (event.type === "retry") {
    if (state.type !== "failed") return state
    return { type: "loading", attempt: state.attempt + 1, benchmarks: state.benchmarks, benchmark: state.benchmark }
  }
  if (state.type !== "loading" || state.attempt !== event.attempt) return state
  if (event.type === "failed")
    return { type: "failed", attempt: state.attempt, benchmarks: state.benchmarks, benchmark: state.benchmark }
  if (event.type === "benchmarks") {
    const first = event.benchmarks.at(0)
    return first === undefined
      ? { type: "ready", attempt: state.attempt, benchmarks: event.benchmarks, controls: [] }
      : { type: "loading", attempt: state.attempt + 1, benchmarks: event.benchmarks, benchmark: first }
  }
  return { type: "ready", attempt: state.attempt, benchmarks: state.benchmarks, benchmark: state.benchmark, controls: event.controls }
}
