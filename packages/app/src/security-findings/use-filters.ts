import { useSearchParams } from "@solidjs/router"
import { createMemo } from "solid-js"
import {
  CATEGORIES,
  FINDING_TYPES,
  PAGE_SIZES,
  SEVERITIES,
  SORT_KEYS,
  STATUSES,
  type FilterState,
  type SortState,
  type ViewMode,
} from "./model"

type Params = Record<string, string | string[] | undefined>

/**
 * The single source of filter, sort, view and paging state. It lives in the URL query, so a view is shareable and
 * survives a refresh. Every write replaces the history entry instead of adding one.
 */
export function useFilters() {
  const [params, setParams] = useSearchParams<Params>()

  const filters = createMemo<FilterState>(() => ({
    search: text(params.q),
    severity: SEVERITIES.find((item) => item === text(params.sev)) ?? "all",
    types: list(params.type, FINDING_TYPES),
    statuses: list(params.status, STATUSES),
    categories: list(params.cat, CATEGORIES),
    asset: text(params.asset) || undefined,
  }))
  const view = createMemo<ViewMode>(() => (params.view === "treemap" ? "treemap" : "table"))
  const sort = createMemo<SortState>(() => {
    const [key, dir] = text(params.sort).split(":")
    const match = SORT_KEYS.find((item) => item === key)
    return match && (dir === "asc" || dir === "desc") ? { key: match, dir } : undefined
  })
  const pageSize = createMemo(() => PAGE_SIZES.find((size) => String(size) === text(params.size)) ?? PAGE_SIZES[0])
  const page = createMemo(() => Math.max(1, Number.parseInt(text(params.page), 10) || 1))

  const write = (values: Params) => setParams(values, { replace: true })

  return {
    filters,
    view,
    sort,
    page,
    pageSize,
    /** Merges a change into the filters and returns to the first page. `view` switches the view in the same write. */
    update(patch: Partial<FilterState>, view?: ViewMode) {
      const next = { ...filters(), ...patch }
      write({
        q: next.search || undefined,
        sev: next.severity === "all" ? undefined : next.severity,
        type: next.types.join(",") || undefined,
        status: next.statuses.join(",") || undefined,
        cat: next.categories.join(",") || undefined,
        asset: next.asset,
        page: undefined,
        ...(view ? { view: view === "table" ? undefined : view } : {}),
      })
    },
    /** Resets every filter, including the search text. View, sort and page size stay. */
    clear() {
      write({
        q: undefined,
        sev: undefined,
        type: undefined,
        status: undefined,
        cat: undefined,
        asset: undefined,
        page: undefined,
      })
    },
    setView: (next: ViewMode) => write({ view: next === "table" ? undefined : next }),
    setSort: (next: SortState) => write({ sort: next ? `${next.key}:${next.dir}` : undefined, page: undefined }),
    setPage: (next: number) => write({ page: next <= 1 ? undefined : String(next) }),
    setPageSize: (next: number) => write({ size: next === PAGE_SIZES[0] ? undefined : String(next), page: undefined }),
  }
}

export const hasActiveFilters = (filters: FilterState) =>
  filters.search !== "" ||
  filters.severity !== "all" ||
  filters.types.length + filters.statuses.length + filters.categories.length > 0 ||
  filters.asset !== undefined

function text(value: string | string[] | undefined) {
  return typeof value === "string" ? value : ""
}

function list<T extends string>(value: string | string[] | undefined, allowed: readonly T[]) {
  return text(value)
    .split(",")
    .filter((item): item is T => allowed.some((option) => option === item))
}
