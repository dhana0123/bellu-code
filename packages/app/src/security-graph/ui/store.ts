// One store per Security Graph view. It holds what the chrome components share: selection, focus, filters, search
// text, panel sizes and the attack paths on show. The filter predicate belongs to `filters.ts`; the store only
// keeps the chosen values.
import { createStore, reconcile } from "solid-js/store"
import { initialAgentState, type AgentState } from "../agents/events"
import type { AttackPath } from "../model"

export const filterDimensions = [
  "repository",
  "service",
  "environment",
  "type",
  "tag",
  "severity",
  "boundary",
  "agent",
] as const
export type FilterDimension = (typeof filterDimensions)[number]
/** Selected values per dimension. An empty list means the dimension does not filter. */
export type Filters = Record<FilterDimension, string[]>

export type PanelId = "inspector" | "activity" | "editor" | "terminal"
/** Panel sizes in pixels. */
export type PanelSizes = Record<PanelId, number>

export type ViewState = {
  /** Selected entity id. */
  selection?: string
  /** Entity the camera was last focused on. */
  focus?: string
  filters: Filters
  query: string
  panels: PanelSizes
  /** Id of the attack path selected for the Inspector. */
  selectedPathId?: string
  /** Attack paths drawn on the graph. */
  attackPaths: AttackPath[]
  agents: AgentState
}

export const defaultPanelSizes = { inspector: 360, activity: 320, editor: 480, terminal: 240 } as const satisfies PanelSizes

export const emptyFilters = (): Filters => ({
  repository: [],
  service: [],
  environment: [],
  type: [],
  tag: [],
  severity: [],
  boundary: [],
  agent: [],
})

export const activeFilterCount = (filters: Filters) =>
  filterDimensions.reduce((sum, dimension) => sum + filters[dimension].length, 0)

export type ViewStore = ReturnType<typeof createViewStore>

export function createViewStore() {
  const [state, setState] = createStore<ViewState>({
    filters: emptyFilters(),
    query: "",
    panels: { ...defaultPanelSizes },
    attackPaths: [],
    agents: initialAgentState,
  })
  return {
    state,
    select: (id: string | undefined) => setState("selection", id),
    focus: (id: string | undefined) => setState("focus", id),
    setFilter: (dimension: FilterDimension, values: string[]) => setState("filters", dimension, values),
    clearFilters: () => setState("filters", emptyFilters()),
    setQuery: (query: string) => setState("query", query),
    resizePanel: (panel: PanelId, size: number) => setState("panels", panel, Math.max(0, Math.round(size))),
    selectPath: (id: string | undefined) => setState("selectedPathId", id),
    showAttackPaths: (paths: AttackPath[]) => setState("attackPaths", paths),
    // The reducer builds a fresh state per event, so reconcile keeps unchanged agents and findings as they were.
    setAgents: (next: AgentState) => setState("agents", reconcile(next)),
  }
}
