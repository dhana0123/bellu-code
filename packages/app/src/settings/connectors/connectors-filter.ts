import type { ConnectorCard } from "./machine"

/** The list's view state: a free-text query and a state filter. Pure selectors derive the visible cards. */
export type ConnectorFilter = "all" | "connected" | "available" | "coming-soon"
export type ConnectorsView = { query: string; filter: ConnectorFilter }

export const INITIAL_CONNECTORS_VIEW: Readonly<ConnectorsView> = Object.freeze({ query: "", filter: "all" })

export const CONNECTOR_FILTERS = [
  { id: "all", key: "settings.connectors.filter.all" },
  { id: "connected", key: "settings.connectors.filter.connected" },
  { id: "available", key: "settings.connectors.filter.available" },
  { id: "coming-soon", key: "settings.connectors.filter.comingSoon" },
] as const

export function matchesFilter(card: ConnectorCard, filter: ConnectorFilter) {
  if (filter === "all") return true
  if (filter === "connected") return card.connections.length > 0
  if (filter === "coming-soon") return card.state === "coming-soon"
  return card.state === "available"
}

/** Case-insensitive match on the displayed name and description. An empty query matches everything. */
export function matchesQuery(name: string, description: string | undefined, query: string) {
  const needle = query.trim().toLowerCase()
  if (!needle) return true
  return name.toLowerCase().includes(needle) || (description ?? "").toLowerCase().includes(needle)
}

export function isFiltering(view: ConnectorsView) {
  return view.query.trim() !== "" || view.filter !== "all"
}
