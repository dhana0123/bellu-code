import type { Connectors } from "@bellucode/schema/connectors"
import type { ConnectorCard } from "./machine"

/** Connectors planned but not yet in the backend catalog. They show as "Coming soon" cards and cannot be connected. */
const PLANNED: readonly (readonly [id: string, name: string])[] = []

/**
 * Catalog cards first (live ones before the catalog's own coming-soon ones), then the planned connectors the catalog
 * does not list. A catalog entry always wins over a planned one with the same id.
 */
export function withPlannedCards(cards: readonly ConnectorCard[]): readonly ConnectorCard[] {
  const planned = PLANNED.filter(([id]) => !cards.some((card) => card.manifest.id === id)).map(
    ([id, name]): ConnectorCard => ({
      manifest: {
        id: id as Connectors.ConnectorID,
        version: "0",
        name,
        icon: id,
        auth_methods: [],
        permissions: [],
        operations: [],
        egress: [],
        entities: [],
      },
      connections: [],
      state: "coming-soon",
    }),
  )
  return [...cards.filter((card) => card.state !== "coming-soon"), ...cards.filter((card) => card.state === "coming-soon"), ...planned]
}
