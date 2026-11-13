import { describe, expect, test } from "bun:test"
import type { Connectors } from "@bellucode/schema/connectors"
import {
  INITIAL_OFFLINE_STATE,
  buildCards,
  cardState,
  clearCredentials,
  expiresSoon,
  rotationDue,
  selectOffline,
  transitionOffline,
  validateAlias,
} from "./machine"
import type { OfflineEvent, OfflineState } from "./machine"

function run(events: readonly OfflineEvent[], from: OfflineState = INITIAL_OFFLINE_STATE) {
  return events.reduce((state, event) => transitionOffline(state, event).state, from)
}

const manifest = (id: string, enabled: boolean) =>
  ({
    id,
    version: "1",
    name: id,
    icon: id,
    auth_methods: [{ id: "m", name: "m", enabled }],
    permissions: [],
    operations: [],
    egress: [],
    entities: [],
  }) as Connectors.Manifest

const connection = (patch: Partial<Connectors.Connection>) =>
  ({
    id: "c1",
    connectorId: "aws",
    alias: "work",
    status: "ACTIVE",
    removed: false,
    rotationIntervalDays: 90,
    credentialCreatedAt: null,
    credentialExpiresAt: null,
    ...patch,
  }) as Connectors.Connection

describe("offline machine", () => {
  test("a probe timeout goes offline and the next successful probe clears it", () => {
    const offline = run([{ type: "tick" }, { type: "probe.timed-out", attempt: 1 }])
    expect(selectOffline(offline)).toBe(true)
    const online = run([{ type: "tick" }, { type: "probe.succeeded", attempt: 2 }], offline)
    expect(selectOffline(online)).toBe(false)
  })

  test("stale results and ticks during a probe return the same state", () => {
    const probing = run([{ type: "tick" }])
    expect(transitionOffline(probing, { type: "tick" }).state).toBe(probing)
    expect(transitionOffline(probing, { type: "probe.failed", attempt: 99 }).state).toBe(probing)
    const idle = run([{ type: "probe.succeeded", attempt: 1 }], probing)
    expect(transitionOffline(idle, { type: "probe.succeeded", attempt: 1 }).state).toBe(idle)
  })

  test("a new probe after a stale one carries a fresh attempt id", () => {
    const first = transitionOffline(INITIAL_OFFLINE_STATE, { type: "tick" })
    const failed = run([{ type: "probe.failed", attempt: 1 }], first.state)
    const second = transitionOffline(failed, { type: "tick" })
    expect(second.effects).toEqual([{ type: "probe.run", attempt: 2, timeoutMs: 5000 }])
    expect(transitionOffline(second.state, { type: "probe.succeeded", attempt: 1 }).state).toBe(second.state)
  })

  test("dispose cancels work and ignores late results", () => {
    const probing = run([{ type: "tick" }])
    const disposed = transitionOffline(probing, { type: "disposed" })
    expect(disposed.effects).toEqual([{ type: "probe.cancel" }, { type: "tick.cancel" }])
    expect(transitionOffline(disposed.state, { type: "probe.succeeded", attempt: 1 }).state).toBe(disposed.state)
  })
})

describe("alias validation", () => {
  const list = [connection({ id: "c1", alias: "work" }), connection({ id: "c2", connectorId: "github", alias: "dev" })]

  test("enforces length and per-connector uniqueness, excluding the edited connection", () => {
    expect(validateAlias("", "aws", list)).toBe("empty")
    expect(validateAlias("x".repeat(41), "aws", list)).toBe("too-long")
    expect(validateAlias("x".repeat(40), "aws", list)).toBeUndefined()
    expect(validateAlias("work", "aws", list)).toBe("taken")
    expect(validateAlias("work", "aws", list, "c1" as Connectors.ConnectionID)).toBeUndefined()
    expect(validateAlias("dev", "aws", list)).toBeUndefined()
  })
})

describe("cards", () => {
  test("one card per catalog id, with removed connections ignored", () => {
    const cards = buildCards(
      [manifest("aws", true), manifest("aws", true), manifest("gitlab", false)],
      [connection({ removed: true, status: "ERROR" })],
    )
    expect(cards.map((card) => [card.manifest.id, card.state])).toEqual([
      ["aws", "available"],
      ["gitlab", "coming-soon"],
    ])
  })
})

// Property 36, as an exhaustive generated table: fast-check is not a dependency of packages/app.
describe("card state mapping (Property 36)", () => {
  const statuses: Connectors.Status[] = ["INITIATED", "VERIFYING", "ACTIVE", "EXPIRED", "PAUSED", "ERROR"]
  // Oracle: each status maps to a state on its own; the most urgent state among the statuses wins.
  const single: Record<Connectors.Status, string> = {
    ACTIVE: "connected",
    INITIATED: "connecting",
    VERIFYING: "connecting",
    EXPIRED: "needs-attention",
    ERROR: "needs-attention",
    PAUSED: "paused",
  }
  const urgency = ["needs-attention", "connecting", "connected", "paused"]
  const subsets = Array.from({ length: 1 << statuses.length }, (_, mask) => statuses.filter((_, i) => mask & (1 << i)))

  test("every implemented flag and every status subset yields the single expected state", () => {
    for (const implemented of [true, false]) {
      for (const subset of subsets) {
        const mapped = subset.map((status) => single[status])
        const expected = urgency.find((state) => mapped.includes(state)) ?? (implemented ? "available" : "coming-soon")
        expect(cardState(implemented, subset), `${implemented} ${subset.join(",")}`).toBe(expected as never)
      }
    }
  })

  test("buildCards yields one card per distinct catalog id in order, owning only its live connections", () => {
    const ids = ["aws", "github", "gitlab"]
    // Catalog: every sequence of ids of length 0..4 (with repeats), each id implemented or not by its first position.
    const sequences: string[][] = [[]]
    for (let n = 0; n < 4; n++)
      for (const seq of sequences.filter((s) => s.length === n)) for (const id of ids) sequences.push([...seq, id])
    for (const seq of sequences) {
      const catalog = seq.map((id, i) => manifest(id, id !== "gitlab" && i % 2 === 0))
      // One live and one removed connection per status per id.
      const connections = ids.flatMap((id) =>
        statuses.flatMap((status) => [
          connection({
            id: `${id}-${status}` as Connectors.ConnectionID,
            connectorId: id as Connectors.ConnectorID,
            status,
          }),
          connection({
            id: `${id}-${status}-x` as Connectors.ConnectionID,
            connectorId: id as Connectors.ConnectorID,
            status: "ERROR",
            removed: true,
          }),
        ]),
      )
      const cards = buildCards(catalog, connections)
      const distinct = [...new Set(seq)]
      expect(cards.map((card) => card.manifest.id)).toEqual(distinct as never)
      for (const card of cards) {
        expect(card.manifest).toBe(catalog.find((m) => m.id === card.manifest.id)!)
        expect(card.connections.map((c) => c.id)).toEqual(statuses.map((s) => `${card.manifest.id}-${s}`) as never)
        expect(card.state).toBe("needs-attention")
      }
    }
  })

  test("a card without live connections is available or coming soon by its manifest", () => {
    const cards = buildCards([manifest("aws", true), manifest("gitlab", false)], [])
    expect(cards.map((card) => card.state)).toEqual(["available", "coming-soon"])
  })
})

describe("expiry and rotation", () => {
  const now = Date.parse("2026-01-10T00:00:00Z")

  test("expires soon only inside 7 days and before expiry", () => {
    expect(expiresSoon(connection({ credentialExpiresAt: "2026-01-16T00:00:00Z" }), now)).toBe(true)
    expect(expiresSoon(connection({ credentialExpiresAt: "2026-01-17T00:00:00Z" }), now)).toBe(false)
    expect(expiresSoon(connection({ credentialExpiresAt: "2026-01-09T00:00:00Z" }), now)).toBe(false)
  })

  test("rotation is due for a non-expiring credential older than its interval", () => {
    expect(rotationDue(connection({ credentialCreatedAt: "2025-10-01T00:00:00Z" }), now)).toBe(true)
    expect(rotationDue(connection({ credentialCreatedAt: "2025-12-01T00:00:00Z" }), now)).toBe(false)
    expect(
      rotationDue(
        connection({ credentialCreatedAt: "2025-10-01T00:00:00Z", credentialExpiresAt: "2026-02-01T00:00:00Z" }),
        now,
      ),
    ).toBe(false)
  })
})

describe("credential clearing", () => {
  test("empties every value and keeps keys", () => {
    expect(clearCredentials({ access_key_id: "AKIA", secret_access_key: "s" })).toEqual({
      access_key_id: "",
      secret_access_key: "",
    })
  })
})
