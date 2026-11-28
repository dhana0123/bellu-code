import type { Connectors } from "@bellucode/schema/connectors"

export const CONNECTORS_PROBE_TIMEOUT_MS = 5_000
export const CONNECTORS_POLL_INTERVAL_MS = 5_000
export const ALIAS_MAX_LENGTH = 40
export const EXPIRES_SOON_DAYS = 7

const DAY_MS = 86_400_000

// ---------------------------------------------------------------------------
// Card state (Requirements 1.3, 1.4, 1.5, 14.2)
// ---------------------------------------------------------------------------

export type CardState = "available" | "coming-soon" | "connecting" | "connected" | "paused" | "needs-attention"

export type ConnectorCard = {
  readonly manifest: Connectors.Manifest
  readonly connections: readonly Connectors.Connection[]
  readonly state: CardState
}

/**
 * A connector is implemented when its manifest offers at least one enabled auth method; a catalog-only card has none.
 * The catalog payload is the only source, so plugins and built-ins are treated alike.
 */
export function isImplemented(manifest: Connectors.Manifest) {
  return manifest.auth_methods.some((method) => method.enabled)
}

/**
 * Exactly one state per card. With several Connections the most urgent wins: needs attention, then connecting,
 * connected, paused. Removed tombstones never count.
 */
export function cardState(implemented: boolean, statuses: readonly Connectors.Status[]): CardState {
  if (statuses.includes("EXPIRED") || statuses.includes("ERROR")) return "needs-attention"
  if (statuses.includes("INITIATED") || statuses.includes("VERIFYING")) return "connecting"
  if (statuses.includes("ACTIVE")) return "connected"
  if (statuses.includes("PAUSED")) return "paused"
  return implemented ? "available" : "coming-soon"
}

/** One card per catalog connector id, in catalog order. A repeated id keeps its first manifest. */
export function buildCards(
  catalog: readonly Connectors.Manifest[],
  connections: readonly Connectors.Connection[],
): readonly ConnectorCard[] {
  const live = connections.filter((connection) => !connection.removed)
  return catalog
    .filter((manifest, index) => catalog.findIndex((other) => other.id === manifest.id) === index)
    .map((manifest) => {
      const own = live.filter((connection) => connection.connectorId === manifest.id)
      return {
        manifest,
        connections: own,
        state: cardState(
          isImplemented(manifest),
          own.map((connection) => connection.status),
        ),
      }
    })
}

export function selectCardConnectionCount(card: ConnectorCard) {
  return card.connections.length
}

/** Connect is offered only for an implemented connector while the service answers. */
export function selectConnectEnabled(card: ConnectorCard, offline: boolean) {
  return !offline && card.state !== "coming-soon"
}

// ---------------------------------------------------------------------------
// Alias validation (Requirements 1.13, 1.15)
// ---------------------------------------------------------------------------

export type AliasError = "empty" | "too-long" | "taken"

/**
 * `editing` names the Connection being renamed so its own alias does not collide with itself. Length counts
 * characters, not UTF-16 units.
 */
export function validateAlias(
  alias: string,
  connectorId: Connectors.ConnectorID,
  connections: readonly Connectors.Connection[],
  editing?: Connectors.ConnectionID,
): AliasError | undefined {
  const length = [...alias].length
  if (length < 1) return "empty"
  if (length > ALIAS_MAX_LENGTH) return "too-long"
  const taken = connections.some(
    (connection) =>
      !connection.removed &&
      connection.connectorId === connectorId &&
      connection.id !== editing &&
      connection.alias === alias,
  )
  return taken ? "taken" : undefined
}

/**
 * The name a new Connection gets when the user types none: the connector id, then `-2`, `-3` and so on until it is
 * unused for that connector.
 */
export function defaultAlias(connectorId: Connectors.ConnectorID, connections: readonly Connectors.Connection[]) {
  const taken = new Set(
    connections
      .filter((connection) => !connection.removed && connection.connectorId === connectorId)
      .map((connection) => connection.alias),
  )
  if (!taken.has(connectorId)) return connectorId
  const next = Array.from({ length: taken.size + 1 }, (_, index) => `${connectorId}-${index + 2}`).find(
    (alias) => !taken.has(alias),
  )
  return next ?? `${connectorId}-${taken.size + 2}`
}

// ---------------------------------------------------------------------------
// Credential fields (Requirements 2.9, 10.6)
// ---------------------------------------------------------------------------

/** Every field emptied, keys kept, so the inputs stay mounted. */
export function clearCredentials(fields: Connectors.CredentialInput): Connectors.CredentialInput {
  return Object.fromEntries(Object.keys(fields).map((key) => [key, ""]))
}

// ---------------------------------------------------------------------------
// Expiry and rotation (Requirements 4.10, 9.10)
// ---------------------------------------------------------------------------

/** Expiring within 7 days, not yet expired. `now` is epoch ms from the caller's clock. */
export function expiresSoon(connection: Connectors.Connection, now: number) {
  if (!connection.credentialExpiresAt) return false
  const expires = Date.parse(connection.credentialExpiresAt)
  if (Number.isNaN(expires)) return false
  return expires > now && expires - now < EXPIRES_SOON_DAYS * DAY_MS
}

/** A static credential (one that never expires) older than its rotation interval. */
export function rotationDue(connection: Connectors.Connection, now: number) {
  if (connection.removed || connection.credentialExpiresAt || !connection.credentialCreatedAt) return false
  if (!(connection.rotationIntervalDays > 0)) return false
  const created = Date.parse(connection.credentialCreatedAt)
  if (Number.isNaN(created)) return false
  return now - created > connection.rotationIntervalDays * DAY_MS
}

// ---------------------------------------------------------------------------
// Offline machine (Requirement 2.6 of the page: 5 s probe, clear within 10 s)
// ---------------------------------------------------------------------------

/**
 * The service probe. `offline` is a field of both live variants because nothing else distinguishes them for the user.
 * The driver ticks every `CONNECTORS_POLL_INTERVAL_MS`, so a recovered service clears the banner within one interval
 * plus one probe, inside the 10 s the requirement allows.
 */
export type OfflineState =
  | { readonly status: "idle"; readonly issued: number; readonly offline: boolean }
  | { readonly status: "probing"; readonly issued: number; readonly attempt: number; readonly offline: boolean }
  | { readonly status: "disposed" }

export type OfflineEvent =
  | { readonly type: "tick" }
  | { readonly type: "probe.succeeded"; readonly attempt: number }
  | { readonly type: "probe.failed"; readonly attempt: number }
  | { readonly type: "probe.timed-out"; readonly attempt: number }
  | { readonly type: "disposed" }

export type OfflineEffect =
  | { readonly type: "probe.run"; readonly attempt: number; readonly timeoutMs: number }
  /** Stops waiting for the probe; the request itself may still finish. */
  | { readonly type: "probe.cancel" }
  | { readonly type: "tick.schedule"; readonly delayMs: number }
  | { readonly type: "tick.cancel" }

export type OfflineTransition = {
  readonly state: OfflineState
  readonly effects: readonly OfflineEffect[]
}

export const INITIAL_OFFLINE_STATE: OfflineState = Object.freeze({ status: "idle", issued: 0, offline: false })

const DISPOSED: OfflineState = Object.freeze({ status: "disposed" })
const NONE: readonly OfflineEffect[] = Object.freeze([])

export function transitionOffline(state: OfflineState, event: OfflineEvent): OfflineTransition {
  if (state.status === "disposed") return unchanged(state)

  if (event.type === "disposed") {
    return { state: DISPOSED, effects: [{ type: "probe.cancel" }, { type: "tick.cancel" }] }
  }

  if (event.type === "tick") {
    // A tick that lands during a probe is dropped; the probe's own result schedules the next one.
    if (state.status !== "idle") return unchanged(state)
    const attempt = state.issued + 1
    return {
      state: { status: "probing", issued: attempt, attempt, offline: state.offline },
      effects: [{ type: "probe.run", attempt, timeoutMs: CONNECTORS_PROBE_TIMEOUT_MS }],
    }
  }

  if (state.status !== "probing" || state.attempt !== event.attempt) return unchanged(state)

  const offline = event.type !== "probe.succeeded"
  const effects: OfflineEffect[] = [{ type: "tick.schedule", delayMs: CONNECTORS_POLL_INTERVAL_MS }]
  // A timeout stops waiting for a probe that is still pending.
  return {
    state: { status: "idle", issued: state.issued, offline },
    effects: event.type === "probe.timed-out" ? [{ type: "probe.cancel" }, ...effects] : effects,
  }
}

export function selectOffline(state: OfflineState) {
  return state.status !== "disposed" && state.offline
}

/** Connect actions are disabled while the service is offline. */
export function selectConnectActionsDisabled(state: OfflineState) {
  return selectOffline(state)
}

function unchanged(state: OfflineState): OfflineTransition {
  return { state, effects: NONE }
}
