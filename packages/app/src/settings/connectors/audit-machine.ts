import type { Connectors } from "@bellucode/schema/connectors"
import type { ConnectorFailure } from "./errors"
import { CONNECTORS_REQUEST_TIMEOUT_MS } from "./mutation-machine"

/**
 * Audit paging for one Connection, 50 entries per page and newest first (the server owns the page size). `items` and
 * `next` survive a failed page so Retry continues where the list stopped. `next` is the cursor of the following page;
 * it is absent on the last page.
 */
export type AuditState =
  | {
      readonly status: "idle"
      readonly issued: number
      readonly id: string
      readonly items: readonly Connectors.AuditEntry[]
      readonly next?: string
      readonly loaded: boolean
    }
  | {
      readonly status: "loading"
      readonly issued: number
      readonly attempt: number
      readonly id: string
      readonly items: readonly Connectors.AuditEntry[]
      readonly next?: string
      readonly loaded: boolean
    }
  | {
      readonly status: "failed"
      readonly issued: number
      readonly id: string
      readonly items: readonly Connectors.AuditEntry[]
      readonly next?: string
      readonly loaded: boolean
      readonly failure: ConnectorFailure
    }
  | { readonly status: "disposed" }

export type AuditEvent =
  | { readonly type: "target.synced"; readonly id: string }
  /** The next page, or the first one when nothing has loaded. Retry sends the same event. */
  | { readonly type: "page.requested" }
  | { readonly type: "page.loaded"; readonly attempt: number; readonly page: Connectors.AuditPage }
  | { readonly type: "page.failed"; readonly attempt: number; readonly failure: ConnectorFailure }
  | { readonly type: "disposed" }

export type AuditEffect =
  | {
      readonly type: "run"
      readonly attempt: number
      readonly id: string
      readonly cursor?: string
      readonly timeoutMs: number
    }
  | { readonly type: "abort"; readonly attempt: number }

export type AuditTransition = { readonly state: AuditState; readonly effects: readonly AuditEffect[] }

const NONE: readonly AuditEffect[] = Object.freeze([])
const DISPOSED: AuditState = Object.freeze({ status: "disposed" })

export function createAuditState(id = "", issued = 0): Extract<AuditState, { status: "idle" }> {
  return { status: "idle", issued, id, items: [], loaded: false }
}

export function transitionAudit(state: AuditState, event: AuditEvent): AuditTransition {
  if (state.status === "disposed") return unchanged(state)
  const abort = state.status === "loading" ? [{ type: "abort", attempt: state.attempt } as const] : NONE

  if (event.type === "disposed") return { state: DISPOSED, effects: abort }

  if (event.type === "target.synced") {
    if (event.id === state.id) return unchanged(state)
    // Another Connection: drop the previous list and error, and start its first page.
    return request(createAuditState(event.id, state.issued), abort)
  }

  if (event.type === "page.requested") {
    if (state.status === "loading" || !state.id) return unchanged(state)
    if (state.loaded && state.next === undefined) return unchanged(state)
    return request(state, NONE)
  }

  if (state.status !== "loading" || state.attempt !== event.attempt) return unchanged(state)

  if (event.type === "page.failed") {
    return {
      state: {
        status: "failed",
        issued: state.issued,
        id: state.id,
        items: state.items,
        next: state.next,
        loaded: state.loaded,
        failure: event.failure,
      },
      effects: NONE,
    }
  }

  return {
    state: {
      status: "idle",
      issued: state.issued,
      id: state.id,
      items: [...state.items, ...event.page.items],
      next: event.page.nextCursor,
      loaded: true,
    },
    effects: NONE,
  }
}

export function selectAuditItems(state: AuditState) {
  return state.status === "disposed" ? [] : state.items
}

export function selectAuditBusy(state: AuditState) {
  return state.status === "loading"
}

/** True once the first page is in and a following page exists. */
export function selectAuditHasMore(state: AuditState) {
  return state.status !== "disposed" && state.loaded && state.next !== undefined
}

export function selectAuditFailure(state: AuditState) {
  return state.status === "failed" ? state.failure : undefined
}

function request(from: Exclude<AuditState, { status: "disposed" }>, before: readonly AuditEffect[]): AuditTransition {
  const attempt = from.issued + 1
  const run: AuditEffect = {
    type: "run",
    attempt,
    id: from.id,
    cursor: from.next,
    timeoutMs: CONNECTORS_REQUEST_TIMEOUT_MS,
  }
  return {
    state: {
      status: "loading",
      issued: attempt,
      attempt,
      id: from.id,
      items: from.items,
      next: from.next,
      loaded: from.loaded,
    },
    effects: [...before, run],
  }
}

function unchanged(state: AuditState): AuditTransition {
  return { state, effects: NONE }
}
