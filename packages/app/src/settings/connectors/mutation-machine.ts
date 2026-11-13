import type { ConnectorFailure } from "./errors"

export const CONNECTORS_REQUEST_TIMEOUT_MS = 30_000

/**
 * One write against the connectors service (connect, test, sync, rotate, disconnect). A second request while one runs
 * is dropped, so a double click cannot send a credential twice. `issued` counts attempts and lives in every live variant.
 */
export type MutationState =
  | { readonly status: "idle"; readonly issued: number }
  | { readonly status: "running"; readonly issued: number; readonly attempt: number }
  | { readonly status: "failed"; readonly issued: number; readonly failure: ConnectorFailure }
  | { readonly status: "disposed" }

export type MutationEvent =
  | { readonly type: "started" }
  | { readonly type: "succeeded"; readonly attempt: number }
  | { readonly type: "failed"; readonly attempt: number; readonly failure: ConnectorFailure }
  | { readonly type: "dismissed" }
  | { readonly type: "disposed" }

export type MutationEffect =
  | { readonly type: "run"; readonly attempt: number; readonly timeoutMs: number }
  | { readonly type: "abort"; readonly attempt: number }

export type MutationTransition = { readonly state: MutationState; readonly effects: readonly MutationEffect[] }

export const INITIAL_MUTATION_STATE: MutationState = Object.freeze({ status: "idle", issued: 0 })

const DISPOSED: MutationState = Object.freeze({ status: "disposed" })
const NONE: readonly MutationEffect[] = Object.freeze([])

export function transitionMutation(state: MutationState, event: MutationEvent): MutationTransition {
  if (state.status === "disposed") return { state, effects: NONE }

  if (event.type === "disposed") {
    return {
      state: DISPOSED,
      effects: state.status === "running" ? [{ type: "abort", attempt: state.attempt }] : NONE,
    }
  }

  if (event.type === "started") {
    if (state.status === "running") return { state, effects: NONE }
    const attempt = state.issued + 1
    return {
      state: { status: "running", issued: attempt, attempt },
      effects: [{ type: "run", attempt, timeoutMs: CONNECTORS_REQUEST_TIMEOUT_MS }],
    }
  }

  if (event.type === "dismissed") {
    return state.status === "failed"
      ? { state: { status: "idle", issued: state.issued }, effects: NONE }
      : { state, effects: NONE }
  }

  if (state.status !== "running" || state.attempt !== event.attempt) return { state, effects: NONE }
  if (event.type === "succeeded") return { state: { status: "idle", issued: state.issued }, effects: NONE }
  return { state: { status: "failed", issued: state.issued, failure: event.failure }, effects: NONE }
}

export function selectMutationBusy(state: MutationState) {
  return state.status === "running"
}

export function selectMutationFailure(state: MutationState) {
  return state.status === "failed" ? state.failure : undefined
}
