import type { Connectors } from "@bellucode/schema/connectors"

/** Fine-grained personal access tokens start with this. Only a hint: the service decides. */
export const GITHUB_PAT_PREFIX = "github_pat_"

/**
 * The GitHub connect panel's steps. Requests in flight (connect, list, save) belong to the `createMutation` machines;
 * this one holds where the user is and what they chose.
 *
 * `credentials` creates the Connection with the token. `repositories` then lists what the token can reach and saves
 * the selection. `touched` becomes true on the first selection event, so the "at least one repository" message does not
 * show on the initial empty list (Requirement 4.11).
 */
export type GithubState =
  | {
      readonly status: "credentials"
      /** The last submitted token did not start with the prefix, so a rejection means a classic token. */
      readonly classicSubmitted: boolean
    }
  | {
      readonly status: "repositories"
      readonly connectionId: string
      /** Counts list requests so a late answer to an earlier one is ignored. */
      readonly attempt: number
      readonly repos:
        | { readonly phase: "loading" }
        | { readonly phase: "ready"; readonly items: readonly Connectors.GithubRepo[] }
        | { readonly phase: "failed" }
      readonly selected: readonly string[]
      readonly touched: boolean
    }

export type GithubEvent =
  | { readonly type: "credentials.submitted"; readonly classic: boolean }
  | { readonly type: "connection.created"; readonly connectionId: string }
  | { readonly type: "repos.loaded"; readonly attempt: number; readonly items: readonly Connectors.GithubRepo[] }
  | { readonly type: "repos.failed"; readonly attempt: number }
  | { readonly type: "repos.retried" }
  | { readonly type: "repo.toggled"; readonly fullName: string }

export const INITIAL_GITHUB_STATE: GithubState = Object.freeze({ status: "credentials", classicSubmitted: false })

export function transitionGithub(state: GithubState, event: GithubEvent): GithubState {
  if (event.type === "credentials.submitted") {
    if (state.status !== "credentials" || state.classicSubmitted === event.classic) return state
    return { status: "credentials", classicSubmitted: event.classic }
  }
  if (event.type === "connection.created") {
    if (state.status !== "credentials") return state
    return {
      status: "repositories",
      connectionId: event.connectionId,
      attempt: 1,
      repos: { phase: "loading" },
      selected: [],
      touched: false,
    }
  }
  if (state.status !== "repositories") return state
  if (event.type === "repos.loaded") {
    if (event.attempt !== state.attempt || state.repos.phase !== "loading") return state
    return { ...state, repos: { phase: "ready", items: event.items } }
  }
  if (event.type === "repos.failed") {
    if (event.attempt !== state.attempt || state.repos.phase !== "loading") return state
    return { ...state, repos: { phase: "failed" } }
  }
  if (event.type === "repos.retried") {
    if (state.repos.phase !== "failed") return state
    return { ...state, attempt: state.attempt + 1, repos: { phase: "loading" } }
  }
  if (state.repos.phase !== "ready") return state
  return {
    ...state,
    touched: true,
    selected: state.selected.includes(event.fullName)
      ? state.selected.filter((name) => name !== event.fullName)
      : [...state.selected, event.fullName],
  }
}

/** Whether to show the prefix hint: only for a non-empty token that does not start with the prefix. */
export function selectPrefixHint(token: string) {
  return token.length > 0 && !token.startsWith(GITHUB_PAT_PREFIX)
}

/** The required message shows only after a selection event emptied the selection. */
export function selectRepositoriesRequired(state: GithubState) {
  return state.status === "repositories" && state.touched && state.selected.length === 0
}

/** Saving needs a loaded list and at least one selected repository. */
export function selectSaveDisabled(state: GithubState) {
  return state.status !== "repositories" || state.repos.phase !== "ready" || state.selected.length === 0
}

export function selectClassicRejected(state: GithubState) {
  return state.status === "credentials" && state.classicSubmitted
}
