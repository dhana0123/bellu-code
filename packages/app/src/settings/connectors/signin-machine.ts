import type { Connectors } from "@bellucode/schema/connectors"
import { INITIAL_GITHUB_STATE, transitionGithub, type GithubState } from "./github-machine"

/**
 * The "Sign in with GitHub" dialog as one machine (Requirement 15). A driver turns effects into requests and timers
 * and dispatches results back with the attempt id; this module does no I/O and reads no clock.
 *
 * `issued` counts attempts started in this dialog, so `issued + 1` is always a new unique attempt id (15.7). The
 * repository phases are composed from `github-machine.ts` (15.14): `repositories` holds a `GithubState` and delegates
 * every repository event to `transitionGithub`.
 */

export type SignInErrorCode = Connectors.ErrorCode | "request_timeout"

type Repositories = Extract<GithubState, { status: "repositories" }>

export type SignInState =
  | { readonly phase: "idle"; readonly issued: number }
  | { readonly phase: "starting"; readonly issued: number; readonly attempt: number; readonly reconnectId?: string }
  | {
      readonly phase: "awaiting"
      readonly issued: number
      readonly attempt: number
      readonly reconnectId?: string
      readonly authorizationId: string
      readonly userCode: string
      readonly verificationUri: string
      /** Epoch milliseconds, the same unit the caller passes as `now`. */
      readonly expiresAt: number
    }
  | {
      readonly phase: "installing"
      readonly issued: number
      readonly attempt: number
      readonly authorizationId: string
      readonly connectionId: string
    }
  | {
      readonly phase: "repositories"
      readonly issued: number
      readonly attempt: number
      readonly authorizationId: string
      readonly github: Repositories
    }
  | {
      readonly phase: "failed"
      readonly issued: number
      readonly attempt: number
      readonly error: SignInErrorCode
      readonly retryAfterSec?: number
    }

export type SignInEvent =
  | { readonly type: "signin.activated"; readonly reconnectId?: string }
  | {
      readonly type: "authorization.started"
      readonly attempt: number
      readonly authorizationId: string
      readonly userCode: string
      readonly verificationUri: string
      readonly expiresAt: number
    }
  | { readonly type: "authorization.connected"; readonly attempt: number; readonly connectionId: string }
  | {
      readonly type: "authorization.failed"
      readonly attempt: number
      readonly error: SignInErrorCode
      readonly retryAfterSec?: number
    }
  | { readonly type: "request.failed"; readonly attempt: number; readonly error: SignInErrorCode }
  | { readonly type: "expired"; readonly attempt: number }
  /** `loadAttempt` is the repository list request's own counter (`GithubState.attempt`). */
  | {
      readonly type: "repos.loaded"
      readonly attempt: number
      readonly loadAttempt: number
      readonly items: readonly Connectors.GithubRepo[]
    }
  | { readonly type: "repos.failed"; readonly attempt: number; readonly loadAttempt: number }
  | { readonly type: "repos.retried"; readonly attempt: number }
  | { readonly type: "repo.toggled"; readonly attempt: number; readonly fullName: string }
  | { readonly type: "saved"; readonly attempt: number }
  | { readonly type: "cancelled" }
  | { readonly type: "disposed" }

export type SignInEffect =
  | { readonly type: "authorization.start"; readonly attempt: number; readonly reconnectId?: string }
  | { readonly type: "status.poll"; readonly attempt: number; readonly authorizationId: string }
  | { readonly type: "expiry.schedule"; readonly attempt: number; readonly at: number }
  | {
      readonly type: "repos.load"
      readonly attempt: number
      readonly connectionId: string
      readonly loadAttempt: number
    }
  /** Stops polling, or deletes the unsaved Connection on the server. */
  | { readonly type: "authorization.cancel"; readonly authorizationId: string }
  /** Aborts the requests and timers of one attempt. */
  | { readonly type: "abort"; readonly attempt: number }

export type SignInResult = { readonly state: SignInState; readonly effects: readonly SignInEffect[] }

const NONE: readonly SignInEffect[] = Object.freeze([])

export const INITIAL_SIGNIN_STATE: SignInState = Object.freeze({ phase: "idle", issued: 0 })

/** Same state object, no effects. */
function ignore(state: SignInState): SignInResult {
  return { state, effects: NONE }
}

function failed(
  state: Exclude<SignInState, { phase: "idle" }>,
  error: SignInErrorCode,
  retryAfterSec?: number,
): SignInResult {
  const next: SignInState = {
    phase: "failed",
    issued: state.issued,
    attempt: state.attempt,
    error,
    ...(retryAfterSec === undefined ? {} : { retryAfterSec }),
  }
  return { state: next, effects: [{ type: "abort", attempt: state.attempt }] }
}

/**
 * `cancelled` and `disposed`: back to idle, stopping whatever the attempt started. Cancel withdraws the authorization
 * (the server deletes a Connection whose repositories were never saved). Dispose only stops a pending authorization:
 * once GitHub authorized, the Connection is kept, so a page that unmounts or reloads never throws away a sign-in.
 */
function leave(state: SignInState, cancel: boolean): SignInResult {
  if (state.phase === "idle") return ignore(state)
  const idle: SignInState = { phase: "idle", issued: state.issued }
  if (state.phase === "failed") return { state: idle, effects: NONE }
  const effects: SignInEffect[] = [{ type: "abort", attempt: state.attempt }]
  if (state.phase === "awaiting" || (cancel && state.phase !== "starting"))
    effects.push({ type: "authorization.cancel", authorizationId: state.authorizationId })
  return { state: idle, effects }
}

export function transition(state: SignInState, event: SignInEvent): SignInResult {
  if (event.type === "signin.activated") {
    if (state.phase !== "idle" && state.phase !== "failed") return ignore(state)
    const attempt = state.issued + 1
    const next: SignInState = {
      phase: "starting",
      issued: attempt,
      attempt,
      ...(event.reconnectId === undefined ? {} : { reconnectId: event.reconnectId }),
    }
    return {
      state: next,
      effects: [
        { type: "authorization.start", attempt, ...(event.reconnectId === undefined ? {} : { reconnectId: event.reconnectId }) },
      ],
    }
  }
  if (event.type === "cancelled" || event.type === "disposed") return leave(state, event.type === "cancelled")
  if (state.phase === "idle") return ignore(state)
  if (event.attempt !== state.attempt) return ignore(state)

  switch (event.type) {
    case "authorization.started": {
      if (state.phase !== "starting") return ignore(state)
      const next: SignInState = {
        phase: "awaiting",
        issued: state.issued,
        attempt: state.attempt,
        ...(state.reconnectId === undefined ? {} : { reconnectId: state.reconnectId }),
        authorizationId: event.authorizationId,
        userCode: event.userCode,
        verificationUri: event.verificationUri,
        expiresAt: event.expiresAt,
      }
      return {
        state: next,
        effects: [
          { type: "status.poll", attempt: state.attempt, authorizationId: event.authorizationId },
          { type: "expiry.schedule", attempt: state.attempt, at: event.expiresAt },
        ],
      }
    }
    case "authorization.connected": {
      if (state.phase !== "awaiting") return ignore(state)
      // A reconnect has nothing to select: the driver closes the dialog and refreshes the list.
      if (state.reconnectId !== undefined) {
        return { state: { phase: "idle", issued: state.issued }, effects: [{ type: "abort", attempt: state.attempt }] }
      }
      const next: SignInState = {
        phase: "installing",
        issued: state.issued,
        attempt: state.attempt,
        authorizationId: state.authorizationId,
        connectionId: event.connectionId,
      }
      return {
        state: next,
        effects: [
          { type: "abort", attempt: state.attempt },
          { type: "repos.load", attempt: state.attempt, connectionId: event.connectionId, loadAttempt: 1 },
        ],
      }
    }
    case "authorization.failed":
      if (state.phase !== "starting" && state.phase !== "awaiting") return ignore(state)
      return failed(state, event.error, event.retryAfterSec)
    case "request.failed":
      if (state.phase !== "starting" && state.phase !== "awaiting" && state.phase !== "installing") return ignore(state)
      return failed(state, event.error)
    case "expired":
      if (state.phase !== "awaiting") return ignore(state)
      return failed(state, "device_code_expired")
    case "repos.loaded":
    case "repos.failed": {
      if (state.phase === "installing") {
        const created = transitionGithub(INITIAL_GITHUB_STATE, { type: "connection.created", connectionId: state.connectionId })
        const github = transitionGithub(created, githubEvent(event))
        if (github.status !== "repositories" || github === created) return ignore(state)
        return {
          state: {
            phase: "repositories",
            issued: state.issued,
            attempt: state.attempt,
            authorizationId: state.authorizationId,
            github,
          },
          effects: NONE,
        }
      }
      return repositories(state, event)
    }
    case "repos.retried": {
      if (state.phase !== "repositories") return ignore(state)
      // `github-machine.ts` retries only from `failed`. "Check again" runs from `ready`, so reopen it as failed first.
      const base: Repositories = state.github.repos.phase === "ready" ? { ...state.github, repos: { phase: "failed" } } : state.github
      const github = transitionGithub(base, { type: "repos.retried" })
      if (github === base || github.status !== "repositories") return ignore(state)
      return {
        state: { ...state, github },
        effects: [
          { type: "repos.load", attempt: state.attempt, connectionId: github.connectionId, loadAttempt: github.attempt },
        ],
      }
    }
    case "repo.toggled":
      return repositories(state, event)
    case "saved":
      if (state.phase !== "repositories") return ignore(state)
      return { state: { phase: "idle", issued: state.issued }, effects: NONE }
  }
}

function githubEvent(event: Extract<SignInEvent, { type: "repos.loaded" | "repos.failed" }>) {
  return event.type === "repos.loaded"
    ? ({ type: "repos.loaded", attempt: event.loadAttempt, items: event.items } as const)
    : ({ type: "repos.failed", attempt: event.loadAttempt } as const)
}

/** Delegates a repository event to the composed machine; the sign-in state changes only if it did. */
function repositories(
  state: SignInState,
  event: Extract<SignInEvent, { type: "repos.loaded" | "repos.failed" | "repo.toggled" }>,
): SignInResult {
  if (state.phase !== "repositories") return ignore(state)
  const github = transitionGithub(
    state.github,
    event.type === "repo.toggled" ? { type: "repo.toggled", fullName: event.fullName } : githubEvent(event),
  )
  if (github === state.github || github.status !== "repositories") return ignore(state)
  return { state: { ...state, github }, effects: NONE }
}

// ---------------------------------------------------------------------------
// Selectors (Requirements 15.10, 15.11). Each is a pure function of state.
// ---------------------------------------------------------------------------

export type SignInPanel = "signin" | "starting" | "prompt" | "installing" | "repositories" | "failed"

const PANELS: Record<SignInState["phase"], SignInPanel> = {
  idle: "signin",
  starting: "starting",
  awaiting: "prompt",
  installing: "installing",
  repositories: "repositories",
  failed: "failed",
}

export function selectPanel(state: SignInState): SignInPanel {
  return PANELS[state.phase]
}

export function selectBusy(state: SignInState) {
  return state.phase === "starting" || state.phase === "installing"
}

/** Disables the "Sign in with GitHub" action. */
export function selectDisabled(state: SignInState) {
  return state.phase === "starting" || state.phase === "awaiting" || state.phase === "installing"
}

export function selectError(state: SignInState): { readonly code: SignInErrorCode; readonly retryAfterSec?: number } | undefined {
  if (state.phase !== "failed") return undefined
  return state.retryAfterSec === undefined
    ? { code: state.error }
    : { code: state.error, retryAfterSec: state.retryAfterSec }
}

export function selectPrompt(state: SignInState) {
  if (state.phase !== "awaiting") return undefined
  return { userCode: state.userCode, verificationUri: state.verificationUri, expiresAt: state.expiresAt }
}

/** Try again is offered for every failure except a disabled device flow. */
export function selectRetryable(state: SignInState) {
  return state.phase === "failed" && state.error !== "device_flow_disabled"
}

export type SignInAnnouncement = "starting" | "prompt" | "installing" | "repositories" | "failed"

/** One value per phase, so the live region never announces the per-second countdown. */
export function selectAnnouncement(state: SignInState): SignInAnnouncement | undefined {
  return state.phase === "idle" ? undefined : PANELS[state.phase] === "signin" ? undefined : (PANELS[state.phase] as SignInAnnouncement)
}

/** Whole seconds left, never negative. `now` is epoch ms from the caller's clock. */
export function selectRemaining(state: SignInState, now: number) {
  if (state.phase !== "awaiting") return 0
  return Math.max(0, Math.ceil((state.expiresAt - now) / 1000))
}
