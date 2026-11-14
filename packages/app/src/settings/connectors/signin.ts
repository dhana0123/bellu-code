import { createSignal, onCleanup, untrack } from "solid-js"
import { createStore } from "solid-js/store"
import { useServerSDK } from "@/runtime/server/client"
import { CLIENT_HEADERS, type ConnectorsData } from "./data"
import { classifyConnectorFailure, type ConnectorFailure } from "./errors"
import {
  INITIAL_SIGNIN_STATE,
  transition,
  type SignInEffect,
  type SignInErrorCode,
  type SignInEvent,
  type SignInState,
} from "./signin-machine"

/** Request deadlines and cadence of the sign-in driver (Requirements 3.11, 3.12, 15.8, 15.9). */
const START_TIMEOUT_MS = 15_000
const POLL_INTERVAL_MS = 2_000
const POLL_TIMEOUT_MS = 5_000
const REPOS_TIMEOUT_MS = 10_000

type Attempt = { readonly controller: AbortController; readonly timers: Set<ReturnType<typeof setTimeout>> }
type Guarded<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly failure: ConnectorFailure }

export type SignInOptions = {
  /** The shell's data layer; a reconnect refreshes its Connection list. */
  data: ConnectorsData
  /** The Account_Alias the dialog collected. Not needed for a reconnect. */
  alias: () => string | undefined
  /** The Source to sign in to. Defaults to "github". Other Sources load their scope themselves, not GitHub repositories. */
  connectorId?: string
}

/**
 * Thin driver for `signin-machine.ts`: turns its effects into requests and timers and dispatches the results back with
 * the attempt id. Every request and timer belongs to one attempt, and the machine's `abort` effect cancels them all.
 *
 * Must run inside a component or root: it ends the dialog's work (`disposed`) on cleanup.
 */
export function createSignIn(options: SignInOptions) {
  const sdk = useServerSDK()
  const api = () => sdk.api.experimental.connectors
  const save = options.data.createMutation()

  // The machine state is replaced whole, so it lives in a signal: a store would merge one variant into another.
  const [state, setState] = createSignal<SignInState>(INITIAL_SIGNIN_STATE)
  // What the repositories request returned besides the items, for the "install the app" hint.
  const [extra, setExtra] = createStore<{ installations: number; installUrl: string | undefined }>({
    installations: 0,
    installUrl: undefined,
  })
  const attempts = new Map<number, Attempt>()

  const begin = (attempt: number) => {
    const current = attempts.get(attempt)
    if (current && !current.controller.signal.aborted) return current
    const created: Attempt = { controller: new AbortController(), timers: new Set() }
    attempts.set(attempt, created)
    return created
  }

  const stop = (attempt: number) => {
    const current = attempts.get(attempt)
    attempts.delete(attempt)
    if (!current) return
    current.timers.forEach(clearTimeout)
    current.timers.clear()
    current.controller.abort()
  }

  const after = (owner: Attempt, ms: number, run: () => void) => {
    const timer = setTimeout(() => {
      owner.timers.delete(timer)
      run()
    }, ms)
    owner.timers.add(timer)
  }

  /** One request bounded by `ms` and by the attempt. Resolves `undefined` when the attempt ended meanwhile. */
  const guarded = async <T>(
    owner: Attempt,
    ms: number,
    call: (signal: AbortSignal) => Promise<T>,
  ): Promise<Guarded<T> | undefined> => {
    const request = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      request.abort()
    }, ms)
    owner.timers.add(timer)
    try {
      const value = await call(AbortSignal.any([owner.controller.signal, request.signal]))
      if (owner.controller.signal.aborted) return
      return { ok: true, value }
    } catch (error) {
      if (owner.controller.signal.aborted) return
      return { ok: false, failure: classifyConnectorFailure(error, timedOut) }
    } finally {
      clearTimeout(timer)
      owner.timers.delete(timer)
    }
  }

  const dispatch = (event: SignInEvent) => {
    const previous = untrack(state)
    const result = transition(previous, event)
    if (result.state !== previous) setState(() => result.state)
    // A finished reconnect has no repositories step: the list only needs to show the refreshed Connection.
    if (event.type === "authorization.connected" && previous.phase === "awaiting" && result.state.phase === "idle") {
      options.data.refresh()
    }
    result.effects.forEach(run)
  }

  const run = (effect: SignInEffect) => {
    if (effect.type === "abort") return stop(effect.attempt)
    if (effect.type === "authorization.cancel") return cancelRemote(effect.authorizationId)
    if (effect.type === "authorization.start") return void start(effect, begin(effect.attempt))
    if (effect.type === "status.poll") return poll(effect.attempt, effect.authorizationId, begin(effect.attempt))
    if (effect.type === "expiry.schedule") {
      const attempt = effect.attempt
      return after(begin(attempt), Math.max(0, effect.at - Date.now()), () => dispatch({ type: "expired", attempt }))
    }
    return void loadRepos(effect, begin(effect.attempt))
  }

  const start = async (effect: Extract<SignInEffect, { type: "authorization.start" }>, owner: Attempt) => {
    const attempt = effect.attempt
    const result = await guarded(owner, START_TIMEOUT_MS, (signal) =>
      Promise.try(() =>
        api().startDeviceAuthorization(
          { connectorId: options.connectorId ?? "github", alias: options.alias(), reconnectId: effect.reconnectId },
          { signal, headers: CLIENT_HEADERS },
        ),
      ),
    )
    if (!result) return
    if (!result.ok) return dispatch(failureEvent(attempt, result.failure))
    dispatch({
      type: "authorization.started",
      attempt,
      authorizationId: result.value.id,
      userCode: result.value.userCode,
      verificationUri: result.value.verificationUri,
      // Epoch milliseconds, as the server sends it.
      expiresAt: result.value.expiresAt,
    })
  }

  /** A failed or timed out status request leaves the authorization pending; the expiry timer ends it (3.12). */
  const poll = (attempt: number, id: string, owner: Attempt) => {
    after(owner, POLL_INTERVAL_MS, async () => {
      const result = await guarded(owner, POLL_TIMEOUT_MS, (signal) =>
        Promise.try(() => api().getDeviceAuthorization({ id }, { signal, headers: CLIENT_HEADERS })),
      )
      if (!result) return
      const status = result.ok ? result.value : undefined
      if (!status || status.status === "pending") return poll(attempt, id, owner)
      if (status.status === "connected") {
        if (status.connection) return dispatch({ type: "authorization.connected", attempt, connectionId: status.connection.id })
        return dispatch({ type: "authorization.failed", attempt, error: "network" })
      }
      const fallback: SignInErrorCode =
        status.status === "expired" ? "device_code_expired" : status.status === "denied" ? "authorization_denied" : "network"
      dispatch({
        type: "authorization.failed",
        attempt,
        error: status.error?.code ?? fallback,
        ...(status.error?.retryAfterSec === undefined ? {} : { retryAfterSec: status.error.retryAfterSec }),
      })
    })
  }

  const loadRepos = async (effect: Extract<SignInEffect, { type: "repos.load" }>, owner: Attempt) => {
    const { attempt, loadAttempt } = effect
    // Only GitHub has repositories here; another Source's panel loads its own scope from the connection id.
    if (options.connectorId !== undefined && options.connectorId !== "github")
      return dispatch({ type: "repos.loaded", attempt, loadAttempt, items: [] })
    const result = await guarded(owner, REPOS_TIMEOUT_MS, (signal) =>
      Promise.try(() => api().listGithubRepos({ id: effect.connectionId }, { signal })),
    )
    if (!result) return
    if (!result.ok) return dispatch({ type: "repos.failed", attempt, loadAttempt })
    setExtra({ installations: result.value.installations, installUrl: result.value.installUrl })
    dispatch({ type: "repos.loaded", attempt, loadAttempt, items: result.value.items })
  }

  /** Best effort: the answer is not awaited by anything, and a failure leaves the server to expire the attempt. */
  const cancelRemote = (id: string) => {
    void Promise.try(() => api().cancelDeviceAuthorization({ id }, { headers: CLIENT_HEADERS })).catch(() => undefined)
  }

  onCleanup(() => {
    dispatch({ type: "disposed" })
    // `disposed` aborts the current attempt; this also covers an attempt the machine no longer names.
    Array.from(attempts.keys()).forEach(stop)
  })

  const repositories = () => {
    const current = state()
    return current.phase === "repositories" ? current : undefined
  }

  return {
    state,
    /** GitHub App installations the token reaches, from the latest repositories request. */
    installations: () => extra.installations,
    installUrl: () => extra.installUrl,
    /** The failure of the last save, kept until the next save starts. The state stays on the repositories step. */
    saveFailure: save.failure,
    saving: save.busy,
    signIn: (reconnectId?: string) => {
      setExtra({ installations: 0, installUrl: undefined })
      dispatch({ type: "signin.activated", ...(reconnectId === undefined ? {} : { reconnectId }) })
    },
    cancel: () => dispatch({ type: "cancelled" }),
    retryRepos: () => {
      const current = repositories()
      if (current) dispatch({ type: "repos.retried", attempt: current.attempt })
    },
    toggleRepo: (fullName: string) => {
      const current = repositories()
      if (current) dispatch({ type: "repo.toggled", attempt: current.attempt, fullName })
    },
    /** Saves `selection` (default: the current one). On failure the state stays and `saveFailure()` has the error. */
    save: async (selection?: readonly string[]) => {
      const current = repositories()
      if (!current) return
      const repos = [...(selection ?? current.github.selected)]
      const connection = await save.run((connectors, signal) =>
        connectors.updateConnection({ id: current.github.connectionId, selection: { regions: [], repos } }, { signal }),
      )
      if (connection) dispatch({ type: "saved", attempt: current.attempt })
      return connection
    },
  }
}

export type SignIn = ReturnType<typeof createSignIn>

/** Connector codes keep their code and retry time; any other failure of the request itself is a request failure. */
function failureEvent(attempt: number, failure: ConnectorFailure): SignInEvent {
  if (failure.kind === "connector") {
    return {
      type: "authorization.failed",
      attempt,
      error: failure.code,
      ...(failure.retryAfterSec === undefined ? {} : { retryAfterSec: failure.retryAfterSec }),
    }
  }
  return { type: "request.failed", attempt, error: failure.kind === "timeout" ? "request_timeout" : "network" }
}
