import type { Connectors } from "@bellucode/schema/connectors"
import { createEffect, createMemo, createResource, createSignal, onCleanup, untrack } from "solid-js"
import { createStore, reconcile } from "solid-js/store"
import { ServerConnection } from "@/runtime/server/registry"
import { useServerSDK } from "@/runtime/server/client"
import {
  createAuditState,
  selectAuditBusy,
  selectAuditFailure,
  selectAuditHasMore,
  selectAuditItems,
  transitionAudit,
  type AuditEffect,
  type AuditEvent,
  type AuditState,
} from "./audit-machine"
import { classifyConnectorFailure } from "./errors"
import {
  INITIAL_MUTATION_STATE,
  selectMutationBusy,
  selectMutationFailure,
  transitionMutation,
  type MutationEffect,
  type MutationEvent,
} from "./mutation-machine"
import { withPlannedCards } from "./planned"
import { INITIAL_OFFLINE_STATE, buildCards, transitionOffline, type OfflineEffect, type OfflineEvent } from "./machine"

/** The generated client's connectors group, as `client.experimental.connectors`. */
type ConnectorsApi = ReturnType<typeof useServerSDK>["api"]["experimental"]["connectors"]

type Cache = {
  /** The server the cached data belongs to; data for another server is never shown. */
  key: string
  catalog?: readonly Connectors.Manifest[]
  connections?: readonly Connectors.Connection[]
  status?: Connectors.ServiceStatus
}

/** Sent on credential-bearing requests. bellud refuses them without it, so a cross-site form post cannot reach them. */
export const CLIENT_HEADERS = { "X-Bellucode-Client": "web" } as const

export type ConnectorsData = ReturnType<typeof createConnectorsData>
export type ConnectorMutation = ReturnType<ConnectorsData["createMutation"]>

/**
 * Settings › Connectors server data: catalog, Connections, service status polling, writes and audit paging.
 *
 * Reads fill a store, and components read the store, never the resources, so no read suspends. The resources only
 * report loading, refreshing and errored. Credentials never pass through this module's state: a write receives them in
 * its `call` closure from the component's local state and hands control back through `settled`, which runs in a
 * `finally` so the component can clear its fields as soon as the response arrives.
 *
 * Must run inside a component or root, because it owns timers and aborts them on cleanup.
 */
export function createConnectorsData() {
  const sdk = useServerSDK()
  const serverKey = createMemo(() => ServerConnection.key(sdk.server))
  const api = (): ConnectorsApi => sdk.api.experimental.connectors
  const [cache, setCache] = createStore<Cache>({ key: untrack(serverKey) })

  const own = () => cache.key === serverKey()

  /** Data for another server never mixes in: the first write for a new key empties the cache. */
  const claim = (key: string) => {
    if (untrack(() => cache.key) !== key)
      setCache({ key, catalog: undefined, connections: undefined, status: undefined })
  }

  const [catalogResource, catalogControls] = createResource(serverKey, async (key) => {
    const result = await api().catalog()
    claim(key)
    setCache("catalog", reconcile(result.items, { key: "id" }))
    return key
  })
  const [connectionsResource, connectionsControls] = createResource(serverKey, async (key) => {
    const result = await api().listConnections()
    claim(key)
    setCache("connections", reconcile(result.items, { key: "id" }))
    return key
  })

  const refreshConnections = () => {
    const state = untrack(() => connectionsResource.state)
    if (state === "pending" || state === "refreshing") return
    void connectionsControls.refetch()
  }

  // -- Offline probe driver -------------------------------------------------------------------------------------

  const [offlineState, setOfflineState] = createSignal(INITIAL_OFFLINE_STATE)
  const probes = new Map<number, { controller: AbortController; timer: ReturnType<typeof setTimeout> }>()
  let tickTimer: ReturnType<typeof setTimeout> | undefined

  const dispatchOffline = (event: OfflineEvent) => {
    const previous = untrack(offlineState)
    const result = transitionOffline(previous, event)
    if (result.state !== previous) setOfflineState(() => result.state)
    result.effects.forEach(runOffline)
  }

  const stopProbe = (attempt: number) => {
    const current = probes.get(attempt)
    probes.delete(attempt)
    clearTimeout(current?.timer)
    current?.controller.abort()
  }

  const runOffline = (effect: OfflineEffect) => {
    if (effect.type === "tick.cancel") {
      clearTimeout(tickTimer)
      return
    }
    if (effect.type === "tick.schedule") {
      clearTimeout(tickTimer)
      tickTimer = setTimeout(() => dispatchOffline({ type: "tick" }), effect.delayMs)
      return
    }
    if (effect.type === "probe.cancel") {
      probes.forEach((_, attempt) => stopProbe(attempt))
      return
    }

    const attempt = effect.attempt
    const controller = new AbortController()
    probes.set(attempt, {
      controller,
      timer: setTimeout(() => dispatchOffline({ type: "probe.timed-out", attempt }), effect.timeoutMs),
    })
    void Promise.try(() => api().status({ signal: controller.signal })).then(
      (status) => {
        stopProbe(attempt)
        // A service that answers but reports itself offline is offline.
        if (status.offline) return dispatchOffline({ type: "probe.failed", attempt })
        claim(untrack(serverKey))
        setCache("status", reconcile(status))
        dispatchOffline({ type: "probe.succeeded", attempt })
        // The service answers again: bring the lists up to date, and retry a list that failed while it was down.
        refreshConnections()
        if (untrack(() => catalogResource.state) === "errored") void catalogControls.refetch()
      },
      () => {
        stopProbe(attempt)
        dispatchOffline({ type: "probe.failed", attempt })
      },
    )
  }

  dispatchOffline({ type: "tick" })
  onCleanup(() => dispatchOffline({ type: "disposed" }))

  // -- Writes ---------------------------------------------------------------------------------------------------

  /**
   * One write at a time per call site. `run` returns the response, or `undefined` when the write failed (the failure
   * is in `failure()`), was dropped because one is running, or timed out after 30 s. `settled` runs in a `finally`,
   * after the state has moved on, and is where a dialog empties its credential fields.
   */
  function createMutation() {
    const [state, setState] = createSignal(INITIAL_MUTATION_STATE)
    const controllers = new Map<number, AbortController>()

    const dispatch = (event: MutationEvent): readonly MutationEffect[] => {
      const previous = untrack(state)
      const result = transitionMutation(previous, event)
      if (result.state !== previous) setState(() => result.state)
      result.effects.forEach((effect) => {
        if (effect.type === "abort") controllers.get(effect.attempt)?.abort()
      })
      return result.effects
    }

    onCleanup(() => dispatch({ type: "disposed" }))

    return {
      busy: () => selectMutationBusy(state()),
      failure: () => selectMutationFailure(state()),
      dismiss: () => void dispatch({ type: "dismissed" }),
      async run<T>(call: (connectors: ConnectorsApi, signal: AbortSignal) => Promise<T>, settled?: () => void) {
        const effect = dispatch({ type: "started" }).find((candidate) => candidate.type === "run")
        if (!effect) return
        const attempt = effect.attempt
        const controller = new AbortController()
        let timedOut = false
        controllers.set(attempt, controller)
        const timer = setTimeout(() => {
          timedOut = true
          controller.abort()
        }, effect.timeoutMs)
        try {
          const value = await call(api(), controller.signal)
          dispatch({ type: "succeeded", attempt })
          // The server may have saved the change even if this owner is gone, so the lists refresh either way.
          refreshConnections()
          return value
        } catch (error) {
          dispatch({ type: "failed", attempt, failure: classifyConnectorFailure(error, timedOut) })
          // A failed write can still have changed the Connection's status (VERIFYING to ERROR).
          refreshConnections()
          return
        } finally {
          clearTimeout(timer)
          controllers.delete(attempt)
          settled?.()
        }
      },
    }
  }

  // -- Audit paging ---------------------------------------------------------------------------------------------

  /** Pages the audit log of the Connection `id()` names; an `undefined` id shows nothing. */
  function createAudit(id: () => string | undefined) {
    const [state, setState] = createSignal<AuditState>(createAuditState())
    const runs = new Map<number, { controller: AbortController; timer: ReturnType<typeof setTimeout> }>()

    const stop = (attempt: number) => {
      const current = runs.get(attempt)
      runs.delete(attempt)
      clearTimeout(current?.timer)
      current?.controller.abort()
    }

    const dispatch = (event: AuditEvent) => {
      const previous = untrack(state)
      const result = transitionAudit(previous, event)
      if (result.state !== previous) setState(() => result.state)
      result.effects.forEach(run)
    }

    const run = (effect: AuditEffect) => {
      if (effect.type === "abort") return stop(effect.attempt)
      const attempt = effect.attempt
      const controller = new AbortController()
      let timedOut = false
      runs.set(attempt, {
        controller,
        timer: setTimeout(() => {
          timedOut = true
          controller.abort()
        }, effect.timeoutMs),
      })
      void Promise.try(() =>
        api().listAudit({ id: effect.id, cursor: effect.cursor }, { signal: controller.signal }),
      ).then(
        (page) => {
          stop(attempt)
          dispatch({ type: "page.loaded", attempt, page })
        },
        (error) => {
          stop(attempt)
          dispatch({ type: "page.failed", attempt, failure: classifyConnectorFailure(error, timedOut) })
        },
      )
    }

    // A new target drops the previous list and error and starts its first page.
    createEffect(() => {
      const target = id() ?? ""
      untrack(() => dispatch({ type: "target.synced", id: target }))
    })
    onCleanup(() => dispatch({ type: "disposed" }))

    return {
      items: () => selectAuditItems(state()),
      busy: () => selectAuditBusy(state()),
      hasMore: () => selectAuditHasMore(state()),
      failure: () => selectAuditFailure(state()),
      /** The next page. Also the Retry after a failed page. */
      loadMore: () => dispatch({ type: "page.requested" }),
    }
  }

  // -- Reads for the page ---------------------------------------------------------------------------------------

  const cards = createMemo(() => (own() && cache.catalog ? withPlannedCards(buildCards(cache.catalog, cache.connections ?? [])) : []))

  return {
    /** One card per catalog connector. Empty until the catalog first loads. */
    cards,
    connections: () => (own() ? (cache.connections ?? []) : []),
    /** Key source, persistence and warnings from the latest answered probe. */
    status: () => (own() ? cache.status : undefined),
    /** True while the service does not answer; Connect actions are disabled. */
    offline: () => {
      const current = offlineState()
      return current.status !== "disposed" && current.offline
    },
    /** `loading` until the catalog has loaded once; `failed` when it could not load and nothing is cached. */
    phase: (): "loading" | "failed" | "ready" => {
      if (own() && cache.catalog) return "ready"
      return catalogResource.state === "errored" ? "failed" : "loading"
    },
    retry: () => {
      void catalogControls.refetch()
      refreshConnections()
    },
    refresh: refreshConnections,
    createMutation,
    createAudit,
  }
}
