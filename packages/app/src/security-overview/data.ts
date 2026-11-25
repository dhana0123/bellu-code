import { ClientError } from "@bellucode/client"
import { Option, Schema } from "effect"
import { onCleanup, onMount } from "solid-js"
import { createStore, reconcile } from "solid-js/store"
import { Persistence } from "@/runtime/persistence/schema"
import { Persist, persisted } from "@/runtime/persistence/storage"
import { useServerSDK } from "@/runtime/server/client"
import { ServerConnection } from "@/runtime/server/registry"
import {
  POLL_INTERVAL_MS,
  REQUEST_TIMEOUT_MS,
  etagOf,
  parseCached,
  type OverviewData,
  type OverviewStatus,
} from "./model"
const CacheSchema = Persistence.struct({
  key: Persistence.fallback(Schema.String, () => ""),
  data: Persistence.fallback(Schema.String, () => ""),
})
/**
 * Overview server data. One `client.experimental.overview.categories()` call fills a store keyed by category, so a
 * refresh patches counts in place and keeps focus and scroll (Requirement 1.7).
 *
 * The page polls every 10 s while it is visible and sends the last revision as `If-None-Match`; bellud answers 304
 * when nothing changed, which the generated client throws as `UnexpectedStatus` and is treated as "unchanged".
 *
 * `finding.updated` and `scan.finished` are not published on the event stream yet, so the poll is the only trigger.
 * When they exist, call `refresh` from an `sdk.event.listen` handler here.
 *
 * Must run inside a component or root, because it owns timers and listeners.
 */
export function createOverviewData() {
  const sdk = useServerSDK()
  const key = ServerConnection.key(sdk.server)
  const [cache, setCache, , cacheReady] = persisted(Persist.global("security-overview.cache"), CacheSchema, {
    key: "",
    data: "",
  })
  const [state, setState] = createStore<{
    status: OverviewStatus
    revision: number | undefined
    categories: OverviewData["categories"]
  }>({ status: "loading", revision: undefined, categories: [] })
  let current: AbortController | undefined
  async function refresh() {
    current?.abort()
    const controller = new AbortController()
    current = controller
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
    const revision = state.categories.length > 0 ? state.revision : undefined
    await sdk.api.experimental.overview
      .categories({
        signal: controller.signal,
        headers: revision === undefined ? undefined : { "If-None-Match": etagOf(revision) },
      })
      .then((data) => {
        if (current !== controller) return
        setState({ status: "ready", revision: data.revision })
        setState("categories", reconcile(data.categories, { key: "category" }))
        setCache({ key, data: JSON.stringify(data) })
      })
      .catch((error: unknown) => {
        if (current !== controller) return
        if (unchanged(error)) return setState("status", "ready")
        // Requirement 1.11: after a failure or timeout the cards show no counts.
        setState({ status: "error", revision: undefined })
        setState("categories", reconcile([]))
      })
      .finally(() => clearTimeout(timer))
  }
  onMount(() => {
    const poll = setInterval(() => document.visibilityState === "visible" && void refresh(), POLL_INTERVAL_MS)
    const visible = () => document.visibilityState === "visible" && void refresh()
    document.addEventListener("visibilitychange", visible)
    onCleanup(() => {
      clearInterval(poll)
      document.removeEventListener("visibilitychange", visible)
      current?.abort()
      current = undefined
    })
    // First view: the last response for this server shows at once, then the fresh one replaces it.
    void Promise.resolve(cacheReady.promise).then(() => {
      const cached = cache.key === key ? parseCached(cache.data) : Option.none()
      if (Option.isSome(cached) && state.status === "loading") {
        setState({ status: "ready", revision: cached.value.revision })
        setState("categories", reconcile(cached.value.categories, { key: "category" }))
      }
      return refresh()
    })
  })
  return {
    state,
    retry: () => {
      setState("status", "loading")
      return refresh()
    },
  }
}
function unchanged(error: unknown) {
  if (!(error instanceof ClientError) || error.reason !== "UnexpectedStatus") return false
  const cause: unknown = error.cause
  return typeof cause === "object" && cause !== null && "status" in cause && cause.status === 304
}
