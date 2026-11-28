import { useQuery } from "@tanstack/solid-query"
import type { Accessor } from "solid-js"
import { useServerCtx } from "@/runtime/server/runtime"
import type { ServerConnection } from "@/runtime/server/registry"

type ConfigEntries = ReadonlyArray<{
  type: string
  info?: { experimental?: { connectors?: boolean; all_flags?: boolean } }
}>

/**
 * The TS side of the `connectors` flag from config entries. Matches the server: the highest-priority document that
 * sets `experimental` decides `experimental.connectors`, then `all_flags: true`. A flag that no config sets is
 * `undefined` (the build default and `BELLUCODE_FLAGS` are not visible here), which leaves the decision to the status
 * probe, whose answer reflects the server's fully resolved flag.
 */
export function connectorsConfigFlag(entries: ConfigEntries | undefined): boolean | undefined {
  if (!entries) return undefined
  const documents = entries.flatMap((entry) =>
    entry.type === "document" && entry.info?.experimental ? [entry.info.experimental] : [],
  )
  const configured = documents.at(-1)?.connectors
  if (configured !== undefined) return configured
  return documents.some((item) => item.all_flags === true) ? true : undefined
}

/** Shows the Connectors page only when no config turns the flag off and the service's status probe succeeds. */
export function connectorsAvailable(input: { flag: boolean | undefined; probe: { enabled: boolean } | undefined }) {
  return input.flag !== false && input.probe?.enabled === true
}

/**
 * Whether Settings shows Connectors for `server`: the resolved flag AND a successful `status` probe. A disabled
 * service answers 404, which rejects and so hides the nav entry, the search results and the page.
 */
export function useConnectorsAvailable(server: Accessor<ServerConnection.Any | undefined>) {
  const context = useServerCtx(server)
  const flag = useQuery(() => ({
    queryKey: [context()?.sdk.scope, "settings-connectors-flag"],
    enabled: !!context(),
    retry: false,
    queryFn: async () => connectorsConfigFlag(await context()!.sdk.api.config.get()),
  }))
  const probe = useQuery(() => ({
    queryKey: [context()?.sdk.scope, "settings-connectors-status"],
    enabled: !!context() && flag.data !== false,
    retry: false,
    queryFn: () => context()!.sdk.api.experimental.connectors.status(),
  }))
  const available = () => connectorsAvailable({ flag: flag.data, probe: probe.data })
  /** True once both reads finished, so a caller does not treat a pending probe as "disabled". */
  // Checks the pending flags before `data`, which suspends while its query loads.
  const settled = () => !context() || (!flag.isPending && (flag.data === false || !probe.isPending))
  return Object.assign(available, { settled })
}
