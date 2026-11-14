import { useQuery } from "@tanstack/solid-query"
import type { Accessor } from "solid-js"
import { useServerCtx } from "@/runtime/server/runtime"
import type { ServerConnection } from "@/runtime/server/registry"
import { securityGraphEnabled } from "./enabled"
/** Whether the Security Graph page and nav entry show for `server`: the `security_graph` flag, read from its config. */
export function useSecurityGraphAvailable(server: Accessor<ServerConnection.Any | undefined>) {
  const context = useServerCtx(server)
  const flag = useQuery(() => ({
    queryKey: [context()?.sdk.scope, "security-graph-flag"],
    enabled: !!context(),
    retry: false,
    queryFn: async () => securityGraphEnabled(await context()!.sdk.api.config.get()),
  }))
  return () => flag.data === true
}
