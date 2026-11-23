import { createMemo } from "solid-js"
import { ServerConnection, useServers } from "@/runtime/server/registry"
import { useLayout } from "@/shell/state/layout"

/** The server the security pages read: the one Home has selected, else the first. */
export function useSecurityConnection() {
  const layout = useLayout()
  const servers = useServers()

  // Same server, same object, so a refreshed server list does not remount a page (and end a sign-in).
  return createMemo(
    () => servers.list.find((item) => ServerConnection.key(item) === layout.home.selection().server) ?? servers.list[0],
    undefined,
    { equals: (a, b) => (a ? ServerConnection.key(a) : undefined) === (b ? ServerConnection.key(b) : undefined) },
  )
}
