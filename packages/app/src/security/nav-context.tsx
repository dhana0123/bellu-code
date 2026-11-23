import { createResource } from "solid-js"
import { useNavigate } from "@solidjs/router"
import { useQueryClient } from "@tanstack/solid-query"
import { createSimpleContext } from "@bellucode/ui/context/helper"
import { useLanguage } from "@/runtime/i18n/language"
import { ServerConnection } from "@/runtime/server/registry"
import { useServerCtx } from "@/runtime/server/runtime"
import { connectorsAvailable, connectorsConfigFlag } from "@/settings/connectors/enabled"
import { useLayout } from "@/shell/state/layout"
import { showToast } from "@/shell/notifications/toast"
import { useSecurityConnection } from "./connection"
import { SECURITY_PAGES, SECURITY_SOON, securityPath, type SecurityPage } from "./nav-items"

/**
 * The security menu's items, built once for the whole shell. Every menu that lists them (the sidebar, its flyout, the
 * composer's add menu) reads this instead of creating its own queries: a query mounted with a menu suspends on its
 * first `.data` read, which blanks the session route and lets the popover mount before it is positioned.
 */
export const { use: useSecurityNav, provider: SecurityNavProvider } = createSimpleContext({
  name: "SecurityNav",
  gate: false,
  init: () => {
    const language = useLanguage()
    const layout = useLayout()
    const navigate = useNavigate()
    const client = useQueryClient()
    const connection = useSecurityConnection()
    const context = useServerCtx(connection)

    // Same keys as `useConnectorsAvailable`, so Settings and this share one cached answer per server.
    const [connectors] = createResource(
      () => {
        const conn = connection()
        const ctx = context()
        return conn && ctx ? { key: ServerConnection.key(conn), ctx } : undefined
      },
      async (source) => {
        const flag = await client
          .fetchQuery({
            queryKey: [source.ctx.sdk.scope, "settings-connectors-flag"],
            retry: false,
            queryFn: async () => connectorsConfigFlag(await source.ctx.sdk.api.config.get()),
          })
          .catch(() => undefined)
        // A disabled service answers 404, which hides Sources.
        const probe =
          flag === false
            ? undefined
            : await client
                .fetchQuery({
                  queryKey: [source.ctx.sdk.scope, "settings-connectors-status"],
                  retry: false,
                  queryFn: () => source.ctx.sdk.api.experimental.connectors.status(),
                })
                .catch(() => undefined)
        return { key: source.key, available: connectorsAvailable({ flag, probe }) }
      },
    )

    // Never suspends: until the answer for the current server is in, Sources stays hidden.
    const sources = () => {
      const loaded = connectors.state === "ready" || connectors.state === "refreshing"
      const conn = connection()
      const result = loaded ? connectors.latest : undefined
      return !!conn && result?.key === ServerConnection.key(conn) && result.available
    }

    return {
      items: () => SECURITY_PAGES.filter((item) => item.page !== "connectors" || sources()),
      soon: SECURITY_SOON,
      active: (): SecurityPage | undefined => {
        const route = layout.route()
        return route.type === "security" ? route.page : undefined
      },
      open: (page: SecurityPage) => navigate(securityPath(page)),
      announce: (label: (typeof SECURITY_SOON)[number]["label"]) =>
        showToast({
          title: language.t("home.security.soon.title", { name: language.t(label) }),
          description: language.t("home.security.soon.description"),
        }),
    }
  },
})
