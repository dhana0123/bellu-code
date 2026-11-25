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
import { SECURITY_DASHBOARDS_SOON, SECURITY_PAGES, SECURITY_SOON, securityPath, type SecurityPage } from "./nav-items"
import { bomAvailable, bomConfigFlag } from "./bom-enabled"
import { scannersAvailable, scannersConfigFlag } from "./scanners-enabled"
import { issuesAvailable, issuesConfigFlag } from "./issues-enabled"
import { overviewAvailable, overviewConfigFlag } from "./overview-enabled"

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

    // Same shape as `connectors`: the config flag, then a probe of the service. Unknown or failed means off.
    const [overviewState] = createResource(
      () => {
        const conn = connection()
        const ctx = context()
        return conn && ctx ? { key: ServerConnection.key(conn), ctx } : undefined
      },
      async (source) => {
        const flag = await client
          .fetchQuery({
            queryKey: [source.ctx.sdk.scope, "security-overview-flag"],
            retry: false,
            queryFn: async () => overviewConfigFlag(await source.ctx.sdk.api.config.get()),
          })
          .catch(() => undefined)
        const probe =
          flag === false
            ? undefined
            : await client
                .fetchQuery({
                  queryKey: [source.ctx.sdk.scope, "security-overview-probe"],
                  retry: false,
                  queryFn: () => source.ctx.sdk.api.experimental.overview.categories().then(() => ({ enabled: true })),
                })
                .catch(() => undefined)
        return { key: source.key, available: overviewAvailable({ flag, probe }) }
      },
    )
    // Never suspends, like `sources`: Overview stays hidden until the answer for the current server is in.
    const overview = () => {
      const loaded = overviewState.state === "ready" || overviewState.state === "refreshing"
      const conn = connection()
      const result = loaded ? overviewState.latest : undefined
      return !!conn && result?.key === ServerConnection.key(conn) && result.available
    }
    // Same shape again for BOM: the `security_scanners` flag, then a probe of the SBOM list.
    const [bomState] = createResource(
      () => {
        const conn = connection()
        const ctx = context()
        return conn && ctx ? { key: ServerConnection.key(conn), ctx } : undefined
      },
      async (source) => {
        const flag = await client
          .fetchQuery({
            queryKey: [source.ctx.sdk.scope, "security-bom-flag"],
            retry: false,
            queryFn: async () => bomConfigFlag(await source.ctx.sdk.api.config.get()),
          })
          .catch(() => undefined)
        const probe =
          flag === false
            ? undefined
            : await client
                .fetchQuery({
                  queryKey: [source.ctx.sdk.scope, "security-bom-probe"],
                  retry: false,
                  queryFn: () => source.ctx.sdk.api.experimental.sbom.list().then(() => ({ enabled: true })),
                })
                .catch(() => undefined)
        return { key: source.key, available: bomAvailable({ flag, probe }) }
      },
    )
    const bom = () => {
      const loaded = bomState.state === "ready" || bomState.state === "refreshing"
      const conn = connection()
      const result = loaded ? bomState.latest : undefined
      return !!conn && result?.key === ServerConnection.key(conn) && result.available
    }
    // And for Scanners: the same flag, then a probe of the scanner list.
    const [scannersState] = createResource(
      () => {
        const conn = connection()
        const ctx = context()
        return conn && ctx ? { key: ServerConnection.key(conn), ctx } : undefined
      },
      async (source) => {
        const flag = await client
          .fetchQuery({
            queryKey: [source.ctx.sdk.scope, "security-scanners-flag"],
            retry: false,
            queryFn: async () => scannersConfigFlag(await source.ctx.sdk.api.config.get()),
          })
          .catch(() => undefined)
        const probe =
          flag === false
            ? undefined
            : await client
                .fetchQuery({
                  queryKey: [source.ctx.sdk.scope, "security-scanners-probe"],
                  retry: false,
                  queryFn: () => source.ctx.sdk.api.experimental.scans.scanners().then(() => ({ enabled: true })),
                })
                .catch(() => undefined)
        return { key: source.key, available: scannersAvailable({ flag, probe }) }
      },
    )
    const scanners = () => {
      const loaded = scannersState.state === "ready" || scannersState.state === "refreshing"
      const conn = connection()
      const result = loaded ? scannersState.latest : undefined
      return !!conn && result?.key === ServerConnection.key(conn) && result.available
    }
    // And for Issues: the `security_posture` flag, then a probe of the issue list.
    const [issuesState] = createResource(
      () => {
        const conn = connection()
        const ctx = context()
        return conn && ctx ? { key: ServerConnection.key(conn), ctx } : undefined
      },
      async (source) => {
        const flag = await client
          .fetchQuery({
            queryKey: [source.ctx.sdk.scope, "security-issues-flag"],
            retry: false,
            queryFn: async () => issuesConfigFlag(await source.ctx.sdk.api.config.get()),
          })
          .catch(() => undefined)
        const probe =
          flag === false
            ? undefined
            : await client
                .fetchQuery({
                  queryKey: [source.ctx.sdk.scope, "security-issues-probe"],
                  retry: false,
                  queryFn: () => source.ctx.sdk.api.experimental.issues.list({ limit: 1 }).then(() => ({ enabled: true })),
                })
                .catch(() => undefined)
        return { key: source.key, available: issuesAvailable({ flag, probe }) }
      },
    )
    const issues = () => {
      const loaded = issuesState.state === "ready" || issuesState.state === "refreshing"
      const conn = connection()
      const result = loaded ? issuesState.latest : undefined
      return !!conn && result?.key === ServerConnection.key(conn) && result.available
    }
    return {
      items: () =>
        SECURITY_PAGES.filter((item) => {
          if (item.page === "overview") return overview()
          if (item.page === "bom") return bom()
          if (item.page === "scanners") return scanners()
          if (item.page === "issues") return issues()
          return item.page !== "connectors" || sources()
        }),
      overview,
      bom,
      scanners,
      issues,
      soon: () => (overview() ? SECURITY_SOON : [SECURITY_DASHBOARDS_SOON, ...SECURITY_SOON]),
      active: (): SecurityPage | undefined => {
        const route = layout.route()
        return route.type === "security" ? route.page : undefined
      },
      open: (page: SecurityPage) => navigate(securityPath(page)),
      announce: (label: (typeof SECURITY_SOON)[number]["label"] | typeof SECURITY_DASHBOARDS_SOON.label) =>
        showToast({
          title: language.t("home.security.soon.title", { name: language.t(label) }),
          description: language.t("home.security.soon.description"),
        }),
    }
  },
})
