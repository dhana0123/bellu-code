import { lazy, Match, Show, Suspense, Switch } from "solid-js"
import { Icon } from "@bellucode/ui/icon"
import { IconButton } from "@bellucode/ui/icon-button"
import { Loader } from "@bellucode/ui/loader"
import { Tooltip } from "@bellucode/ui/tooltip"
import { ServerProvider } from "@/runtime/server/current"
import { useLanguage } from "@/runtime/i18n/language"
import { useSettings } from "@/settings/model"
import { useLayout } from "@/shell/state/layout"
import { SettingsConnectors } from "@/settings/connectors/connectors-page"
import { ConnectionList } from "@/settings/connectors/connection-list"
import { ConnectDialog } from "@/settings/connectors/connect-dialog"
import { useSecurityConnection } from "./connection"
import type { SecurityPage } from "./nav-items"

// Each page loads on demand so the graph renderer and the findings table stay out of the main chunk.
const SecurityGraphPage = lazy(() =>
  import("@/security-graph/page").then((module) => ({ default: module.SecurityGraphPage })),
)
const SecurityFindingsPage = lazy(() =>
  import("@/security-findings/page").then((module) => ({ default: module.SecurityFindingsPage })),
)

/** A security page in the whole main area. The sidebar stays unless the page's maximize button hides it. */
export function SecurityRoute() {
  const layout = useLayout()
  const language = useLanguage()
  const preferences = useSettings()

  const page = (): SecurityPage | undefined => {
    const route = layout.route()
    return route.type === "security" ? route.page : undefined
  }

  const connection = useSecurityConnection()

  const maximize = () => (
    <Tooltip
      placement="bottom"
      value={language.t(preferences.appearance.sidebarOpen() ? "security.maximize" : "security.restore")}
    >
      <IconButton
        data-action="security-maximize"
        variant="ghost-muted"
        size="large"
        icon={<Icon name={preferences.appearance.sidebarOpen() ? "expand" : "sidebar"} />}
        aria-pressed={!preferences.appearance.sidebarOpen()}
        aria-label={language.t(preferences.appearance.sidebarOpen() ? "security.maximize" : "security.restore")}
        onClick={() => preferences.appearance.setSidebarOpen(!preferences.appearance.sidebarOpen())}
      />
    </Tooltip>
  )

  return (
    <div
      data-slot="security-panel"
      class={`
        mx-[var(--shell-inline-inset,8px)] mb-[var(--shell-bottom-inset,8px)] mt-[var(--shell-top-inset,8px)] flex min-h-0 min-w-0 flex-1 flex-col self-stretch overflow-hidden rounded-xl
        bg-v2-background-bg-base shadow-[var(--v2-elevation-raised)]
      `}
    >
      <Show
        when={connection()}
        keyed
        fallback={
          <div class="flex flex-1 items-center justify-center text-text-weak">
            {language.t("home.security.graph.noServer")}
          </div>
        }
      >
        {(server) => (
          <ServerProvider conn={server}>
            <Suspense
              fallback={
                <div class="flex flex-1 items-center justify-center gap-2 text-text-weak" role="status">
                  <Loader class="size-4" />
                  <span>{language.t("security.loading")}</span>
                </div>
              }
            >
              <Switch>
                <Match when={page() === "graph"}>
                  <div data-slot="security-graph" class="flex min-h-0 min-w-0 flex-1 flex-col">
                    <SecurityGraphPage headerAction={maximize()} />
                  </div>
                </Match>
                <Match when={page() === "findings"}>
                  <div data-slot="security-findings" class="flex min-h-0 min-w-0 flex-1 flex-col">
                    <div class="flex shrink-0 justify-end px-3 pt-2">{maximize()}</div>
                    <div data-scrollable class="min-h-0 flex-1 overflow-y-auto">
                      <SecurityFindingsPage />
                    </div>
                  </div>
                </Match>
                <Match when={page() === "connectors"}>
                  <div data-slot="security-connectors" data-scrollable class="min-h-0 min-w-0 flex-1 overflow-y-auto">
                    <div class="mx-auto w-full max-w-[920px]">
                      <SettingsConnectors
                        headerAction={maximize()}
                        connectionList={({ card, data, open }) => (
                          <ConnectionList card={card} data={data} onReconnect={open} />
                        )}
                        connectDialog={(ctx) => <ConnectDialog {...ctx} />}
                      />
                    </div>
                  </div>
                </Match>
              </Switch>
            </Suspense>
          </ServerProvider>
        )}
      </Show>
    </div>
  )
}
