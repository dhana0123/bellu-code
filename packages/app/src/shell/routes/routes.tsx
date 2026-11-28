import { Route, useParams } from "@solidjs/router"
import { createMemo, lazy, Show, Suspense, type ParentProps } from "solid-js"
import { Home } from "@/home/route"
import { SecurityRoute } from "@/security/route"
import { SecurityNavProvider } from "@/security/nav-context"
import { ServerProvider } from "@/runtime/server/current"
import { useGlobal } from "@/runtime/server/runtime"
import { ServerConnection, useServers } from "@/runtime/server/registry"
import { isServerUnauthorized } from "@/runtime/server/health-machine"
import { SessionPanelFrame, SessionRouteFrame } from "@/session/session-frame"
import { ServerSignedOutPanel } from "@/session/server-unavailable-panel"
import { LayoutProvider } from "@/shell/state/layout"
import { SettingsSurfaceProvider } from "@/settings/surface"
import Shell from "@/shell/shell"
import { requireServerKey } from "./session"
import { PluginAttachment } from "@/runtime/plugin/root"
import { RouteBoundary } from "./route-boundary"

export const File = lazy(() => import("@bellucode/session-ui/file").then((module) => ({ default: module.File })))

const loadSessionRoute = () => Promise.all([import("@/session/route"), File.preload()]).then(([module]) => module)

const DraftRoute = lazy(() => import("@/new-session/route").then((module) => ({ default: module.DraftRoute })))

const SettingsScreen = lazy(() => import("@/settings/shell").then((module) => ({ default: module.SettingsScreen })))

const ConnectServerScreen = lazy(() =>
  import("@/servers/connect/screen").then((module) => ({ default: module.ConnectServerScreen })),
)

// The dev server and Beta only. Both are fixed at build time, so other builds, prod included, drop the import and never
// contain the lab, its stories or knobs. Beta loads it as its own chunk, only when /components opens.
const ComponentsLab =
  import.meta.env.DEV || import.meta.env.VITE_BELLUCODE_CHANNEL === "beta"
    ? lazy(() => import("@/components-lab/lab"))
    : undefined

const TargetSessionRouteContent = lazy(() =>
  loadSessionRoute().then((module) => ({ default: module.TargetSessionRouteContent })),
)

export function preloadRoute(url: string) {
  const pathname = url.split(/[?#]/, 1)[0]

  if (pathname === "/new-session") return DraftRoute.preload().then(() => undefined)

  if (pathname === "/settings") return SettingsScreen.preload().then(() => undefined)

  if (/^\/server\/[^/]+\/session\/[^/]+$/.test(pathname))
    return TargetSessionRouteContent.preload().then(() => undefined)

  return Promise.resolve()
}

function HomeScreen() {
  return (
    <RouteBoundary screen={{ key: "home.title" }}>
      <Home />
    </RouteBoundary>
  )
}
function SettingsRoute() {
  return (
    <RouteBoundary screen={{ key: "sidebar.settings" }}>
      <SettingsScreen />
    </RouteBoundary>
  )
}
function SecurityScreen() {
  return (
    <RouteBoundary screen={{ key: "home.security" }}>
      <SecurityRoute />
    </RouteBoundary>
  )
}
function NewSessionRoute() {
  return (
    <RouteBoundary screen={{ key: "command.session.new" }}>
      <DraftRoute />
    </RouteBoundary>
  )
}
function ComponentsRoute() {
  return <RouteBoundary screen={{ text: "Components" }}>{ComponentsLab && <ComponentsLab />}</RouteBoundary>
}
export function AppRoutes() {
  return (
    <Route component={AppLayout}>
      <Route path="/" component={HomeScreen} />
      <Route path="/settings" component={SettingsRoute} />
      <Route path="/security/:page" component={SecurityScreen} />
      <Route
        path="/server/:serverKey/session/:id"
        component={() => (
          <SessionRouteFrame>
            <RouteBoundary screen={{ key: "session.tab.session" }}>
              <Suspense
                fallback={
                  <div class="flex min-h-0 flex-1 px-[var(--shell-inline-inset,8px)] pb-[var(--shell-bottom-inset,8px)] pt-[var(--shell-top-inset,8px)]">
                    <SessionPanelFrame raised />
                  </div>
                }
              >
                <TargetServerRoute>
                  <TargetSessionRouteContent />
                </TargetServerRoute>
              </Suspense>
            </RouteBoundary>
          </SessionRouteFrame>
        )}
      />
      <Route path="/new-session" component={NewSessionRoute} />
      {ComponentsLab && <Route path="/components" component={ComponentsRoute} />}
    </Route>
  )
}

function TargetServerRoute(props: ParentProps) {
  const params = useParams<{ serverKey: string }>()
  const global = useGlobal()

  const connection = createMemo(() =>
    global.servers.list().find((item) => ServerConnection.key(item) === requireServerKey(params.serverKey)),
  )

  return (
    <Show when={connection()} keyed>
      {(connection) => (
        <ServerProvider
          conn={connection}
          signedOut={
            <div class="flex min-h-0 flex-1 px-[var(--shell-inline-inset,8px)] pb-[var(--shell-bottom-inset,8px)] pt-[var(--shell-top-inset,8px)]">
              <SessionPanelFrame raised>
                <ServerSignedOutPanel conn={connection} />
              </SessionPanelFrame>
            </div>
          }
        >
          {props.children}
        </ServerProvider>
      )}
    </Show>
  )
}

function AppLayout(props: ParentProps) {
  const servers = useServers()
  const global = useGlobal()

  // A lone server that rejects our credentials (e.g. the web app before pairing) has nothing else to show.
  const signedOut = () => {
    const only = servers.list.length === 1 ? servers.list[0] : undefined

    if (only?.type !== "http") return

    return isServerUnauthorized(global.servers.health[ServerConnection.key(only)]) ? only : undefined
  }

  return (
    <Show when={servers.list.length > 0 && !signedOut()} fallback={<ConnectServerScreen url={signedOut()?.http.url} />}>
      <LayoutProvider>
        <SettingsSurfaceProvider>
          <PluginAttachment>
            <SecurityNavProvider>
              <Shell>{props.children}</Shell>
            </SecurityNavProvider>
          </PluginAttachment>
        </SettingsSurfaceProvider>
      </LayoutProvider>
    </Show>
  )
}
