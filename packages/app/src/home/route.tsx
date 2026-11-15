import { ScrollView } from "@bellucode/ui/scroll-view"
import { createMediaQuery } from "@solid-primitives/media"
import { createEffect, createMemo, lazy, on, Show, Suspense } from "solid-js"
import { createStore } from "solid-js/store"
import { Button } from "@bellucode/ui/button"
import { Loader } from "@bellucode/ui/loader"
import { ServerConnection } from "@/runtime/server/registry"
import { ServerProvider } from "@/runtime/server/current"
import { useLanguage } from "@/runtime/i18n/language"
import { SettingsConnectors } from "@/settings/connectors/connectors-page"
import { ConnectionList } from "@/settings/connectors/connection-list"
import { ConnectDialog } from "@/settings/connectors/connect-dialog"
import { useConnectorsAvailable } from "@/settings/connectors/enabled"
import { createHomeController } from "./model"
import { createHomeProjectsController } from "./projects/controller"
import { HomeUtilityNav } from "./projects/view"
import { HomeProjects } from "./projects/region"
import { createHomeScrollController } from "./scroll"
import { createHomeSessionSearchController } from "./sessions/search"
import { createHomeSessionsController } from "./sessions/controller"
import { HomeSessions } from "./sessions/region"

export function Home() {
  const mobile = createMediaQuery("(max-width: 767px)")
  const home = createHomeController()
  const projects = createHomeProjectsController(home)
  const sessions = createHomeSessionsController(home)
  const search = createHomeSessionSearchController(home, sessions)
  const scroll = createHomeScrollController(sessions.data.groups)
  // Security pages Home shows in place of the session list. Picking a project goes back to the sessions.
  const [view, setView] = createStore<{ page: "sessions" | "connectors" | "graph" }>({ page: "sessions" })
  // Same server, same object: a refreshed server list must not remount the Connectors page (and end a sign-in).
  const connection = createMemo(
    () => {
      const key = sessions.session.server()
      return key ? projects.server.list().find((conn) => ServerConnection.key(conn) === key) : undefined
    },
    undefined,
    { equals: (a, b) => (a ? ServerConnection.key(a) : undefined) === (b ? ServerConnection.key(b) : undefined) },
  )
  const connectors = useConnectorsAvailable(connection)
  const securityPage = () => (view.page === "connectors" && connectors() ? "connectors" : view.page === "graph" ? "graph" : undefined)
  createEffect(on(() => projects.selection.value(), () => setView("page", "sessions"), { defer: true }))

  return (
    <div
      data-slot="home-panel"
      class={`
        mx-[var(--shell-inline-inset,8px)] mb-[var(--shell-bottom-inset,8px)] mt-[var(--shell-top-inset,8px)] flex min-h-0 flex-1 flex-col self-stretch overflow-hidden rounded-xl
        bg-v2-background-bg-base shadow-[var(--v2-elevation-raised)]
      `}
    >
      <Show when={mobile()}>
        <div class="relative z-40 -mb-3 shrink-0 px-3 pt-3">
          <HomeProjects projects={projects} scroll={scroll} dropdown />
        </div>
      </Show>
      <ScrollView
        class="min-h-0 flex-1 [container-type:size]"
        thumbContainer={scroll.viewport.thumbTrack()}
        thumbHoverTarget={scroll.viewport.hoverTarget()}
        viewportRef={scroll.viewport.setViewport}
        onScroll={(event) => scroll.viewport.update(event.currentTarget.scrollTop)}
      >
        <div
          class={`
            mx-auto grid min-h-full w-full max-w-[1080px] grid-rows-[auto_minmax(0,1fr)] gap-4 px-3
            max-md:grid-rows-[minmax(0,1fr)] lg:max-w-none lg:grid-cols-[260px_minmax(0,1fr)] lg:grid-rows-1 lg:gap-0 lg:px-0
          `}
        >
          <Show when={!mobile()}>
            <HomeProjects
              projects={projects}
              scroll={scroll}
              connectorsAvailable={connectors()}
              securityPage={securityPage()}
              onOpenConnectors={() => setView("page", "connectors")}
              graphAvailable
              onOpenGraph={() => setView("page", "graph")}
            />
          </Show>
          <Show
            when={securityPage() === "graph"}
            fallback={
              <Show
                when={securityPage() === "connectors" && connection()}
                fallback={<HomeSessions sessions={sessions} search={search} scroll={scroll} />}
              >
                {(server) => <HomeConnectors server={server()} onBack={() => setView("page", "sessions")} />}
              </Show>
            }
          >
            <HomeSecurityGraph onBack={() => setView("page", "sessions")} />
          </Show>
        </div>
      </ScrollView>
      <div class="hidden shrink-0 px-3 py-2 md:block lg:hidden">
        <HomeUtilityNav
          class="flex"
          onOpenSettings={projects.utility.settings}
          onOpenHelp={projects.utility.help}
          language={projects.copy.language}
        />
      </div>
    </div>
  )
}

// The Connectors page of the Security menu, shown in Home's main column for the server the sessions list shows.
function HomeConnectors(props: { server: ServerConnection.Any; onBack: () => void }) {
  const language = useLanguage()
  return (
    <ServerProvider conn={props.server}>
      <div data-slot="home-connectors" class="min-w-0 lg:mx-auto lg:w-full lg:max-w-[920px]">
        <SettingsConnectors
          headerAction={
            <Button size="small" variant="ghost" onClick={() => props.onBack()}>
              {language.t("home.security.backToSessions")}
            </Button>
          }
          connectionList={({ card, data, open }) => <ConnectionList card={card} data={data} onReconnect={open} />}
          connectDialog={(ctx) => <ConnectDialog {...ctx} />}
        />
      </div>
    </ServerProvider>
  )
}

// The Security Graph loads on demand so its renderer and layout code stay out of the main chunk.
const SecurityGraphPage = lazy(() =>
  import("@/security-graph/page").then((module) => ({ default: module.SecurityGraphPage })),
)
function HomeSecurityGraph(props: { onBack: () => void }) {
  const language = useLanguage()
  return (
    <div data-slot="home-security-graph" class="flex h-[max(560px,100cqh)] min-w-0 flex-col">
      <Suspense
        fallback={
          <div class="flex flex-1 items-center justify-center gap-2 text-text-weak" role="status">
            <Loader class="size-4" />
            <span>{language.t("security.graph.loading")}</span>
          </div>
        }
      >
        <SecurityGraphPage
          headerAction={
            <Button size="small" variant="ghost" onClick={() => props.onBack()}>
              {language.t("home.security.backToSessions")}
            </Button>
          }
        />
      </Suspense>
    </div>
  )
}
