import { afterEach, describe, expect, mock, test } from "bun:test"
import { createComponent, type Component, type JSX } from "solid-js"
import { render } from "solid-js/web"

// Mirrors the "port" / "adapt" screens in .kiro/specs/desktop-web-ui-sync/parity-inventory.md ("Routes and screens").
// That file is gitignored, so the list is kept here. When the inventory gains a port/adapt screen, add it to
// SCREENS and add a case to CASES; the completeness test fails until both agree.
const SCREENS = [
  "Security overview",
  "Security graph",
  "Security findings",
  "Security BOM",
  "Security scanners",
  "Security issues",
  "Settings: connectors",
] as const
type Screen = (typeof SCREENS)[number]

// A data call resolves to an empty result: every list-like field is empty, so a screen mounts its empty state.
const empty = { items: [], categories: [], data: [], findings: [], packages: [], nodes: [], edges: [], revision: 0 }
const callable = (): unknown =>
  new Proxy(() => Promise.resolve(empty), {
    get: (_target, key) => (key === "then" ? undefined : callable()),
  })
const sdk = {
  server: { type: "http", http: { url: "http://localhost:0" } },
  api: callable(),
  event: { listen: () => () => {}, on: () => () => {} },
  url: "http://localhost:0",
}

mock.module("@/runtime/i18n/language", () => ({
  useLanguage: () => ({ t: (key: string) => key, locale: () => "en" }),
}))
mock.module("@solidjs/router", () => ({
  useLocation: () => ({ pathname: "/", search: "" }),
  useSearchParams: () => [{}, () => {}],
  useNavigate: () => () => {},
  A: (props: { children?: JSX.Element }) => props.children,
}))
// Persisted state reads the platform; the web platform needs no provider tree beyond this.
const platform = { platform: "web", openExternal: () => {}, restart: async () => {}, notify: async () => {} }
const actualPlatform = await import("@/runtime/platform/platform")
mock.module("@/runtime/platform/platform", () => ({ ...actualPlatform, usePlatform: () => platform }))
// happy-dom has no WebGL; the graph renderer (sigma) only needs the constructor to exist at import time.
Object.assign(globalThis, { WebGL2RenderingContext: globalThis.WebGL2RenderingContext ?? class {} })
mock.module("@sentry/solid", () => ({ captureException: () => {} }))
mock.module("@/runtime/server/client", () => ({ useServerSDK: () => sdk }))
mock.module("@/shell/notifications/toast", () => ({ showToast: () => {} }))

const MOUNT_TIMEOUT_MS = 5000
const load: Record<Screen, () => Promise<Component>> = {
  "Security overview": async () => (await import("@/security-overview/page")).SecurityOverviewPage,
  "Security graph": async () => (await import("@/security-graph/page")).SecurityGraphPage,
  "Security findings": async () => (await import("@/security-findings/page")).SecurityFindingsPage,
  "Security BOM": async () => (await import("@/security-bom/page")).SecurityBomPage,
  "Security scanners": async () => (await import("@/security-scanners/page")).SecurityScannersPage,
  "Security issues": async () => (await import("@/security-issues/page")).SecurityIssuesPage,
  "Settings: connectors": async () => (await import("@/settings/connectors/connectors-page")).SettingsConnectors,
}
const CASES = Object.keys(load) as Screen[]

const cleanups: (() => void)[] = []
// Test JSX (hyperscript) reads each array prop item for `$ELEMENT`, so `<For each={Array.from({ length: n })}>`
// (skeleton rows) throws on its undefined items; compiled Solid does not. Fill such arrays with 0 while mounting.
const arrayFrom = Array.from
function fillPlaceholders() {
  Array.from = ((source: unknown, ...rest: unknown[]) => {
    const placeholder = typeof source === "object" && source !== null && Object.keys(source).join() === "length"
    if (placeholder && rest.length === 0) return new Array<number>((source as { length: number }).length).fill(0)
    return (arrayFrom as (...args: unknown[]) => unknown)(source, ...rest)
  }) as typeof Array.from
}
const consoleError = console.error
const errors: unknown[][] = []
const uncaught: unknown[] = []
const onError = (event: ErrorEvent) => uncaught.push(event.error ?? event.message)
const onRejection = (reason: unknown) => uncaught.push(reason)
afterEach(() => {
  cleanups.splice(0).forEach((cleanup) => cleanup())
  console.error = consoleError
  Array.from = arrayFrom
  window.removeEventListener("error", onError)
  process.off("unhandledRejection", onRejection)
})

async function mountScreen(Screen: Component) {
  errors.length = 0
  uncaught.length = 0
  console.error = (...args: unknown[]) => void errors.push(args)
  fillPlaceholders()
  window.addEventListener("error", onError)
  process.on("unhandledRejection", onRejection)
  const host = document.createElement("div")
  document.body.append(host)
  // Hyperscript JSX needs the component created inside the render root; see route-boundary.test.tsx.
  const dispose = render(() => createComponent(Screen, {}), host)
  cleanups.push(() => {
    dispose()
    host.remove()
  })
  // Let the empty data calls settle so a late throw or console.error is caught too.
  await new Promise((resolve) => setTimeout(resolve, 50))
  return host
}

describe("screen mount", () => {
  test("every port/adapt screen has a mount case", () => {
    const missing = SCREENS.filter((screen) => !CASES.includes(screen))
    const unlisted = CASES.filter((screen) => !(SCREENS as readonly string[]).includes(screen))
    expect({ missing, unlisted }).toEqual({ missing: [], unlisted: [] })
  })

  for (const screen of SCREENS) {
    test(
      `${screen} mounts with no uncaught exception and no console.error`,
      async () => {
        const started = performance.now()
        const Screen = await load[screen]()
        const host = await mountScreen(Screen)
        expect(performance.now() - started).toBeLessThan(MOUNT_TIMEOUT_MS)
        expect(errors).toEqual([])
        expect(uncaught).toEqual([])
        expect(host.childNodes.length).toBeGreaterThan(0)
      },
      MOUNT_TIMEOUT_MS,
    )
  }
})
