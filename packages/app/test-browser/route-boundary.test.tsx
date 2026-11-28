import { afterEach, describe, expect, mock, test } from "bun:test"
import { createComponent, createSignal, type Component, type JSX } from "solid-js"
import { render } from "solid-js/web"

mock.module("@/runtime/i18n/language", () => ({ useLanguage: () => ({ t: (key: string) => key }) }))
mock.module("@solidjs/router", () => ({ useLocation: () => ({ pathname: "/" }) }))
mock.module("@sentry/solid", () => ({ captureException: () => {} }))
const { RouteBoundary } = await import("@/shell/routes/route-boundary")

const cleanups: (() => void)[] = []
const consoleError = console.error
afterEach(() => {
  cleanups.splice(0).forEach((cleanup) => cleanup())
  console.error = consoleError
})

function mount(ui: () => JSX.Element) {
  // The boundary logs what it catches; these tests throw on purpose.
  console.error = () => {}
  const host = document.createElement("div")
  document.body.append(host)
  const dispose = render(ui, host)
  cleanups.push(() => {
    dispose()
    host.remove()
  })
  return host
}

// Test JSX compiles to Solid's hyperscript runtime, not Solid's compiler, and two of its differences matter here.
// Hyperscript reads `props.children` eagerly, so the screen is handed over as a thunk that only the ErrorBoundary
// calls; compiled Solid creates it there too. Hyperscript also returns components as one-shot thunks, so the result
// is unwrapped once, giving the ErrorBoundary's own accessor as compiled Solid would.
function boundary(name: string, Screen: Component) {
  const screen = () => createComponent(Screen, {})
  const element = createComponent(RouteBoundary, {
    screen: { text: name },
    get children() {
      return screen as unknown as JSX.Element
    },
  })
  return (element as unknown as () => JSX.Element)()
}

describe("RouteBoundary", () => {
  test("a throwing screen shows its name and a retry button", () => {
    const host = mount(() =>
      boundary("Broken screen", () => {
        throw new Error("boom")
      }),
    )
    const alert = host.querySelector('[role="alert"]')
    expect(alert).not.toBeNull()
    expect(alert!.textContent).toContain("Broken screen")
    expect(alert!.querySelector("button")?.textContent).toContain("common.retry")
  })

  test("retry remounts the screen, and a screen outside the boundary stays usable", () => {
    let failing = true
    let mounts = 0
    const Screen = () => {
      mounts++
      if (failing) throw new Error("boom")
      return <p data-test="screen">recovered</p>
    }
    const [count, setCount] = createSignal(0)
    const host = mount(() => [
      <button data-test="other" onClick={() => setCount(count() + 1)}>
        other screen
      </button>,
      boundary("Flaky", Screen),
    ])
    expect(host.querySelector('[role="alert"]')).not.toBeNull()

    // The other screen still renders and responds while this one shows its error.
    const other = host.querySelector<HTMLButtonElement>('[data-test="other"]')!
    other.click()
    expect(count()).toBe(1)

    failing = false
    host.querySelector<HTMLButtonElement>('[role="alert"] button')!.click()
    expect(mounts).toBe(2)
    expect(host.querySelector('[role="alert"]')).toBeNull()
    expect(host.querySelector('[data-test="screen"]')?.textContent).toBe("recovered")
    // Same node: neither the failure nor the retry replaced the other screen.
    expect(host.querySelector('[data-test="other"]')).toBe(other)
  })
})
