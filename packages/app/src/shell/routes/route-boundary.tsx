import { useLocation } from "@solidjs/router"
import { Button } from "@bellucode/ui/button"
import { createEffect, ErrorBoundary, on, type ParentProps } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"

type ScreenName = { key: Parameters<ReturnType<typeof useLanguage>["t"]>[0] } | { text: string }

// One screen failing to render (a crashed render or a failed lazy chunk import) shows here and leaves the shell
// and the other screens alone. The app-level boundary in app.tsx stays reserved for fatal failures.
// Solid's `lazy` clears a rejected import, so `reset` remounts the screen and re-triggers the import.
export function RouteBoundary(props: ParentProps<{ screen: ScreenName }>) {
  const language = useLanguage()
  const location = useLocation()
  const name = () => ("key" in props.screen ? language.t(props.screen.key) : props.screen.text)
  return (
    <ErrorBoundary
      fallback={(error, reset) => {
        console.error(error)
        void import("@sentry/solid").then(({ captureException }) => captureException(error))
        // The route component survives a param change, so leaving the failed target clears the error.
        createEffect(on(() => location.pathname, reset, { defer: true }))
        return (
          <div
            role="alert"
            data-component="route-error"
            class="flex min-h-0 flex-1 flex-col items-center justify-center gap-3 p-6 text-center"
          >
            <h2 class="text-16-medium text-text-strong">{name()}</h2>
            <p class="text-14-regular text-text-weak">{language.t("error.page.title")}</p>
            {/* Takes the event so the unit tests' hyperscript JSX does not read a zero-arg prop as a getter. */}
            <Button size="large" onClick={(_event: MouseEvent) => reset()}>
              {language.t("common.retry")}
            </Button>
          </div>
        )
      }}
    >
      {props.children}
    </ErrorBoundary>
  )
}
