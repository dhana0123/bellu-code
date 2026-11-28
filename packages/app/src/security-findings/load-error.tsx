import { useLanguage } from "@/runtime/i18n/language"
import { Glyph } from "./glyph"

/** The list could not load. `unavailable` is a server without the findings API, which retrying does not fix at once. */
export function LoadError(props: { reason: "unavailable" | "error"; onRetry: () => void }) {
  const language = useLanguage()
  return (
    <div data-slot="load-error" role="alert">
      <Glyph name="info" size={20} />
      <p>
        {props.reason === "unavailable"
          ? language.t("security.findings.error.unavailable")
          : language.t("security.findings.error.failed")}
      </p>
      <button type="button" class="sf-button" data-variant="outline" onClick={() => props.onRetry()}>
        {language.t("security.findings.error.retry")}
      </button>
    </div>
  )
}
