import { useLanguage } from "@/runtime/i18n/language"
import { Glyph } from "./glyph"
/** Mock workspace chrome for the Findings page. Nothing here is wired to a server. */
const WORKSPACE = "Bellu Security"
const UNREAD = 3
export function TopBar() {
  const language = useLanguage()
  return (
    <header data-slot="top-bar" aria-label={language.t("security.findings.topbar.label")}>
      <div data-slot="top-bar-start">
        <button
          type="button"
          class="sf-button"
          aria-label={language.t("security.findings.topbar.workspace", { name: WORKSPACE })}
        >
          <Glyph name="workspace" />
          {WORKSPACE}
          <Glyph name="chevron" />
        </button>
        <button type="button" class="sf-button">
          {language.t("security.findings.topbar.projects")}
          <Glyph name="chevron" />
        </button>
      </div>
      <div data-slot="top-bar-end">
        <button type="button" data-slot="top-search" aria-label={language.t("security.findings.topbar.search")}>
          <Glyph name="search" />
          <span>{language.t("security.findings.topbar.search")}</span>
          <kbd>{language.t("security.findings.topbar.searchHint")}</kbd>
        </button>
        <span data-slot="trial-badge">{language.t("security.findings.topbar.trial")}</span>
        <button type="button" data-slot="icon-button" aria-label={language.t("security.findings.topbar.history")}>
          <Glyph name="history" />
        </button>
        <button type="button" data-slot="icon-button" aria-label={language.t("security.findings.topbar.docs")}>
          <Glyph name="book" />
        </button>
        <button
          type="button"
          data-slot="icon-button"
          aria-label={language.t("security.findings.topbar.notifications", { count: UNREAD })}
        >
          <Glyph name="bell" />
          <span data-slot="notification-count" aria-hidden="true">
            {UNREAD}
          </span>
        </button>
        <button type="button" data-slot="icon-button" aria-label={language.t("security.findings.topbar.help")}>
          <Glyph name="help" />
        </button>
      </div>
    </header>
  )
}
