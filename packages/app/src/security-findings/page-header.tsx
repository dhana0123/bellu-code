import { useLanguage } from "@/runtime/i18n/language"
import { showToast } from "@/shell/notifications/toast"
import { Dropdown } from "./dropdown"
import { Glyph } from "./glyph"
export function PageHeader(props: { onShowHelp: () => void }) {
  const language = useLanguage()
  const save = (key: "saveView" | "saveReport" | "saveRule") => () =>
    showToast({
      title: language.t("security.findings.toast.saved", { value: language.t(`security.findings.header.${key}`) }),
    })
  return (
    <div data-slot="page-header">
      <h1>{language.t("security.findings.title")}</h1>
      <div data-slot="page-header-actions">
        <Dropdown
          label={language.t("security.findings.header.saveAs")}
          triggerClass="sf-button"
          align="end"
          trigger={
            <>
              {language.t("security.findings.header.saveAs")}
              <Glyph name="chevron" />
            </>
          }
          items={[
            { id: "view", label: language.t("security.findings.header.saveView"), onSelect: save("saveView") },
            { id: "report", label: language.t("security.findings.header.saveReport"), onSelect: save("saveReport") },
            { id: "rule", label: language.t("security.findings.header.saveRule"), onSelect: save("saveRule") },
          ]}
        />
        <button type="button" class="sf-button">
          {language.t("security.findings.header.manageRules")}
        </button>
        <button
          type="button"
          data-slot="icon-button"
          aria-label={language.t("security.findings.header.showHelp")}
          onClick={() => props.onShowHelp()}
        >
          <Glyph name="help" />
        </button>
        <button type="button" data-slot="icon-button" aria-label={language.t("security.findings.header.info")}>
          <Glyph name="info" />
        </button>
      </div>
    </div>
  )
}
