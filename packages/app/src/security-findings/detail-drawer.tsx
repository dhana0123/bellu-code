import { createEffect, For, onCleanup, Show } from "solid-js"
import { Portal } from "solid-js/web"
import { useLanguage } from "@/runtime/i18n/language"
import {
  ProviderGlyph,
  ResourceGlyph,
  SeverityPill,
  StatusPill,
  resourceTypeLabelKey,
  severityLabelKey,
} from "./badges"
import { Glyph } from "./glyph"
import { relatedIssuesFor } from "./mock-data"
import type { Finding } from "./model"

/**
 * Right-side details for one finding. It is not a route. Esc or the close button dismisses it and the page returns
 * focus to the row that opened it.
 */
export function DetailDrawer(props: {
  finding: Finding | undefined
  onClose: () => void
  onIgnore: (finding: Finding) => void
  onCopyLink: (finding: Finding) => void
}) {
  const language = useLanguage()
  let close: HTMLButtonElement | undefined
  let drawer: HTMLElement | undefined

  createEffect(() => {
    if (!props.finding) return
    queueMicrotask(() => close?.focus({ preventScroll: true }))
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Tab" && drawer) {
        // The drawer is modal, so Tab cycles inside it.
        const items = [...drawer.querySelectorAll<HTMLElement>("button:not([disabled])")]
        const edge = event.shiftKey ? items[0] : items[items.length - 1]
        if (document.activeElement === edge) {
          event.preventDefault()
          items[event.shiftKey ? items.length - 1 : 0].focus()
        }
        return
      }
      if (event.key !== "Escape") return
      event.stopPropagation()
      props.onClose()
    }
    document.addEventListener("keydown", onKey, true)
    onCleanup(() => document.removeEventListener("keydown", onKey, true))
  })

  return (
    <Show when={props.finding}>
      {(finding) => (
        <Portal>
          <div data-component="security-findings-drawer-layer">
            <div data-slot="drawer-scrim" onClick={() => props.onClose()} />
            <aside
              ref={drawer}
              data-slot="drawer"
              role="dialog"
              aria-modal="true"
              aria-label={language.t("security.findings.drawer.label", { cve: finding().cve })}
            >
              <header>
                <h2>{finding().cve}</h2>
                <SeverityPill severity={finding().severity} />
                <button
                  ref={close}
                  type="button"
                  data-slot="icon-button"
                  aria-label={language.t("security.findings.drawer.close")}
                  onClick={() => props.onClose()}
                >
                  <Glyph name="close" />
                </button>
              </header>
              <div data-slot="drawer-body" data-scrollable>
                <p data-slot="description">{finding().description}</p>
                <dl>
                  <dt>{language.t("security.findings.column.status")}</dt>
                  <dd>
                    <StatusPill />
                  </dd>
                  <dt>{language.t("security.findings.drawer.score")}</dt>
                  <dd>{finding().cvss.toFixed(1)}</dd>
                  <dt>{language.t("security.findings.drawer.resource")}</dt>
                  <dd>
                    <span data-slot="line">
                      <ResourceGlyph type={finding().resource.type} />
                      <span data-slot="wrap">{finding().resource.name}</span>
                    </span>
                    <span data-slot="sub">{language.t(resourceTypeLabelKey(finding().resource.type))}</span>
                  </dd>
                  <dt>{language.t("security.findings.drawer.component")}</dt>
                  <dd>
                    {finding().component.name} {finding().component.version}
                    <span data-slot="sub">{finding().component.kind}</span>
                  </dd>
                  <dt>{language.t("security.findings.column.fix")}</dt>
                  <dd>{finding().fixVersion ?? language.t("security.findings.drawer.noFix")}</dd>
                  <dt>{language.t("security.findings.column.detection")}</dt>
                  <dd>{language.t(`security.findings.detection.${finding().component.dependency}`)}</dd>
                  <dt>{language.t("security.findings.column.subscription")}</dt>
                  <dd>
                    <span data-slot="line">
                      <ProviderGlyph provider={finding().resource.subscription.provider} />
                      {finding().resource.subscription.name}
                    </span>
                    <span data-slot="sub">{finding().resource.subscription.id}</span>
                  </dd>
                </dl>
                <h3>{language.t("security.findings.column.related")}</h3>
                <Show
                  when={relatedIssuesFor(finding()).length > 0}
                  fallback={<p data-slot="sub">{language.t("security.findings.drawer.noRelated")}</p>}
                >
                  <ul data-slot="related">
                    <For each={relatedIssuesFor(finding())}>
                      {(issue) => (
                        <li>
                          <span data-slot="pill" data-severity={issue.severity}>
                            {language.t(severityLabelKey(issue.severity))}
                          </span>
                          <span>{issue.title}</span>
                          <span data-slot="sub">{issue.count.toLocaleString()}</span>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </div>
              <footer>
                <button
                  type="button"
                  class="sf-button"
                  data-variant="outline"
                  onClick={() => props.onIgnore(finding())}
                >
                  {language.t("security.findings.action.ignore")}
                </button>
                <button
                  type="button"
                  class="sf-button"
                  data-variant="outline"
                  onClick={() => props.onCopyLink(finding())}
                >
                  {language.t("security.findings.drawer.copyLink")}
                </button>
              </footer>
            </aside>
          </div>
        </Portal>
      )}
    </Show>
  )
}
