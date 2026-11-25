import { A } from "@solidjs/router"
import { For, Show } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { securityPath } from "@/security/nav-items"
import { SEVERITIES, lensPath, type OverviewCategory } from "./model"
/**
 * One Category card. The title link is stretched over the whole card, so the card is one tab stop and the empty-state
 * link sits above it without nesting anchors. Counts are siblings of the link, so a screen reader reads them too.
 */
export function CategoryCard(props: { category: OverviewCategory }) {
  const language = useLanguage()
  return (
    <li data-slot="overview-card" data-category={props.category.category}>
      <h2 data-slot="card-title">
        <A
          href={lensPath(props.category.category)}
          data-slot="card-link"
          aria-label={language.t("home.security.overview.card.label", {
            title: props.category.title,
            count: props.category.entityCount,
          })}
          onKeyDown={(event) => {
            // A native link activates on Enter only.
            if (event.key !== " ") return
            event.preventDefault()
            event.currentTarget.click()
          }}
        >
          {props.category.title}
        </A>
      </h2>
      <p data-slot="card-subtitle">{props.category.subtitle}</p>
      <p data-slot="card-count">
        <strong>{props.category.entityCount.toLocaleString()}</strong>
        <span>{language.t("home.security.overview.entities")}</span>
      </p>
      <ul data-slot="card-severity" aria-label={language.t("home.security.overview.severity")}>
        <For each={SEVERITIES}>
          {(severity) => (
            <li data-severity={severity}>
              <strong>{props.category.severity[severity].toLocaleString()}</strong>
              <span>{language.t(`home.security.overview.severity.${severity}`)}</span>
            </li>
          )}
        </For>
      </ul>
      <Show when={props.category.topIssues.length > 0}>
        <ol data-slot="card-issues" aria-label={language.t("home.security.overview.topIssues")}>
          <For each={props.category.topIssues.slice(0, 3)}>
            {(issue) => (
              <li data-severity={issue.severity}>
                <span data-slot="issue-severity">{language.t(`home.security.overview.severity.${issue.severity}`)}</span>
                <A
                  href={`${securityPath("issues")}?id=${encodeURIComponent(issue.id)}`}
                  data-slot="issue-title"
                  title={issue.title}
                >
                  {issue.title}
                </A>
              </li>
            )}
          </For>
        </ol>
      </Show>
      <Show when={props.category.emptyState}>
        {(empty) => (
          <div data-slot="card-empty">
            <p>{language.t("home.security.overview.empty", { source: empty().missingSource })}</p>
            <A href={securityPath("connectors")} data-slot="card-connect">
              {language.t("home.security.overview.connect")}
            </A>
          </div>
        )}
      </Show>
    </li>
  )
}
