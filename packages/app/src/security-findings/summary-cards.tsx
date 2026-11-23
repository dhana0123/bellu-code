import { For, Show, type JSX } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { MiddleTruncate, ResourceGlyph, RiskChip, TechBadge, severityLabelKey } from "./badges"
import type { RankedGroup } from "./filters"
import { Glyph } from "./glyph"
import { SEVERITIES, type Component, type FilterState, type Resource, type Severity } from "./model"

/**
 * Three cards that follow the active filters. The severity card ignores the severity filter itself, so choosing
 * "Critical" leaves the other rows visible and clickable.
 */
export function SummaryCards(props: {
  severity: FilterState["severity"]
  counts: Record<Severity, number>
  components: RankedGroup<Component>[]
  resources: RankedGroup<Resource>[]
  onSeverity: (severity: Severity) => void
}) {
  const language = useLanguage()
  return (
    <div data-slot="summary-cards">
      <Card title={language.t("security.findings.cards.severity")}>
        <ul data-slot="severity-rows">
          <For each={SEVERITIES}>
            {(severity) => (
              <li>
                <button
                  type="button"
                  data-severity={severity}
                  aria-pressed={props.severity === severity}
                  onClick={() => props.onSeverity(severity)}
                >
                  <span data-slot="bar" aria-hidden="true" />
                  <strong>{props.counts[severity].toLocaleString()}</strong>
                  <span>{language.t(severityLabelKey(severity))}</span>
                </button>
              </li>
            )}
          </For>
        </ul>
      </Card>
      <Card title={language.t("security.findings.cards.components")}>
        <Show when={props.components.length > 0} fallback={<Empty />}>
          <ul data-slot="rank-list" data-scrollable>
            <For each={props.components}>
              {(group) => (
                <li>
                  <TechBadge tech={group.item.tech} />
                  <span data-slot="rank-name" title={group.item.name}>
                    {group.item.name}
                  </span>
                  <span data-slot="rank-version">{group.item.version}</span>
                  <Chips critical={group.critical} high={group.high} />
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Card>
      <Card title={language.t("security.findings.cards.resources")}>
        <Show when={props.resources.length > 0} fallback={<Empty />}>
          <ul data-slot="rank-list" data-scrollable>
            <For each={props.resources}>
              {(group) => (
                <li>
                  <ResourceGlyph type={group.item.type} />
                  <span data-slot="rank-name">
                    <MiddleTruncate text={group.item.name} />
                  </span>
                  <Chips critical={group.critical} high={group.high} />
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Card>
    </div>
  )
}

function Card(props: { title: string; children: JSX.Element }) {
  const language = useLanguage()
  return (
    <section data-slot="card">
      <header>
        <h2>{props.title}</h2>
        <button
          type="button"
          data-slot="icon-button"
          aria-label={language.t("security.findings.cards.add", { name: props.title })}
        >
          <Glyph name="plus" />
        </button>
        <button
          type="button"
          data-slot="icon-button"
          aria-label={language.t("security.findings.cards.more", { name: props.title })}
        >
          <Glyph name="kebab" />
        </button>
      </header>
      {props.children}
    </section>
  )
}

function Chips(props: { critical: number; high: number }) {
  return (
    <span data-slot="chips">
      <RiskChip severity="critical" count={props.critical} />
      <RiskChip severity="high" count={props.high} />
    </span>
  )
}

function Empty() {
  const language = useLanguage()
  return <p data-slot="card-empty">{language.t("security.findings.cards.empty")}</p>
}
