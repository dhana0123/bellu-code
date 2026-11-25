import { For, Show, type JSX } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { MiddleTruncate, RiskChip, severityLabelKey } from "./badges"
import type { RankedGroup } from "./filters"
import { Glyph } from "./glyph"
import { SEVERITIES, type FilterState, type Severity } from "./model"

/**
 * Three cards that follow the active filters. The severity card ignores the severity filter itself, so choosing
 * "Critical" leaves the other rows visible and clickable.
 */
export function SummaryCards(props: {
  severity: FilterState["severity"]
  /** A severity the server was not asked for has no count. */
  counts: Partial<Record<Severity, number>>
  /** The server has more rows than are loaded, so each count is a lower bound. */
  more: boolean
  rules: RankedGroup[]
  assets: RankedGroup[]
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
                  <strong>{count(props.counts[severity], props.more)}</strong>
                  <span>{language.t(severityLabelKey(severity))}</span>
                </button>
              </li>
            )}
          </For>
        </ul>
      </Card>
      <Card title={language.t("security.findings.cards.rules")}>
        <Show when={props.rules.length > 0} fallback={<Empty />}>
          <ul data-slot="rank-list" data-scrollable>
            <For each={props.rules}>
              {(group) => (
                <li>
                  <Glyph name="bug" class="sf-icon" />
                  <span data-slot="rank-name" title={group.item.name}>
                    {group.item.name}
                  </span>
                  <Chips critical={group.critical} high={group.high} />
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Card>
      <Card title={language.t("security.findings.cards.assets")}>
        <Show when={props.assets.length > 0} fallback={<Empty />}>
          <ul data-slot="rank-list" data-scrollable>
            <For each={props.assets}>
              {(group) => (
                <li>
                  <Glyph name="cloud" class="sf-icon" />
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

function count(value: number | undefined, more: boolean) {
  if (value === undefined) return "–"
  return `${value.toLocaleString()}${more ? "+" : ""}`
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
