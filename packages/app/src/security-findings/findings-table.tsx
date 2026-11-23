import { createMemo, For, Match, Show, Switch } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { showToast } from "@/shell/notifications/toast"
import {
  MiddleTruncate,
  ProviderGlyph,
  ResourceGlyph,
  RiskChip,
  SeverityPill,
  StatusPill,
  resourceTypeLabelKey,
} from "./badges"
import { copyText, downloadJson } from "./clipboard"
import { Dropdown } from "./dropdown"
import { Glyph } from "./glyph"
import { PAGE_SIZES, type Finding, type SortKey, type SortState } from "./model"

type ColumnId =
  | "finding"
  | "resource"
  | "component"
  | "status"
  | "severity"
  | "related"
  | "fix"
  | "detection"
  | "subscription"

const COLUMNS: readonly { id: ColumnId; sort: SortKey; width: number }[] = [
  { id: "finding", sort: "cve", width: 176 },
  { id: "resource", sort: "resource", width: 260 },
  { id: "component", sort: "component", width: 200 },
  { id: "status", sort: "status", width: 108 },
  { id: "severity", sort: "severity", width: 100 },
  { id: "related", sort: "related", width: 140 },
  { id: "fix", sort: "fix", width: 180 },
  { id: "detection", sort: "detection", width: 120 },
  { id: "subscription", sort: "subscription", width: 200 },
]
const ACTIONS_WIDTH = 64
const SKELETON_ROWS = 10

/** The findings table: sticky header, sortable columns, column visibility, row menu and pagination. */
export function FindingsTable(props: {
  rows: readonly Finding[]
  loading: boolean
  sort: SortState
  page: number
  pageSize: number
  onSort: (sort: SortState) => void
  onPage: (page: number) => void
  onPageSize: (size: number) => void
  onOpen: (finding: Finding, row: HTMLElement) => void
  onIgnore: (finding: Finding) => void
  onClear: () => void
}) {
  const language = useLanguage()
  const [hidden, setHidden] = createStore<Partial<Record<ColumnId, boolean>>>({})
  const columns = createMemo(() => COLUMNS.filter((column) => !hidden[column.id]))
  const pages = createMemo(() => Math.max(1, Math.ceil(props.rows.length / props.pageSize)))
  const page = createMemo(() => Math.min(props.page, pages()))
  const visible = createMemo(() => props.rows.slice((page() - 1) * props.pageSize, page() * props.pageSize))

  const cycle = (key: SortKey) => {
    const current = props.sort?.key === key ? props.sort.dir : undefined
    props.onSort(current === undefined ? { key, dir: "asc" } : current === "asc" ? { key, dir: "desc" } : undefined)
  }
  const ariaSort = (key: SortKey) =>
    props.sort?.key !== key ? "none" : props.sort.dir === "asc" ? "ascending" : "descending"

  const copy = (finding: Finding) =>
    copyText(finding.cve).then(() =>
      showToast({ title: language.t("security.findings.toast.copied", { value: finding.cve }) }),
    )

  return (
    <div data-slot="table-card">
      <div data-slot="table-scroll" data-scrollable tabindex="-1">
        <table aria-busy={props.loading} aria-label={language.t("security.findings.table.label")}>
          <colgroup>
            <For each={columns()}>{(column) => <col style={{ width: `${column.width}px` }} />}</For>
            <col style={{ width: `${ACTIONS_WIDTH}px` }} />
          </colgroup>
          <thead>
            <tr>
              <For each={columns()}>
                {(column) => (
                  <th scope="col" aria-sort={ariaSort(column.sort)}>
                    <button type="button" onClick={() => cycle(column.sort)}>
                      {language.t(`security.findings.column.${column.id}`)}
                      <Show when={props.sort?.key === column.sort}>
                        <Glyph name={props.sort?.dir === "asc" ? "arrow-up" : "arrow-down"} size={12} />
                      </Show>
                    </button>
                  </th>
                )}
              </For>
              <th scope="col" data-slot="actions">
                <Dropdown
                  label={language.t("security.findings.table.columns")}
                  triggerClass="sf-icon-button"
                  align="end"
                  trigger={<Glyph name="gear" />}
                  items={COLUMNS.filter((column) => column.id !== "finding").map((column) => ({
                    id: column.id,
                    label: language.t(`security.findings.column.${column.id}`),
                    checked: !hidden[column.id],
                    onSelect: () => setHidden(column.id, !hidden[column.id]),
                  }))}
                />
              </th>
            </tr>
          </thead>
          <tbody>
            <Show
              when={!props.loading}
              fallback={
                <For each={Array.from({ length: SKELETON_ROWS })}>
                  {() => (
                    <tr data-slot="skeleton">
                      <For each={columns()}>
                        {() => (
                          <td>
                            <span data-slot="skeleton-bar" />
                          </td>
                        )}
                      </For>
                      <td />
                    </tr>
                  )}
                </For>
              }
            >
              <For each={visible()}>
                {(finding) => {
                  let row!: HTMLTableRowElement
                  return (
                    <tr
                      ref={row}
                      tabindex="0"
                      aria-label={language.t("security.findings.row.open", { cve: finding.cve })}
                      onClick={(event) => {
                        if ((event.target as Element).closest("[data-slot=actions], [role=menu]")) return
                        props.onOpen(finding, event.currentTarget)
                      }}
                      onKeyDown={(event) => {
                        if (event.target !== event.currentTarget) return
                        if (event.key !== "Enter" && event.key !== " ") return
                        event.preventDefault()
                        props.onOpen(finding, event.currentTarget)
                      }}
                    >
                      <For each={columns()}>{(column) => <td>{cell(column.id, finding)}</td>}</For>
                      <td data-slot="actions" onClick={(event) => event.stopPropagation()}>
                        <Dropdown
                          label={language.t("security.findings.row.actions", { cve: finding.cve })}
                          triggerClass="sf-icon-button"
                          align="end"
                          trigger={<Glyph name="kebab" />}
                          items={[
                            {
                              id: "details",
                              label: language.t("security.findings.action.view"),
                              onSelect: () => props.onOpen(finding, row),
                            },
                            {
                              id: "ignore",
                              label: language.t("security.findings.action.ignore"),
                              onSelect: () => props.onIgnore(finding),
                            },
                            {
                              id: "copy",
                              label: language.t("security.findings.action.copyCve"),
                              onSelect: () => void copy(finding),
                            },
                            {
                              id: "export",
                              label: language.t("security.findings.action.exportRow"),
                              onSelect: () => {
                                downloadJson(`${finding.cve}.json`, { ...finding, searchText: undefined })
                                showToast({
                                  title: language.t("security.findings.toast.exported", { value: finding.cve }),
                                })
                              },
                            },
                          ]}
                        />
                      </td>
                    </tr>
                  )
                }}
              </For>
            </Show>
          </tbody>
        </table>
        <Show when={!props.loading && props.rows.length === 0}>
          <div data-slot="empty" role="status">
            <Glyph name="empty" size={32} />
            <p>{language.t("security.findings.empty.title")}</p>
            <button type="button" class="sf-button" data-variant="outline" onClick={() => props.onClear()}>
              {language.t("security.findings.empty.clear")}
            </button>
          </div>
        </Show>
      </div>
      <div data-slot="pagination">
        <label>
          {language.t("security.findings.page.perPage")}
          <select value={props.pageSize} onChange={(event) => props.onPageSize(Number(event.currentTarget.value))}>
            <For each={PAGE_SIZES}>{(size) => <option value={size}>{size}</option>}</For>
          </select>
        </label>
        <span aria-live="polite">
          {props.rows.length === 0
            ? language.t("security.findings.page.none")
            : language.t("security.findings.page.range", {
                from: ((page() - 1) * props.pageSize + 1).toLocaleString(),
                to: Math.min(page() * props.pageSize, props.rows.length).toLocaleString(),
                total: props.rows.length.toLocaleString(),
              })}
        </span>
        <button
          type="button"
          data-slot="icon-button"
          aria-label={language.t("security.findings.page.previous")}
          disabled={page() <= 1}
          onClick={() => props.onPage(page() - 1)}
        >
          <Glyph name="chevron" class="sf-rotate-left" />
        </button>
        <button
          type="button"
          data-slot="icon-button"
          aria-label={language.t("security.findings.page.next")}
          disabled={page() >= pages()}
          onClick={() => props.onPage(page() + 1)}
        >
          <Glyph name="chevron" class="sf-rotate-right" />
        </button>
      </div>
    </div>
  )

  function cell(id: ColumnId, finding: Finding) {
    return (
      <Switch>
        <Match when={id === "finding"}>
          <span data-slot="finding">
            <span data-slot="gutter">
              <Show when={finding.fixVersion}>
                <Glyph name="check" size={12} class="sf-fix" />
                <span class="sr-only">{language.t("security.findings.fixAvailable")}</span>
              </Show>
            </span>
            <Glyph name="bug" class="sf-icon" />
            <span data-slot="strong">{finding.cve}</span>
          </span>
        </Match>
        <Match when={id === "resource"}>
          <span data-slot="two-line">
            <span data-slot="line">
              <ResourceGlyph type={finding.resource.type} />
              <MiddleTruncate text={finding.resource.name} />
            </span>
            <span data-slot="sub">{language.t(resourceTypeLabelKey(finding.resource.type))}</span>
          </span>
        </Match>
        <Match when={id === "component"}>
          <span data-slot="two-line">
            <span data-slot="line">
              <Glyph name="package" class="sf-icon" />
              <span data-slot="truncate" title={`${finding.component.name} ${finding.component.version}`}>
                {finding.component.name}
              </span>
            </span>
            <span data-slot="sub">{finding.component.kind}</span>
          </span>
        </Match>
        <Match when={id === "status"}>
          <StatusPill />
        </Match>
        <Match when={id === "severity"}>
          <SeverityPill severity={finding.severity} />
        </Match>
        <Match when={id === "related"}>
          <span data-slot="chips">
            <RiskChip severity="critical" count={finding.related.critical} />
            <RiskChip
              severity={finding.related.high > 0 ? "high" : "medium"}
              count={finding.related.high > 0 ? finding.related.high : finding.related.medium}
            />
          </span>
        </Match>
        <Match when={id === "fix"}>
          <span data-slot="truncate" title={finding.fixVersion}>
            {finding.fixVersion ?? "—"}
          </span>
        </Match>
        <Match when={id === "detection"}>
          {language.t(`security.findings.detection.${finding.component.dependency}`)}
        </Match>
        <Match when={id === "subscription"}>
          <span data-slot="two-line">
            <span data-slot="line">
              <ProviderGlyph provider={finding.resource.subscription.provider} />
              <span data-slot="truncate">{finding.resource.subscription.name}</span>
            </span>
            <span data-slot="sub" title={finding.resource.subscription.id}>
              {finding.resource.subscription.id}
            </span>
          </span>
        </Match>
      </Switch>
    )
  }
}
