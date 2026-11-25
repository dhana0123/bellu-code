import { createEffect, For, on, onCleanup, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Portal } from "solid-js/web"
import { useLanguage } from "@/runtime/i18n/language"
import { MiddleTruncate, SeverityPill, StatusPill, categoryLabelKey, statusLabelKey, typeLabelKey } from "./badges"
import type { DrawerState, StatusRequest } from "./drawer-machine"
import { Glyph } from "./glyph"
import { SNOOZE_STATUSES, STATUSES, type Finding, type Status, type StatusEvent } from "./model"
import { formatTime } from "./time"

const FOCUSABLE = "button:not([disabled]), input, select, textarea"

const snoozes = (status: Status) => SNOOZE_STATUSES.some((item) => item === status)

/**
 * Right-side details for one finding. It is not a route. Esc or the close button dismisses it and the page returns
 * focus to the row that opened it. The status form changes the status on the server. A 400 names the field it
 * refused and the message shows under that field.
 */
export function DetailDrawer(props: {
  finding: Finding | undefined
  state: DrawerState
  onClose: () => void
  onSave: (request: StatusRequest) => void
  onCopyLink: (finding: Finding) => void
}) {
  const language = useLanguage()
  const [form, setForm] = createStore<{ status: Status; reason: string; until: string }>({
    status: "open",
    reason: "",
    until: "",
  })
  let close: HTMLButtonElement | undefined
  let drawer: HTMLElement | undefined
  let reason: HTMLTextAreaElement | undefined

  // Each open starts the form from the finding, or from the status the row menu asked for.
  createEffect(
    on(
      () => (props.state.type === "open" ? props.state.attempt : undefined),
      (attempt) => {
        if (attempt === undefined || !props.finding) return
        setForm({
          status: props.state.type === "open" && props.state.intent ? props.state.intent : props.finding.status,
          reason: "",
          until: "",
        })
      },
    ),
  )
  // A saved change clears the reason and expiry, and the form follows the finding's new status.
  createEffect(
    on(
      () => (props.state.type === "open" ? props.state.save.type : undefined),
      (type, previous) => {
        if (previous === "saving" && type === "idle" && props.finding)
          setForm({ status: props.finding.status, reason: "", until: "" })
      },
    ),
  )

  createEffect(() => {
    if (!props.finding) return
    queueMicrotask(() => close?.focus({ preventScroll: true }))
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Tab" && drawer) {
        // The drawer is modal, so Tab cycles inside it.
        const items = [...drawer.querySelectorAll<HTMLElement>(FOCUSABLE)]
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

  const saving = () => props.state.type === "open" && props.state.save.type === "saving"
  const rejected = () =>
    props.state.type === "open" && props.state.save.type === "rejected" ? props.state.save : undefined
  // A refusal shows under the field it names. One that names no field of this form shows above the form.
  const fieldError = (field: "status" | "reason" | "until") =>
    rejected()?.field === field ? rejected()?.message || language.t("security.findings.status.error") : undefined
  const formError = () => {
    const value = rejected()
    if (!value) return undefined
    if (value.field === "status" || value.field === "reason" || value.field === "until") return undefined
    return value.message || language.t("security.findings.status.error")
  }

  const submit = (event: SubmitEvent) => {
    event.preventDefault()
    props.onSave({
      status: form.status,
      ...(snoozes(form.status)
        ? {
            reason: form.reason,
            // The date input has no time, so the expiry is the end of that day in the reader's time zone.
            until: form.until ? new Date(`${form.until}T23:59:59`).toISOString() : undefined,
          }
        : {}),
    })
  }

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
              aria-label={language.t("security.findings.drawer.label", { title: finding().title })}
            >
              <header>
                <h2>{finding().title}</h2>
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
                    <StatusPill status={finding().status} />
                  </dd>
                  <dt>{language.t("security.findings.column.risk")}</dt>
                  <dd>{finding().riskScore === undefined ? "—" : Math.round(finding().riskScore!)}</dd>
                  <dt>{language.t("security.findings.column.asset")}</dt>
                  <dd>
                    <span data-slot="line">
                      <Glyph name="cloud" class="sf-icon" />
                      <span data-slot="wrap">{finding().assetId}</span>
                    </span>
                  </dd>
                  <dt>{language.t("security.findings.column.type")}</dt>
                  <dd>
                    {language.t(typeLabelKey(finding().type))}
                    <span data-slot="sub">{language.t(categoryLabelKey(finding().category))}</span>
                  </dd>
                  <dt>{language.t("security.findings.drawer.rule")}</dt>
                  <dd>{finding().ruleId}</dd>
                  <dt>{language.t("security.findings.column.source")}</dt>
                  <dd>{finding().source}</dd>
                  <dt>{language.t("security.findings.column.firstSeen")}</dt>
                  <dd>{formatTime(finding().firstSeen)}</dd>
                  <dt>{language.t("security.findings.column.lastSeen")}</dt>
                  <dd>{formatTime(finding().lastSeen)}</dd>
                  <dt>{language.t("security.findings.drawer.occurrences")}</dt>
                  <dd>{finding().occurrences.toLocaleString()}</dd>
                </dl>

                <h3>{language.t("security.findings.drawer.change")}</h3>
                <form data-slot="status-form" onSubmit={submit} novalidate>
                  <Show when={formError()}>
                    {(message) => (
                      <p data-slot="field-error" role="alert">
                        {message()}
                      </p>
                    )}
                  </Show>
                  <label>
                    {language.t("security.findings.column.status")}
                    <select
                      value={form.status}
                      aria-invalid={fieldError("status") !== undefined}
                      aria-describedby={fieldError("status") ? "sf-status-error" : undefined}
                      onChange={(event) => setForm("status", STATUSES.find((item) => item === event.currentTarget.value) ?? form.status)}
                    >
                      <For each={STATUSES}>
                        {(status) => (
                          <option value={status} selected={status === form.status}>
                            {language.t(statusLabelKey(status))}
                          </option>
                        )}
                      </For>
                    </select>
                  </label>
                  <Show when={fieldError("status")}>
                    {(message) => (
                      <p id="sf-status-error" data-slot="field-error" role="alert">
                        {message()}
                      </p>
                    )}
                  </Show>
                  <Show when={snoozes(form.status)}>
                    <label>
                      {language.t("security.findings.status.reason")}
                      <textarea
                        ref={reason}
                        rows={3}
                        maxLength={1024}
                        value={form.reason}
                        aria-invalid={fieldError("reason") !== undefined}
                        aria-describedby={fieldError("reason") ? "sf-reason-error" : undefined}
                        onInput={(event) => setForm("reason", event.currentTarget.value)}
                      />
                    </label>
                    <Show when={fieldError("reason")}>
                      {(message) => (
                        <p id="sf-reason-error" data-slot="field-error" role="alert">
                          {message()}
                        </p>
                      )}
                    </Show>
                    <label>
                      {language.t("security.findings.status.until")}
                      <input
                        type="date"
                        value={form.until}
                        aria-invalid={fieldError("until") !== undefined}
                        aria-describedby={fieldError("until") ? "sf-until-error" : undefined}
                        onInput={(event) => setForm("until", event.currentTarget.value)}
                      />
                    </label>
                    <Show when={fieldError("until")}>
                      {(message) => (
                        <p id="sf-until-error" data-slot="field-error" role="alert">
                          {message()}
                        </p>
                      )}
                    </Show>
                  </Show>
                  <button type="submit" class="sf-button" data-variant="primary" disabled={saving()}>
                    {saving()
                      ? language.t("security.findings.status.saving")
                      : language.t("security.findings.status.apply")}
                  </button>
                </form>

                <h3>{language.t("security.findings.drawer.evidence")}</h3>
                <Show
                  when={finding().evidence.length > 0}
                  fallback={<p data-slot="sub">{language.t("security.findings.drawer.noEvidence")}</p>}
                >
                  <ul data-slot="related">
                    <For each={finding().evidence}>
                      {(item) => (
                        <li>
                          <span data-slot="sub">{item.kind}</span>
                          <MiddleTruncate text={item.line === undefined ? item.ref : `${item.ref}:${item.line}`} />
                          <Show when={item.excerpt}>
                            <code>{item.excerpt}</code>
                          </Show>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>

                <h3>{language.t("security.findings.drawer.history")}</h3>
                <Show when={props.state.type === "open" ? props.state.history : undefined}>
                  {(history) => (
                    <>
                      <Show when={history().type === "loading"}>
                        <p data-slot="sub" role="status">
                          {language.t("security.findings.drawer.historyLoading")}
                        </p>
                      </Show>
                      <Show when={history().type === "failed"}>
                        <p data-slot="sub" role="alert">
                          {language.t("security.findings.drawer.historyFailed")}
                        </p>
                      </Show>
                      <Show when={readyEvents(history())}>
                        {(events) => (
                          <Show
                            when={events().length > 0}
                            fallback={<p data-slot="sub">{language.t("security.findings.drawer.noHistory")}</p>}
                          >
                            <ul data-slot="related">
                              <For each={events()}>
                                {(event) => (
                                  <li>
                                    <span data-slot="sub">{formatTime(event.at)}</span>
                                    <span>
                                      {event.actor}:{" "}
                                      {event.prevStatus
                                        ? language.t("security.findings.drawer.transition", {
                                            from: language.t(statusLabelKey(event.prevStatus)),
                                            to: language.t(statusLabelKey(event.newStatus)),
                                          })
                                        : language.t(statusLabelKey(event.newStatus))}
                                    </span>
                                    <Show when={event.reason}>
                                      <span data-slot="sub">{event.reason}</span>
                                    </Show>
                                  </li>
                                )}
                              </For>
                            </ul>
                          </Show>
                        )}
                      </Show>
                    </>
                  )}
                </Show>
              </div>
              <footer>
                <button
                  type="button"
                  class="sf-button"
                  data-variant="outline"
                  onClick={() => {
                    setForm("status", "ignored")
                    queueMicrotask(() => reason?.focus())
                  }}
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

function readyEvents(history: { type: "loading" } | { type: "ready"; events: readonly StatusEvent[] } | { type: "failed" }) {
  return history.type === "ready" ? history.events : undefined
}
