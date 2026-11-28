import { createEffect, createMemo, createSignal, For, onCleanup, Show, untrack } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { useServerSDK } from "@/runtime/server/client"
import { failureReason, rejection } from "@/security-findings/query"
import { formatTime } from "@/security-findings/time"
import {
  idle,
  initial,
  selectBusy,
  selectCancelling,
  selectFailure,
  selectFirstLoad,
  selectJobs,
  selectMessage,
  selectPolling,
  selectSaved,
  selectScanners,
  transition,
  transitionAction,
  type Action,
  type ActionEvent,
  type ScansEvent,
} from "./machine"
import {
  intervalSeconds,
  isActive,
  KINDS,
  MAX_INTERVAL_SECONDS,
  MIN_INTERVAL_SECONDS,
  POLL_INTERVAL_MS,
  REQUEST_TIMEOUT_MS,
  scheduleId,
  TARGET_TYPES,
  UNITS,
  type Unit,
} from "./model"
import { CveSettingsPanel } from "./cve-panel"
import "./scanners.css"

/**
 * Scanners. The scanner table comes from `scans.scanners()` and the job table from `scans.list()`. Both reload every
 * 5 s while a job is queued or running. A scan runs from the form, a queued or running job can be cancelled, and a
 * schedule repeats a kind on a target type at an interval from 15 minutes to 30 days.
 */
export function SecurityScannersPage() {
  const language = useLanguage()
  const sdk = useServerSDK()
  const [machine, setMachine] = createSignal(initial)
  const [actions, setActions] = createSignal(idle)
  const [form, setForm] = createStore({
    kind: KINDS[0],
    targetType: TARGET_TYPES[0],
    targetId: "",
    scheduleKind: KINDS[0],
    scheduleTargetType: TARGET_TYPES[0],
    amount: "1",
    unit: "hours" as Unit,
    enabled: true,
  })
  const dispatch = (event: ScansEvent) => {
    const previous = untrack(machine)
    const next = transition(previous, event)
    if (next !== previous) setMachine(next)
  }
  const dispatchAction = (event: ActionEvent) => {
    const previous = untrack(actions)
    const next = transitionAction(previous, event)
    if (next !== previous) setActions(next)
  }
  onCleanup(() => {
    dispatch({ type: "disposed" })
    dispatchAction({ type: "disposed" })
  })

  // Driver: each load attempt starts one request pair, and a stale or disposed attempt aborts it.
  const load = createMemo(
    () => {
      const current = machine()
      return current.type === "loading" ? current.attempt : undefined
    },
    undefined,
  )
  createEffect(() => {
    const attempt = load()
    if (attempt === undefined) return
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
    onCleanup(() => {
      clearTimeout(timer)
      controller.abort()
    })
    const signal = controller.signal
    void Promise.all([
      sdk.api.experimental.scans.scanners({ signal }),
      sdk.api.experimental.scans.list({ limit: 200 }, { signal }),
    ]).then(
      ([scanners, jobs]) => dispatch({ type: "loaded", attempt, scanners: scanners.items, jobs: jobs.items }),
      (error: unknown) => dispatch({ type: "failed", attempt, reason: failureReason(error) }),
    )
  })

  // Driver: while a job is queued or running, a ready table reloads every 5 s.
  const polling = createMemo(() => machine().type === "ready" && selectPolling(machine()))
  createEffect(() => {
    if (!polling()) return
    const timer = setTimeout(() => dispatch({ type: "refresh" }), POLL_INTERVAL_MS)
    onCleanup(() => clearTimeout(timer))
  })

  // Driver: one action request at a time. A 400 or 409 comes back as an inline message.
  const running = createMemo(
    () => {
      const current = actions()
      return current.type === "busy" ? current : undefined
    },
    undefined,
    { equals: (a, b) => a?.attempt === b?.attempt },
  )
  createEffect(() => {
    const current = running()
    if (!current) return
    const action = current.action
    const call = () => {
      const api = sdk.api.experimental.scans
      if (action.name === "enqueue") return api.enqueue({ kind: form.kind, targetType: form.targetType, targetId: action.targetId })
      if (action.name === "cancel") return api.cancel({ id: action.id })
      return api.schedule({
        id: scheduleId(form.scheduleKind, form.scheduleTargetType),
        kind: form.scheduleKind,
        targetType: form.scheduleTargetType,
        intervalSeconds: action.intervalSeconds,
        enabled: action.enabled,
      })
    }
    void call().then(
      () => {
        dispatchAction({ type: "succeeded", attempt: current.attempt })
        if (action.name !== "schedule") dispatch({ type: "refresh" })
      },
      (error: unknown) =>
        dispatchAction({
          type: "rejected",
          attempt: current.attempt,
          message: rejection(error).message || language.t("security.scanners.error.action"),
        }),
    )
  })

  const submit = (action: Action) => dispatchAction({ type: "submit", action })
  const seconds = () => intervalSeconds(form.amount, form.unit)
  const targetId = () => form.targetId.trim()
  const rows = () => selectJobs(machine())

  return (
    <div data-component="security-scanners">
      <div data-slot="page-header">
        <h1>{language.t("security.scanners.title")}</h1>
        <button
          type="button"
          class="ss-button"
          disabled={machine().type === "loading"}
          onClick={() => dispatch({ type: "refresh" })}
        >
          {language.t("security.scanners.refresh")}
        </button>
      </div>

      <Show when={selectFailure(machine())}>
        {(reason) => (
          <div data-slot="load-error" role="alert">
            <p>
              {reason() === "unavailable"
                ? language.t("security.scanners.error.unavailable")
                : language.t("security.scanners.error.failed")}
            </p>
            <button type="button" class="ss-button" onClick={() => dispatch({ type: "refresh" })}>
              {language.t("security.scanners.retry")}
            </button>
          </div>
        )}
      </Show>

      <CveSettingsPanel />
      <section data-slot="section" aria-labelledby="ss-run">
        <h2 id="ss-run">{language.t("security.scanners.run.title")}</h2>
        <form
          data-slot="form"
          onSubmit={(event) => {
            event.preventDefault()
            if (targetId() === "") return
            submit({ name: "enqueue", kind: form.kind, targetType: form.targetType, targetId: targetId() })
          }}
        >
          <label>
            <span>{language.t("security.scanners.field.kind")}</span>
            <select value={form.kind} onChange={(event) => setForm("kind", KINDS.find((item) => item === event.currentTarget.value) ?? KINDS[0])}>
              <For each={KINDS}>{(item) => <option value={item}>{language.t(`security.scanners.kind.${item}`)}</option>}</For>
            </select>
          </label>
          <label>
            <span>{language.t("security.scanners.field.targetType")}</span>
            <select
              value={form.targetType}
              onChange={(event) =>
                setForm("targetType", TARGET_TYPES.find((item) => item === event.currentTarget.value) ?? TARGET_TYPES[0])
              }
            >
              <For each={TARGET_TYPES}>
                {(item) => <option value={item}>{language.t(`security.scanners.target.${item}`)}</option>}
              </For>
            </select>
          </label>
          <label>
            <span>{language.t("security.scanners.field.targetId")}</span>
            <input value={form.targetId} onInput={(event) => setForm("targetId", event.currentTarget.value)} />
          </label>
          <button type="submit" class="ss-button" data-variant="primary" disabled={selectBusy(actions()) || targetId() === ""}>
            {language.t("security.scanners.run.submit")}
          </button>
        </form>
        <Show when={selectMessage(actions(), "enqueue")}>
          {(message) => (
            <p data-slot="inline-error" role="alert">
              {message()}
            </p>
          )}
        </Show>
      </section>

      <section data-slot="section" aria-labelledby="ss-schedule">
        <h2 id="ss-schedule">{language.t("security.scanners.schedule.title")}</h2>
        <form
          data-slot="form"
          onSubmit={(event) => {
            event.preventDefault()
            const value = seconds()
            if (value === undefined) return
            submit({
              name: "schedule",
              kind: form.scheduleKind,
              targetType: form.scheduleTargetType,
              intervalSeconds: value,
              enabled: form.enabled,
            })
          }}
        >
          <label>
            <span>{language.t("security.scanners.field.kind")}</span>
            <select
              value={form.scheduleKind}
              onChange={(event) => setForm("scheduleKind", KINDS.find((item) => item === event.currentTarget.value) ?? KINDS[0])}
            >
              <For each={KINDS}>{(item) => <option value={item}>{language.t(`security.scanners.kind.${item}`)}</option>}</For>
            </select>
          </label>
          <label>
            <span>{language.t("security.scanners.field.targetType")}</span>
            <select
              value={form.scheduleTargetType}
              onChange={(event) =>
                setForm("scheduleTargetType", TARGET_TYPES.find((item) => item === event.currentTarget.value) ?? TARGET_TYPES[0])
              }
            >
              <For each={TARGET_TYPES}>
                {(item) => <option value={item}>{language.t(`security.scanners.target.${item}`)}</option>}
              </For>
            </select>
          </label>
          <label>
            <span>{language.t("security.scanners.schedule.every")}</span>
            <input
              type="number"
              min="1"
              step="1"
              value={form.amount}
              aria-invalid={seconds() === undefined}
              onInput={(event) => setForm("amount", event.currentTarget.value)}
            />
          </label>
          <label>
            <span>{language.t("security.scanners.schedule.unit")}</span>
            <select
              value={form.unit}
              onChange={(event) => setForm("unit", (Object.keys(UNITS) as Unit[]).find((item) => item === event.currentTarget.value) ?? "hours")}
            >
              <For each={Object.keys(UNITS) as Unit[]}>
                {(item) => <option value={item}>{language.t(`security.scanners.unit.${item}`)}</option>}
              </For>
            </select>
          </label>
          <label data-slot="check">
            <input type="checkbox" checked={form.enabled} onChange={(event) => setForm("enabled", event.currentTarget.checked)} />
            <span>{language.t("security.scanners.schedule.enabled")}</span>
          </label>
          <button type="submit" class="ss-button" data-variant="primary" disabled={selectBusy(actions()) || seconds() === undefined}>
            {language.t("security.scanners.schedule.save")}
          </button>
        </form>
        <Show when={seconds() === undefined}>
          <p data-slot="hint">
            {language.t("security.scanners.schedule.range", {
              min: String(MIN_INTERVAL_SECONDS / 60),
              max: String(MAX_INTERVAL_SECONDS / 86400),
            })}
          </p>
        </Show>
        <Show when={selectMessage(actions(), "schedule")}>
          {(message) => (
            <p data-slot="inline-error" role="alert">
              {message()}
            </p>
          )}
        </Show>
        <Show when={selectSaved(actions(), "schedule")}>
          <p data-slot="hint" role="status">
            {language.t("security.scanners.schedule.saved")}
          </p>
        </Show>
      </section>

      <section data-slot="section" aria-labelledby="ss-scanners">
        <h2 id="ss-scanners">{language.t("security.scanners.table.title")}</h2>
        <table>
          <thead>
            <tr>
              <th>{language.t("security.scanners.col.name")}</th>
              <th>{language.t("security.scanners.col.kind")}</th>
              <th>{language.t("security.scanners.col.version")}</th>
              <th>{language.t("security.scanners.col.license")}</th>
              <th>{language.t("security.scanners.col.lastRun")}</th>
            </tr>
          </thead>
          <tbody>
            <For
              each={selectScanners(machine())}
              fallback={
                <tr>
                  <td colSpan={5} data-slot="empty">
                    {selectFirstLoad(machine())
                      ? language.t("security.scanners.loading")
                      : language.t("security.scanners.table.empty")}
                  </td>
                </tr>
              }
            >
              {(scanner) => (
                <tr>
                  <td>{scanner.name}</td>
                  <td>{language.t(`security.scanners.kind.${scanner.kind}`)}</td>
                  <td>{scanner.version}</td>
                  <td>{scanner.license}</td>
                  <td>
                    <Show when={scanner.lastRun} fallback={language.t("security.scanners.never")}>
                      {(run) => (
                        <>
                          <span data-status={run().status}>{language.t(`security.scanners.status.${run().status}`)}</span>{" "}
                          {formatTime(run().endedAt ?? run().startedAt ?? run().queuedAt)}
                        </>
                      )}
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </section>

      <section data-slot="section" aria-labelledby="ss-jobs">
        <h2 id="ss-jobs">{language.t("security.scanners.jobs.title")}</h2>
        <Show when={selectMessage(actions(), "cancel")}>
          {(message) => (
            <p data-slot="inline-error" role="alert">
              {message()}
            </p>
          )}
        </Show>
        <table>
          <thead>
            <tr>
              <th>{language.t("security.scanners.col.status")}</th>
              <th>{language.t("security.scanners.col.kind")}</th>
              <th>{language.t("security.scanners.col.target")}</th>
              <th>{language.t("security.scanners.col.start")}</th>
              <th>{language.t("security.scanners.col.end")}</th>
              <th>{language.t("security.scanners.col.counts")}</th>
              <th>{language.t("security.scanners.col.reason")}</th>
              <th>
                <span class="sr-only">{language.t("security.scanners.col.actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <For
              each={rows()}
              fallback={
                <tr>
                  <td colSpan={8} data-slot="empty">
                    {selectFirstLoad(machine())
                      ? language.t("security.scanners.loading")
                      : language.t("security.scanners.jobs.empty")}
                  </td>
                </tr>
              }
            >
              {(job) => (
                <tr>
                  <td>
                    <span data-status={job.status}>{language.t(`security.scanners.status.${job.status}`)}</span>
                  </td>
                  <td>{language.t(`security.scanners.kind.${job.kind}`)}</td>
                  <td>
                    {language.t(`security.scanners.target.${job.targetType}`)} <code>{job.targetId}</code>
                  </td>
                  <td>{job.startedAt ? formatTime(job.startedAt) : "–"}</td>
                  <td>{job.endedAt ? formatTime(job.endedAt) : "–"}</td>
                  <td>
                    {language.t("security.scanners.counts", {
                      created: String(job.created),
                      updated: String(job.updated),
                      resolved: String(job.resolved),
                    })}
                  </td>
                  <td>{job.reason ?? ""}</td>
                  <td>
                    <Show when={isActive(job)}>
                      <button
                        type="button"
                        class="ss-button"
                        disabled={selectBusy(actions())}
                        aria-busy={selectCancelling(actions(), job.id)}
                        onClick={() => submit({ name: "cancel", id: job.id })}
                      >
                        {language.t("security.scanners.cancel")}
                      </button>
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </section>
    </div>
  )
}
