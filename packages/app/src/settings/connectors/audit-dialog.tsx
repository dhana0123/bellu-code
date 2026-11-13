import { Button } from "@bellucode/ui/button"
import { useDialog } from "@bellucode/ui/context/dialog"
import { Dialog, DialogBody, DialogTitleGroup } from "@bellucode/ui/dialog"
import { Loader } from "@bellucode/ui/loader"
import { MenuScroll } from "@bellucode/ui/menu-scroll"
import type { Connectors } from "@bellucode/schema/connectors"
import { createMemo, For, Show } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { createConnectorsData } from "./data"
import { failureMessage } from "./errors"

/** Opens the audit dialog for one Connection through the shared dialog host. */
export function useConnectorAuditDialog() {
  const dialog = useDialog()
  return (input: { connectionId: string; alias: string; onClose?: () => void }) => {
    void dialog.show(
      () => <ConnectorAuditDialog connectionId={input.connectionId} alias={input.alias} onClose={input.onClose} />,
      input.onClose,
    )
  }
}

/**
 * Audit log of one Connection, newest first, 50 entries per page. Every value is server text and renders as plain text
 * (never markup); detail keys are listed with their values as text nodes.
 */
export function ConnectorAuditDialog(props: { connectionId: string; alias: string; onClose?: () => void }) {
  const language = useLanguage()
  const audit = createConnectorsData().createAudit(() => props.connectionId)
  const format = createMemo(
    () => new Intl.DateTimeFormat(language.locale(), { dateStyle: "medium", timeStyle: "medium" }),
  )
  const time = (ts: string) => {
    const date = new Date(ts)
    return Number.isNaN(date.getTime()) ? ts : format().format(date)
  }
  const outcome = (value: Connectors.AuditEntry["outcome"]) =>
    language.t(`settings.connectors.audit.outcome.${value}` as const)
  const details = (entry: Connectors.AuditEntry) => Object.entries(entry.detail ?? {})
  const failed = () => {
    const failure = audit.failure()
    return failure ? failureMessage(failure) : undefined
  }
  const initial = () => audit.busy() && audit.items().length === 0

  return (
    <Dialog class="command-palette command-palette-compact" size="large">
      <DialogTitleGroup title={language.t("settings.connectors.audit.title", { alias: props.alias })} />
      <DialogBody>
        <Show when={failed()}>
          {(message) => (
            <div role="alert" class="flex items-center gap-2 px-4 py-2 text-14-regular text-text-critical-base">
              <span class="min-w-0 flex-1">{language.t(message().key, message().params)}</span>
              <Button variant="neutral" size="normal" onClick={() => audit.loadMore()}>
                {language.t("settings.connectors.action.retry")}
              </Button>
            </div>
          )}
        </Show>
        <Show when={initial()}>
          <div role="status" class="flex items-center gap-2 px-4 py-6 text-14-regular text-text-weak">
            <Loader />
            <span>{language.t("settings.connectors.audit.loading")}</span>
          </div>
        </Show>
        <Show when={!audit.busy() && !failed() && audit.items().length === 0}>
          <p class="px-4 py-6 text-14-regular text-text-weak">{language.t("settings.connectors.audit.empty")}</p>
        </Show>
        <Show when={audit.items().length > 0}>
          <MenuScroll class="max-h-[60vh] min-h-0" viewportClass="px-2 pb-2">
            <ul aria-label={language.t("settings.connectors.audit.list")} class="m-0 list-none p-0">
              <For each={audit.items()}>
                {(entry) => (
                  <li class="border-b border-border-weak-base px-2 py-2 text-13-regular">
                    <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <time class="text-text-weak" dateTime={entry.ts}>
                        <span class="sr-only">{language.t("settings.connectors.audit.timestamp")}: </span>
                        {time(entry.ts)}
                      </time>
                      <span class="min-w-0 break-words font-medium">
                        <span class="sr-only">{language.t("settings.connectors.audit.event")}: </span>
                        {entry.event}
                      </span>
                      <span data-outcome={entry.outcome}>
                        <span class="sr-only">{language.t("settings.connectors.audit.outcome")}: </span>
                        {outcome(entry.outcome)}
                      </span>
                      <span class="min-w-0 break-words text-text-weak">
                        <span class="sr-only">{language.t("settings.connectors.audit.actor")}: </span>
                        {entry.actor}
                      </span>
                    </div>
                    <Show when={details(entry).length > 0}>
                      <dl
                        aria-label={language.t("settings.connectors.audit.detail")}
                        class="m-0 mt-1 grid grid-cols-[auto_1fr] gap-x-3 text-text-weak"
                      >
                        <For each={details(entry)}>
                          {([key, value]) => (
                            <>
                              <dt class="break-all">{key}</dt>
                              <dd class="m-0 break-all">{value}</dd>
                            </>
                          )}
                        </For>
                      </dl>
                    </Show>
                  </li>
                )}
              </For>
            </ul>
            <Show when={audit.hasMore() && !failed()}>
              <div class="flex justify-center py-2">
                <Button variant="neutral" size="normal" disabled={audit.busy()} onClick={() => audit.loadMore()}>
                  <Show when={audit.busy()}>
                    <Loader />
                  </Show>
                  {language.t("settings.connectors.action.loadMore")}
                </Button>
              </div>
            </Show>
          </MenuScroll>
        </Show>
      </DialogBody>
    </Dialog>
  )
}
