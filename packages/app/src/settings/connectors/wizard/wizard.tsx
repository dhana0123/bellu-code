import { Button } from "@bellucode/ui/button"
import { Icon } from "@bellucode/ui/icon"
import { TextField } from "@bellucode/ui/text-field"
import { For, Match, Show, Switch, createUniqueId, onCleanup, type Component, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { useLanguage } from "@/runtime/i18n/language"
import { DevicePrompt, type DevicePromptProps } from "../device-prompt"
import type { CopyBlock, PasteField, SourceDescriptor, StepGuide, WizardStepId } from "./descriptor"
import { selectCanGoBack, selectWizardStep, type WizardState } from "./machine"
import "../connectors.css"
import "./wizard.css"

const COPIED_MS = 2_000

type Key = Parameters<ReturnType<typeof useLanguage>["t"]>[0]

export type WizardProps = {
  descriptor: SourceDescriptor
  state: WizardState
  /** A request (verify, save, sign-in start) is in flight. Disables the actions and Back. */
  busy?: boolean
  /** Method ids the user cannot pick now, such as a sign-in method without a client ID. */
  unavailableMethodIds?: ReadonlySet<string>
  /** Current paste field values, keyed by `PasteField.id`. */
  values: Readonly<Record<string, string>>
  onValue: (fieldId: string, value: string) => void
  onSelectMethod: (methodId: string) => void
  onContinue: () => void
  /** Runs the step's check: verifies pasted credentials or saves the scope. */
  onVerify: () => void
  onBack: () => void
  /** Shown on `choose` while a sign-in authorization is running. */
  devicePrompt?: DevicePromptProps
  /** The source-specific scope picker for the `scope` step. */
  scope?: JSX.Element
  /** Disables Verify on `paste` or `scope` until the input is complete. */
  verifyDisabled?: boolean
  /** Set once the connection exists. Shows the Connected screen. */
  connection?: { readonly accountLabel?: string }
  onDone: () => void
}

/**
 * The shared connection Wizard. It renders the step in `state` and reports user intent through callbacks; the driver
 * owns the machine, the requests and the sign-in flow. It holds no source-specific text: descriptors carry i18n keys.
 */
export const Wizard: Component<WizardProps> = (props) => {
  const language = useLanguage()
  const t = (key: string, params?: Record<string, string>) => language.t(key as Key, params)
  const name = createUniqueId()
  const view = () => selectWizardStep(props.descriptor, props.state)
  const method = () => props.descriptor.methods.find((item) => item.id === props.state.methodId)
  const unavailable = (id: string) => props.unavailableMethodIds?.has(id) ?? false
  const noSignIn = () =>
    !props.descriptor.methods.some((item) => item.kind === "signin" && !unavailable(item.id))
  const guide = (): StepGuide | undefined => {
    const step = props.state.step
    if (step === "choose") return props.descriptor.choose
    if (step === "done") return undefined
    return method()?.guides[step]
  }
  const stepKey = (step: WizardStepId) => `settings.connectors.wizard.step.${step}`
  const current = () => (props.connection ? view().steps.length : view().index)

  return (
    <div class="connector-wizard" data-component="connector-wizard">
      <ol data-slot="github-wizard-steps" aria-label={t("settings.connectors.wizard.label")}>
        <For each={view().steps}>
          {(step, index) => {
            const status = () => (index() < current() || step === "done" && props.connection ? "done" : index() === current() ? "active" : "todo")
            return (
              <li data-slot="github-wizard-step" data-status={status()} aria-current={status() === "active" ? "step" : undefined}>
                <span data-slot="github-wizard-circle" aria-hidden="true">
                  <Show when={status() === "done"} fallback={index() + 1}>
                    <Icon name="check" size="small" />
                  </Show>
                </span>
                <span data-slot="github-wizard-step-label">{t(stepKey(step))}</span>
              </li>
            )
          }}
        </For>
      </ol>
      <Switch>
        <Match when={props.connection} keyed>
          {(connection) => (
            <div class="flex flex-col gap-3" data-slot="connect-page-connected" role="status">
              <div class="flex items-center gap-2">
                <Icon name="circle-check" class="size-5 text-[color:var(--v2-state-fg-success)]" aria-hidden="true" />
                <h4 class="m-0 text-14-medium text-v2-text-text-base">{t("settings.connectors.wizard.connected.title")}</h4>
              </div>
              <Show when={connection.accountLabel}>
                {(account) => (
                  <p class="m-0 text-13-regular text-v2-text-text-base">
                    {t("settings.connectors.wizard.connected.account", { account: account() })}
                  </p>
                )}
              </Show>
              <div class="connector-wizard-actions">
                <Button type="button" variant="submit" onClick={props.onDone}>
                  {t("settings.connectors.wizard.connected.done")}
                </Button>
              </div>
            </div>
          )}
        </Match>
        <Match when={true}>
          <section class="connector-wizard-section">
            <Show when={guide()}>
              {(item) => (
                <p class="connector-wizard-note">
                  {t(item().instructionKey)}{" "}
                  <a href={item().docsUrl} target="_blank" rel="noopener noreferrer" class="connector-wizard-link">
                    {t("settings.connectors.wizard.docs")}
                  </a>
                </p>
              )}
            </Show>
            <Switch>
              <Match when={props.state.step === "choose"}>
                <Show when={noSignIn()}>
                  <p class="connector-wizard-note" data-slot="connector-wizard-signin-unavailable">
                    {t("settings.connectors.wizard.signinUnavailable")}
                  </p>
                </Show>
                <Show
                  when={props.state.authorizing && props.devicePrompt}
                  fallback={
                    <fieldset data-slot="github-wizard-options">
                      <legend class="sr-only">{t("settings.connectors.wizard.step.choose")}</legend>
                      <For each={props.descriptor.methods}>
                        {(item, index) => (
                          <label data-slot="github-wizard-option" data-disabled={unavailable(item.id) ? "" : undefined}>
                            <input
                              type="radio"
                              name={name}
                              value={item.id}
                              checked={props.state.methodId === item.id}
                              disabled={unavailable(item.id) || props.busy || props.state.authorizing}
                              onChange={() => props.onSelectMethod(item.id)}
                            />
                            <span data-slot="github-wizard-option-body">
                              <span data-slot="github-wizard-option-title">
                                {t(item.titleKey)}
                                <Show when={index() === 0 && !unavailable(item.id)}>
                                  <span data-slot="github-wizard-recommended">
                                    {t("settings.connectors.wizard.recommended")}
                                  </span>
                                </Show>
                              </span>
                              <span data-slot="github-wizard-option-text">{t(item.descriptionKey)}</span>
                            </span>
                          </label>
                        )}
                      </For>
                    </fieldset>
                  }
                >
                  {(_) => <DevicePrompt {...props.devicePrompt!} />}
                </Show>
              </Match>
              <Match when={props.state.step === "create"}>
                <For each={method()?.copyBlocks ?? []}>{(block) => <CodeBlock block={block} t={t} />}</For>
              </Match>
              <Match when={props.state.step === "paste"}>
                <For each={method()?.fields ?? []}>
                  {(field) => <Field field={field} value={props.values[field.id] ?? ""} onValue={props.onValue} t={t} />}
                </For>
              </Match>
              <Match when={props.state.step === "scope"}>{props.scope}</Match>
            </Switch>
            <Show when={props.state.failure}>
              {(reason) => (
                <p class="connector-wizard-failure" role="alert">
                  {t("settings.connectors.wizard.failure", { reason: reason() })}
                </p>
              )}
            </Show>
          </section>
          <div class="connector-wizard-actions">
            <Show when={selectCanGoBack(props.state, props.busy ?? false)}>
              <Button type="button" variant="ghost" onClick={props.onBack}>
                {t("settings.connectors.wizard.back")}
              </Button>
            </Show>
            <Switch>
              <Match when={props.state.step === "paste" || props.state.step === "scope"}>
                <Button
                  type="button"
                  variant="submit"
                  disabled={props.busy || props.verifyDisabled}
                  onClick={props.onVerify}
                >
                  {props.busy
                    ? t("settings.connectors.wizard.verifying")
                    : t(props.state.step === "paste" ? "settings.connectors.wizard.verify" : "settings.connectors.wizard.save")}
                </Button>
              </Match>
              <Match when={!props.state.authorizing}>
                <Button
                  type="button"
                  variant="submit"
                  disabled={props.busy || unavailable(props.state.methodId)}
                  onClick={props.onContinue}
                >
                  {t("settings.connectors.wizard.continue")}
                </Button>
              </Match>
            </Switch>
          </div>
        </Match>
      </Switch>
    </div>
  )
}

const Field: Component<{
  field: PasteField
  value: string
  onValue: (id: string, value: string) => void
  t: (key: string) => string
}> = (props) => (
  <TextField
    label={props.t(props.field.labelKey)}
    value={props.value}
    type={props.field.secret ? "password" : "text"}
    multiline={props.field.multiline}
    onChange={(value: string) => props.onValue(props.field.id, value)}
    autocomplete="off"
    spellcheck={false}
    required
  />
)

/** A scrollable code block with a Copy button. Falls back to a hint when the clipboard is unavailable (plain HTTP). */
const CodeBlock: Component<{ block: CopyBlock; t: (key: string) => string }> = (props) => {
  const [state, setState] = createStore<{ copy: "idle" | "copied" | "failed" }>({ copy: "idle" })
  let reset: ReturnType<typeof setTimeout> | undefined
  onCleanup(() => clearTimeout(reset))
  const copy = async () => {
    clearTimeout(reset)
    const board = typeof navigator === "undefined" ? undefined : navigator.clipboard
    const written = board
      ? await Promise.try(() => board.writeText(props.block.content)).then(() => true, () => false)
      : false
    setState("copy", written ? "copied" : "failed")
    reset = setTimeout(() => setState("copy", "idle"), COPIED_MS)
  }
  return (
    <div class="connector-wizard-code">
      <span class="connector-wizard-code-label">{props.t(props.block.labelKey)}</span>
      <pre tabIndex={0} data-scrollable>
        <code>{props.block.content}</code>
      </pre>
      <div class="flex items-center gap-2">
        <Button type="button" size="small" variant="outline" onClick={() => void copy()}>
          {props.t("settings.connectors.action.copy")}
        </Button>
        <Show when={state.copy !== "idle"}>
          <span class="connector-wizard-note" role="status">
            {props.t(state.copy === "copied" ? "settings.connectors.wizard.copied" : "settings.connectors.wizard.copyFailed")}
          </span>
        </Show>
      </div>
    </div>
  )
}
