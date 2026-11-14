/**
 * The shared Wizard's step machine. One pure `transitionWizard(descriptor, state, event)` covers every Source:
 *
 * - AWS IAM role: choose, create, paste (ARN), scope (regions), done
 * - AWS keys:     choose, paste (keys), scope, done
 * - GitHub:       choose, sign-in, scope (repositories), done
 * - GitHub PAT:   choose, paste, scope, done
 *
 * The machine owns only the step, the method and the last failure. Requests and the device prompt live in the driver
 * and the sign-in machine; the driver reports their outcome as `verified` or `failed`.
 */
import type { MethodStepId, SourceDescriptor, SourceMethod, WizardStepId } from "./descriptor"

export type WizardState = {
  readonly step: WizardStepId
  readonly methodId: string
  /** Sign-in only: the device authorization started from `choose` and has not finished. The step stays `choose`. */
  readonly authorizing: boolean
  /** The reason the last verification failed on this step, or undefined. */
  readonly failure?: string
}

export type WizardEvent =
  | { readonly type: "method.selected"; readonly methodId: string }
  | { readonly type: "continued" }
  | { readonly type: "back" }
  /** The step's check passed: credential accepted, sign-in finished, or the scope saved. */
  | { readonly type: "verified" }
  | { readonly type: "failed"; readonly reason: string }

export function initialWizardState(descriptor: SourceDescriptor): WizardState {
  return { step: "choose", methodId: descriptor.methods[0]?.id ?? "", authorizing: false }
}

/** The ordered steps of a method. Sign-in skips `create` and `paste`. */
export function wizardPath(method: SourceMethod | undefined): readonly WizardStepId[] {
  const steps = (method?.steps ?? []).filter((step: MethodStepId) => method?.kind !== "signin" || step === "scope")
  return ["choose", ...steps, "done"]
}

export function transitionWizard(descriptor: SourceDescriptor, state: WizardState, event: WizardEvent): WizardState {
  const method = descriptor.methods.find((item) => item.id === state.methodId)
  const path = wizardPath(method)
  const index = path.indexOf(state.step)
  switch (event.type) {
    case "method.selected":
      if (state.step !== "choose" || state.authorizing || state.methodId === event.methodId) return state
      if (!descriptor.methods.some((item) => item.id === event.methodId)) return state
      return { step: "choose", methodId: event.methodId, authorizing: false }
    case "continued": {
      if (state.step === "done" || index < 0) return state
      // Pasting and choosing scope finish through `verified`, so the user cannot skip the check.
      if (state.step === "paste" || state.step === "scope") return state
      if (state.step === "choose" && method?.kind === "signin") {
        if (state.authorizing) return state
        return { step: "choose", methodId: state.methodId, authorizing: true }
      }
      const next = path[index + 1]
      if (!next || next === "done") return state
      return { step: next, methodId: state.methodId, authorizing: false }
    }
    case "back": {
      if (state.step === "done") return state
      if (state.step === "choose") {
        if (!state.authorizing) return state
        return { step: "choose", methodId: state.methodId, authorizing: false }
      }
      const previous = path[index - 1]
      if (!previous) return state
      return { step: previous, methodId: state.methodId, authorizing: false }
    }
    case "verified": {
      if (state.step === "done") return state
      if (state.step === "choose" && !state.authorizing) return state
      const next = path[index + 1]
      if (!next) return state
      return { step: next, methodId: state.methodId, authorizing: false }
    }
    case "failed":
      if (state.step === "done") return state
      // Stay on the step so the user can fix the input and try again; a failed sign-in ends the authorization.
      return { step: state.step, methodId: state.methodId, authorizing: false, failure: event.reason }
  }
}

export type WizardStepView = {
  /** Zero-based position in the method's path. */
  readonly index: number
  readonly steps: readonly WizardStepId[]
  readonly step: WizardStepId
}

export function selectWizardStep(descriptor: SourceDescriptor, state: WizardState): WizardStepView {
  const steps = wizardPath(descriptor.methods.find((item) => item.id === state.methodId))
  return { index: Math.max(0, steps.indexOf(state.step)), steps, step: state.step }
}

/** Back is offered after `choose`, and on `choose` while a sign-in authorization can be cancelled; never mid-request. */
export function selectCanGoBack(state: WizardState, busy: boolean) {
  if (busy || state.step === "done") return false
  return state.step !== "choose" || state.authorizing
}
