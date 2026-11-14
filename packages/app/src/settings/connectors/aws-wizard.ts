/**
 * The AWS connect wizard's phase. The setup step (role or keys) and the region step come before the request; the
 * request itself and its failure live in the panel's mutation, and `connected` ends the flow.
 */
import type { AwsMethod } from "./aws-form"

export type AwsWizardState =
  | { readonly step: "choose"; readonly method: AwsMethod }
  | { readonly step: "setup"; readonly method: AwsMethod }
  | { readonly step: "arn"; readonly method: AwsMethod }
  | { readonly step: "regions"; readonly method: AwsMethod }
  | { readonly step: "connected"; readonly method: AwsMethod }
export type AwsWizardEvent =
  | { readonly type: "method.selected"; readonly method: AwsMethod }
  | { readonly type: "continued" }
  | { readonly type: "back" }
  | { readonly type: "connected" }

export const INITIAL_AWS_WIZARD_STATE: AwsWizardState = Object.freeze({ step: "choose", method: "assume_role" })

export function transitionAwsWizard(state: AwsWizardState, event: AwsWizardEvent): AwsWizardState {
  switch (event.type) {
    case "method.selected":
      if (state.step !== "choose" || state.method === event.method) return state
      return { step: "choose", method: event.method }
    case "continued":
      if (state.step === "choose") return { step: "setup", method: state.method }
      // The role ARN exists only after the role is created, so the IAM role path asks for it on its own step.
      if (state.step === "setup") return { step: state.method === "assume_role" ? "arn" : "regions", method: state.method }
      if (state.step === "arn") return { step: "regions", method: state.method }
      return state
    case "back":
      if (state.step === "setup") return { step: "choose", method: state.method }
      if (state.step === "arn") return { step: "setup", method: state.method }
      if (state.step === "regions") return { step: state.method === "assume_role" ? "arn" : "setup", method: state.method }
      return state
    case "connected":
      if (state.step === "connected") return state
      return { step: "connected", method: state.method }
  }
}

export type AwsWizardStep = 1 | 2 | 3 | 4 | "done"

export function selectAwsWizardStep(state: AwsWizardState): AwsWizardStep {
  switch (state.step) {
    case "choose":
      return 1
    case "setup":
      return 2
    case "arn":
      return 3
    case "regions":
      return state.method === "assume_role" ? 4 : 3
    case "connected":
      return "done"
  }
}

/** Back is offered on every step after the first while no request is in flight. */
export function selectAwsCanGoBack(state: AwsWizardState, busy: boolean) {
  return !busy && (state.step === "setup" || state.step === "arn" || state.step === "regions")
}
