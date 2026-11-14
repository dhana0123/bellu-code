/**
 * The GitHub connect wizard's own phase: which method was chosen and whether the user has left the choice step.
 * Everything after "Continue" (device authorization, token submit, repositories, saved) already lives in
 * `signin-machine.ts` and `github-machine.ts`; `selectWizardStep` derives the visible step from all of them.
 */
export type WizardMethod = "signin" | "pat"

export type WizardState = { readonly step: "choose" | "authorize"; readonly method: WizardMethod }

export type WizardEvent =
  | { readonly type: "method.selected"; readonly method: WizardMethod }
  | { readonly type: "continued" }
  | { readonly type: "back" }

export const INITIAL_WIZARD_STATE: WizardState = Object.freeze({ step: "choose", method: "signin" })

export function transitionWizard(state: WizardState, event: WizardEvent): WizardState {
  if (event.type === "method.selected") {
    if (state.step !== "choose" || state.method === event.method) return state
    return { step: "choose", method: event.method }
  }
  if (event.type === "continued") {
    if (state.step !== "choose") return state
    return { step: "authorize", method: state.method }
  }
  if (state.step !== "authorize") return state
  return { step: "choose", method: state.method }
}

/** Without a configured device method the personal access token is the only choice. */
export function selectMethod(state: WizardState, signInConfigured: boolean): WizardMethod {
  return signInConfigured ? state.method : "pat"
}

export type WizardProgress = {
  /** Sign-in is starting, waiting for the code, or checking installations. Nothing may be abandoned silently. */
  readonly signInBusy: boolean
  /** The token request is in flight. */
  readonly patBusy: boolean
  /** Either path reached the repository checklist. */
  readonly repositories: boolean
  /** The Connection is saved. */
  readonly connected: boolean
}

export type WizardStep = 1 | 2 | 3 | "done"

export function selectWizardStep(state: WizardState, progress: WizardProgress): WizardStep {
  if (progress.connected) return "done"
  if (progress.repositories) return 3
  return state.step === "choose" ? 1 : 2
}

/** Back is offered on step 2 only while no authorization or token request is pending. */
export function selectCanGoBack(state: WizardState, progress: WizardProgress) {
  return selectWizardStep(state, progress) === 2 && !progress.signInBusy && !progress.patBusy
}
