import { describe, expect, test } from "bun:test"
import {
  INITIAL_WIZARD_STATE,
  selectCanGoBack,
  selectMethod,
  selectWizardStep,
  transitionWizard,
  type WizardProgress,
} from "./github-wizard"

const idle: WizardProgress = { signInBusy: false, patBusy: false, repositories: false, connected: false }

describe("github wizard", () => {
  test("choose, continue, back keeps the method", () => {
    const picked = transitionWizard(INITIAL_WIZARD_STATE, { type: "method.selected", method: "pat" })
    const next = transitionWizard(picked, { type: "continued" })
    expect(next).toEqual({ step: "authorize", method: "pat" })
    expect(transitionWizard(next, { type: "method.selected", method: "signin" })).toBe(next)
    expect(transitionWizard(next, { type: "back" })).toEqual({ step: "choose", method: "pat" })
  })

  test("events that do not apply return the same state", () => {
    expect(transitionWizard(INITIAL_WIZARD_STATE, { type: "back" })).toBe(INITIAL_WIZARD_STATE)
    expect(transitionWizard(INITIAL_WIZARD_STATE, { type: "method.selected", method: "signin" })).toBe(
      INITIAL_WIZARD_STATE,
    )
  })

  test("falls back to the token without a device method", () => {
    expect(selectMethod(INITIAL_WIZARD_STATE, false)).toBe("pat")
    expect(selectMethod(INITIAL_WIZARD_STATE, true)).toBe("signin")
  })

  test("step follows progress and back is blocked while pending", () => {
    const authorize = transitionWizard(INITIAL_WIZARD_STATE, { type: "continued" })
    expect(selectWizardStep(INITIAL_WIZARD_STATE, idle)).toBe(1)
    expect(selectWizardStep(authorize, idle)).toBe(2)
    expect(selectCanGoBack(authorize, idle)).toBe(true)
    expect(selectCanGoBack(authorize, { ...idle, signInBusy: true })).toBe(false)
    expect(selectCanGoBack(authorize, { ...idle, patBusy: true })).toBe(false)
    expect(selectWizardStep(authorize, { ...idle, repositories: true })).toBe(3)
    expect(selectWizardStep(authorize, { ...idle, repositories: true, connected: true })).toBe("done")
  })
})
