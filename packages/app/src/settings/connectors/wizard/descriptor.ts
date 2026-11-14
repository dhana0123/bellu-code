/**
 * Describes one Source to the shared Wizard: the connection methods it offers, the steps each method goes through,
 * and the copy shown on every step. Text fields are i18n keys, never English strings.
 */
export type WizardStepId = "choose" | "create" | "paste" | "scope" | "done"

/** The steps a method can include between `choose` and `done`. */
export type MethodStepId = "create" | "paste" | "scope"

export type HttpsUrl = `https://${string}`

/** One short instruction and one docs link, shown on a step. */
export type StepGuide = {
  readonly instructionKey: string
  readonly docsUrl: HttpsUrl
  /** The link text. Defaults to the generic setup-guide label. */
  readonly docsLabelKey?: string
}

export type PasteField = {
  readonly id: string
  readonly labelKey: string
  readonly secret: boolean
  readonly multiline: boolean
  readonly placeholder?: string
  /** Optional fields do not block Verify and are not marked required. */
  readonly optional?: boolean
  /** Help text shown under the field. */
  readonly descriptionKey?: string
}

/** Text the user copies out of the Wizard, such as a kubectl manifest or a role list. */
export type CopyBlock = {
  readonly id: string
  readonly labelKey: string
  readonly content: string
}

export type SourceMethod = {
  readonly id: string
  /** `signin` runs a device or OAuth flow and never has a `create` or `paste` step. */
  readonly kind: "signin" | "paste"
  readonly titleKey: string
  readonly descriptionKey: string
  /** The steps after `choose`, in order. Sign-in methods ignore `create` and `paste`. */
  readonly steps: readonly MethodStepId[]
  readonly guides: Readonly<Partial<Record<MethodStepId, StepGuide>>>
  readonly fields?: readonly PasteField[]
  readonly copyBlocks?: readonly CopyBlock[]
  /** Overrides the stepper label of a step for this method. */
  readonly stepKeys?: Partial<Record<WizardStepId, string>>
  /** Overrides the label of the step's primary button for this method. */
  readonly actionKeys?: Partial<Record<MethodStepId, string>>
}
/** Copy for the Connected screen. Defaults to the generic keys. */
export type ConnectedCopy = {
  readonly titleKey: string
  readonly accountKey: string
  readonly noteKey?: string
}

export type SourceDescriptor = {
  readonly id: string
  /** Instruction shown on `choose`. Omit it when the method list is self-explanatory. */
  readonly choose?: StepGuide
  readonly connected?: ConnectedCopy
  /** The accessible label of the stepper. Defaults to the generic key. */
  readonly stepsLabelKey?: string
  /** Replaces the generic "sign-in unavailable" note for sources whose copy names the sign-in. */
  readonly signinUnavailableKey?: string
  /** Hides the "sign-in unavailable" note for sources that never offer sign-in. */
  readonly hideSigninNote?: boolean
  /** Hides the Recommended badge on the first method, for titles that already say so. */
  readonly hideRecommendedBadge?: boolean
  /** The accessible label of the method list on `choose`. */
  readonly methodsLabelKey?: string
  /** The first method is the default selection. */
  readonly methods: readonly SourceMethod[]
}
