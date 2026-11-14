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
}

export type PasteField = {
  readonly id: string
  readonly labelKey: string
  readonly secret: boolean
  readonly multiline: boolean
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
}

export type SourceDescriptor = {
  readonly id: string
  readonly choose: StepGuide
  /** The first method is the default selection. */
  readonly methods: readonly SourceMethod[]
}
