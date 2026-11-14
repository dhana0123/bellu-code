import { selectDisabled, type SignInState } from "./signin-machine"
import type { AliasError } from "./machine"

/**
 * Whether the "Sign in with GitHub" control is shown and enabled in the connect dialog (Requirements 1.5, 1.6,
 * 11.4, 11.5, 12.1). Pure: the panel passes the alias error it already computed with `validateAlias`.
 */
const GITHUB_HOST = "github.com"

/** The control is hidden for any host other than github.com. An empty host means the default, github.com. */
export function selectSignInVisible(host: string) {
  const value = host.trim().toLowerCase()
  return value === "" || value === GITHUB_HOST
}

export type SignInAvailabilityInput = {
  /** Result of `validateAlias` for the alias field; `undefined` when the alias is valid and unused. */
  readonly aliasError: AliasError | undefined
  readonly machine: SignInState
  /** A personal access token connect request is running. */
  readonly patBusy: boolean
  readonly host: string
}

/** Enabled only for a valid alias, an idle or failed machine, no running PAT request and a github.com host. */
export function selectSignInAvailable(input: SignInAvailabilityInput) {
  if (input.aliasError !== undefined) return false
  if (selectDisabled(input.machine)) return false
  if (input.patBusy) return false
  return selectSignInVisible(input.host)
}
