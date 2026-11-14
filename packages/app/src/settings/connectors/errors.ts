import { ClientError, isConflictError, isConnectorError, isServiceUnavailableError } from "@bellucode/client"
import type { Connectors } from "@bellucode/schema/connectors"
import type { dict } from "@/runtime/i18n/en"

/** Plain keys only: `language.t` rejects plural variants, which only `language.plural` resolves. */
type Key = Exclude<Extract<keyof typeof dict, string>, `${string}.${"zero" | "one" | "two" | "few" | "many" | "other"}`>

/**
 * What a failed connector request means for the UI. It carries codes and field names only, never the server's message,
 * so nothing a response contained can reach the screen except through an i18n key.
 */
export type ConnectorFailure =
  | {
      readonly kind: "connector"
      readonly code: Connectors.ErrorCode
      readonly offenders: readonly string[]
      /** Whole seconds until a retry is worthwhile, present only when the server sent it (`rate_limited`). */
      readonly retryAfterSec?: number
    }
  /** The service did not answer or is not running. */
  | { readonly kind: "unavailable" }
  /** The 30 s request deadline passed. */
  | { readonly kind: "timeout" }
  | { readonly kind: "unknown" }

const STATUS_CODES: Readonly<Record<number, Connectors.ErrorCode>> = {
  403: "forbidden",
  413: "payload_too_large",
}

/**
 * Normalizes a rejected client call. A `ConnectorError` is declared for 400 and arrives with its code. 403 and 413 are
 * not declared statuses, so the client rejects them as `UnexpectedStatus` with only the status, and the status names the
 * code. A conflict is the sync that is already running.
 */
export function classifyConnectorFailure(error: unknown, timedOut: boolean): ConnectorFailure {
  if (timedOut) return { kind: "timeout" }
  if (isConnectorError(error)) {
    const failure = { kind: "connector", code: error.code, offenders: error.offenders ?? [] } as const
    // The generated client type gains `retryAfterSec` when it is regenerated; read it defensively until then.
    const retry: unknown = "retryAfterSec" in error ? error.retryAfterSec : undefined
    return typeof retry === "number" ? { ...failure, retryAfterSec: retry } : failure
  }
  if (isConflictError(error)) return { kind: "connector", code: "run_in_progress", offenders: [] }
  if (isServiceUnavailableError(error)) return { kind: "unavailable" }
  if (error instanceof ClientError) {
    if (error.reason === "Transport") return { kind: "unavailable" }
    const status = statusOf(error)
    const code = status === undefined ? undefined : STATUS_CODES[status]
    if (code) return { kind: "connector", code, offenders: [] }
  }
  return { kind: "unknown" }
}

function statusOf(error: ClientError) {
  const cause: unknown = error.cause
  if (typeof cause !== "object" || cause === null || !("status" in cause)) return
  return typeof cause.status === "number" ? cause.status : undefined
}

const CODE_KEYS = {
  invalid_credential: "settings.connectors.error.authentication",
  insufficient_permission: "settings.connectors.error.insufficientPermission",
  excess_permission: "settings.connectors.error.excessPermission",
  network: "settings.connectors.error.network",
  rate_limited: "settings.connectors.error.rateLimited",
  expired: "settings.connectors.error.expired",
  alias_invalid: "settings.connectors.error.aliasInvalid",
  alias_taken: "settings.connectors.error.aliasTaken",
  blocked_by_policy: "settings.connectors.error.blockedByPolicy",
  scope_denied: "settings.connectors.error.scopeDenied",
  run_in_progress: "settings.connectors.error.syncInProgress",
  vault_unavailable: "settings.connectors.error.vaultLocked",
  audit_failed: "settings.connectors.audit.failed",
  decrypt_failed: "settings.connectors.error.decryptFailed",
  transition_rejected: "settings.connectors.error.transitionRejected",
  validation_failed: "settings.connectors.error.validation",
  payload_too_large: "settings.connectors.error.payloadTooLarge",
  forbidden: "settings.connectors.error.authorization",
  device_code_expired: "settings.connectors.error.device_code_expired",
  authorization_denied: "settings.connectors.error.authorization_denied",
  device_flow_disabled: "settings.connectors.error.device_flow_disabled",
  already_pending: "settings.connectors.error.already_pending",
} as const satisfies Readonly<Record<Connectors.ErrorCode, Key>>

/** The plural base for the rate-limit message with a retry time. Resolved only by `language.plural`. */
const RATE_LIMITED_RETRY = "settings.connectors.error.rateLimited.retry"
/** Only the keys `failureMessage` can return, so callers pass them to `language.t` (which rejects plural lookup keys). */
type FailureKey =
  | (typeof CODE_KEYS)[Connectors.ErrorCode]
  | "settings.connectors.error.request_timeout"
  | "settings.connectors.error.timeout"
  | "settings.connectors.error.serviceUnavailable"
  | "settings.connectors.error.unknown"
export type FailureMessage = {
  key: FailureKey
  params?: Record<string, string>
  /** Set when the message is count-sensitive: render it with `language.plural(plural.key, plural.count)` instead of `key`. */
  plural?: { key: typeof RATE_LIMITED_RETRY; count: number }
}
const KEYS_BY_CODE: Readonly<Partial<Record<string, FailureKey>>> = CODE_KEYS
/** A server newer than this build can send a code the table lacks; it gets the generic message. */
function keyFor(code: string): FailureKey {
  return (Object.hasOwn(KEYS_BY_CODE, code) ? KEYS_BY_CODE[code] : undefined) ?? "settings.connectors.error.unknown"
}
/** The i18n key and parameters for a failure. Offenders are field names or permission names, never values. */
export function failureMessage(failure: ConnectorFailure): FailureMessage {
  if (failure.kind === "timeout") return { key: "settings.connectors.error.timeout" }
  if (failure.kind === "unavailable") return { key: "settings.connectors.error.serviceUnavailable" }
  if (failure.kind === "unknown") return { key: "settings.connectors.error.unknown" }
  const key = keyFor(failure.code)
  if (failure.code === "excess_permission") return { key, params: { permissions: failure.offenders.join(", ") } }
  if (failure.code === "validation_failed") return { key, params: { fields: failure.offenders.join(", ") } }
  return signInFailureMessage(failure.code, failure.retryAfterSec)
}
/** The message for a sign-in failure, whose codes are the typed codes plus the UI-only `request_timeout`. */
export function signInFailureMessage(code: Connectors.ErrorCode | "request_timeout", retryAfterSec?: number): FailureMessage {
  if (code === "request_timeout") return { key: "settings.connectors.error.request_timeout" }
  const key = keyFor(code)
  if (code === "rate_limited" && retryAfterSec !== undefined && retryAfterSec > 0) {
    return { key, plural: { key: RATE_LIMITED_RETRY, count: retryAfterSec } }
  }
  return { key }
}
