import type { ScansJob, ScansKind, ScansScanner, ScansTargetType } from "@bellucode/client/promise"

export const KINDS: readonly ScansKind[] = [
  "sbom",
  "vulnerability",
  "misconfiguration",
  "secret",
  "posture",
  "data_classification",
  "ai_inventory",
]
export const TARGET_TYPES: readonly ScansTargetType[] = ["repository", "image", "host", "cloud_account", "cluster"]

export type Job = ScansJob
export type Scanner = ScansScanner

/** Jobs poll every 5 s while one is queued or running (Requirement 18.12). */
export const POLL_INTERVAL_MS = 5000
export const REQUEST_TIMEOUT_MS = 15000

export const MIN_INTERVAL_SECONDS = 15 * 60
export const MAX_INTERVAL_SECONDS = 30 * 24 * 60 * 60

export const UNITS = { minutes: 60, hours: 3600, days: 86400 } as const
export type Unit = keyof typeof UNITS

/** The interval in seconds, or `undefined` when the amount is not a whole number in the allowed range. */
export function intervalSeconds(amount: string, unit: Unit): number | undefined {
  const value = Number(amount)
  if (amount.trim() === "" || !Number.isInteger(value)) return undefined
  const seconds = value * UNITS[unit]
  return seconds >= MIN_INTERVAL_SECONDS && seconds <= MAX_INTERVAL_SECONDS ? seconds : undefined
}

export const isActive = (job: Job) => job.status === "queued" || job.status === "running"

/** The schedule id the page writes for a kind and target type, so one schedule exists per pair. */
export const scheduleId = (kind: ScansKind, targetType: ScansTargetType) => `${kind}:${targetType}`
