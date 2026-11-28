const WINDOW_MS = 7 * 24 * 60 * 60 * 1000

export type ExpiryWarning = "expired" | "soon"

type ConnectionLike = {
  status: string
  credentialExpiresAt?: string | null
}

/**
 * Chooses the expiry indicator for a connection.
 * "expired" when status is EXPIRED; "soon" when not EXPIRED and 0 < remaining < 7 days; otherwise undefined.
 * `now` is epoch milliseconds; `credentialExpiresAt` is an ISO timestamp.
 */
export function selectExpiryWarning(connection: ConnectionLike, now: number): ExpiryWarning | undefined {
  if (connection.status === "EXPIRED") return "expired"
  if (!connection.credentialExpiresAt) return undefined
  const expires = Date.parse(connection.credentialExpiresAt)
  if (!Number.isFinite(expires)) return undefined
  const remaining = expires - now
  return remaining > 0 && remaining < WINDOW_MS ? "soon" : undefined
}
