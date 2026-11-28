/** Formats whole seconds as MM:SS. Minutes are not capped; negatives and non-finite values clamp to 00:00. */
export function formatCountdown(totalSeconds: number): string {
  const total = Number.isFinite(totalSeconds) ? Math.max(0, Math.floor(totalSeconds)) : 0
  const minutes = Math.floor(total / 60)
  const seconds = total % 60
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`
}

/** Parses MM:SS (minutes of two or more digits, seconds 00-59) into seconds, or undefined if malformed. */
export function parseCountdown(text: string): number | undefined {
  const match = /^(\d{2,}):([0-5]\d)$/.exec(text)
  if (!match) return undefined
  return Number(match[1]) * 60 + Number(match[2])
}
