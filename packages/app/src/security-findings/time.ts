/** A timestamp from the server in the reader's locale. A value that does not parse is shown as sent. */
export function formatTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}
