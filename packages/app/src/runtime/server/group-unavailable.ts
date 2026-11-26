// The Go server owns the /api/experimental/<group>/ routes. A sidecar that does not run it answers them with the TS
// stub handlers, which fail with a message ending "served by the Go server". Only that signal (or a bare 404/503 that
// is not a tagged API error) means the group is not served; validation, auth and network errors are left alone.
const GROUP_PATH = /\/api\/experimental\/([a-z][a-z0-9-]*)(?:[/?#]|$)/i
const STUB_MESSAGE = /served by the Go server/i

export function apiGroupFromUrl(url: string): string | undefined {
  const match = GROUP_PATH.exec(url)
  return match ? `experimental.${match[1]}` : undefined
}

// One reporter per server: each group is shown once for that server, so repeated calls do not stack toasts.
export function createGroupUnavailableReporter(show: (group: string) => void) {
  const reported = new Set<string>()
  return (group: string) => {
    if (reported.has(group)) return
    reported.add(group)
    show(group)
  }
}
export async function unavailableApiGroup(url: string, response: Response): Promise<string | undefined> {
  if (response.ok) return undefined
  if (response.status !== 404 && response.status !== 500 && response.status !== 503) return undefined
  const group = apiGroupFromUrl(url)
  if (!group) return undefined
  const body: unknown = await response
    .clone()
    .json()
    .catch(() => undefined)
  const message =
    typeof body === "object" && body !== null && "message" in body && typeof body.message === "string"
      ? body.message
      : undefined
  if (message !== undefined) return STUB_MESSAGE.test(message) ? group : undefined
  const tagged = typeof body === "object" && body !== null && "_tag" in body
  if (tagged) return undefined
  return response.status === 404 || response.status === 503 ? group : undefined
}
