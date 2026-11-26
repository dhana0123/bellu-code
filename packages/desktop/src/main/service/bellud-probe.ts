// Readiness probe and failure type for `bellud`. Free of Electron so it can be unit tested.
import { BELLUD_USERNAME } from "./bellud-launch"

/** How long bellud has, from spawn, to report its address and answer the probe. */
export const BELLUD_READY_TIMEOUT_MS = 30_000
export const BELLUD_PROBE_INTERVAL_MS = 250
/** bellud has no dedicated health route; `/api/info` needs auth and is served by the CLI it spawns, so it only answers once both run. */
export const BELLUD_HEALTH_PATH = "/api/info"

/** The message users see is fixed; `detail` (bellud's last stderr lines) is for logs only. */
export class SidecarStartupError extends Error {
  static readonly MESSAGE = "Sidecar server failed to start"
  override readonly name = "SidecarStartupError"
  constructor(
    readonly detail: string,
    options?: ErrorOptions,
  ) {
    super(SidecarStartupError.MESSAGE, options)
  }
}

export interface ProbeInput {
  readonly origin: string
  readonly password: string
  readonly signal: AbortSignal
  readonly fetch?: typeof fetch
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>
  readonly intervalMs?: number
}

/** Polls the health endpoint until it answers 2xx. Rejects with the signal's reason once it aborts. */
export async function waitForHealth(input: ProbeInput): Promise<void> {
  const doFetch = input.fetch ?? fetch
  const sleep = input.sleep ?? abortableSleep
  const authorization = `Basic ${Buffer.from(`${BELLUD_USERNAME}:${input.password}`).toString("base64")}`
  const url = new URL(BELLUD_HEALTH_PATH, input.origin)
  while (true) {
    input.signal.throwIfAborted()
    const ok = await doFetch(url, { headers: { authorization }, signal: input.signal }).then(
      (response) => response.ok,
      () => false,
    )
    if (ok) return
    input.signal.throwIfAborted()
    await sleep(input.intervalMs ?? BELLUD_PROBE_INTERVAL_MS, input.signal)
  }
}

function abortableSleep(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(done, ms)
    signal.addEventListener("abort", onAbort, { once: true })
    function done() {
      signal.removeEventListener("abort", onAbort)
      resolve()
    }
    function onAbort() {
      clearTimeout(timer)
      reject(signal.reason)
    }
  })
}
