import { spawn, type ChildProcess } from "node:child_process"
import { randomBytes } from "node:crypto"
import { createInterface } from "node:readline"
import { app } from "electron"
import type { Endpoint } from "@bellucode/client/service"
import { BELLUD_USERNAME, belludArgs, parseListening, type BelludTarget } from "./bellud-launch"

import { BELLUD_READY_TIMEOUT_MS, SidecarStartupError, waitForHealth } from "./bellud-probe"

export interface Running {
  readonly endpoint: Endpoint
  readonly child: ChildProcess
}

let current: Promise<Running> | undefined

/**
 * Starts `bellud serve` on a random loopback port, or returns the one this app already started. The sidecar is
 * a child of the app (not a detached background service): it gets a fresh password per launch and stops with the app.
 */
export function ensureBellud(executable: string, target: BelludTarget): Promise<Running> {
  if (current) {
    const existing = current

    return existing.then(
      (running) => (alive(running.child) ? running : replace(executable, target)),
      () => replace(executable, target),
    )
  }

  return replace(executable, target)
}

function replace(executable: string, target: BelludTarget) {
  const started = start(executable, target)

  current = started
  started.catch(() => {
    if (current === started) current = undefined
  })

  return started
}

function alive(child: ChildProcess) {
  return child.exitCode === null && child.signalCode === null
}

function start(executable: string, target: BelludTarget): Promise<Running> {
  const password = randomBytes(24).toString("hex")

  return new Promise<Running>((resolve, reject) => {
    const child = spawn(executable, belludArgs(target), {
      windowsHide: true,
      stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, BELLUCODE_PASSWORD: password },
    })

    const abort = new AbortController()
    let settled = false
    let tail = ""
    const settle = (action: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      action()
    }
    const fail = (message: string, cause?: unknown) => {
      abort.abort()
      settle(() => reject(new SidecarStartupError(`${message}\n${tail.trim()}`.trim(), { cause })))
      if (alive(child)) child.kill()
    }
    // One budget covers spawn, the listening line and the first answer from the health endpoint.
    const timer = setTimeout(
      () => fail(`bellud was not ready within ${BELLUD_READY_TIMEOUT_MS / 1000}s`),
      BELLUD_READY_TIMEOUT_MS,
    )
    let probing = false
    // Reading to the end keeps the stderr pipe from filling and blocking bellud after startup.
    createInterface({ input: child.stderr! }).on("line", (line) => {
      tail = `${tail}\n${line}`.slice(-4096)
      const url = parseListening(line)
      if (!url || probing) return
      probing = true
      waitForHealth({ origin: url, password, signal: abort.signal }).then(
        () =>
          settle(() =>
            resolve({ child, endpoint: { url, auth: { type: "basic", username: BELLUD_USERNAME, password } } }),
          ),
        () => undefined,
      )
    })
    child.once("error", (cause) => fail("Failed to start bellud", cause))
    child.once("close", (code, signal) => fail(`bellud exited (${signal ?? `code ${code}`}) before it was ready`))
  })
}
// bellud shuts down gracefully on SIGTERM, so it is not left running after the app quits.
app.once("will-quit", () => {
  void current?.then(({ child }) => alive(child) && child.kill()).catch(() => undefined)
})
