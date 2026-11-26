import { describe, expect, test } from "bun:test"
import { BELLUD_HEALTH_PATH, BELLUD_READY_TIMEOUT_MS, SidecarStartupError, waitForHealth } from "./bellud-probe"

const origin = "http://127.0.0.1:4567"
const instant = () => Promise.resolve()

describe("waitForHealth", () => {
  test("retries until the endpoint answers OK and sends basic auth", async () => {
    const calls: { url: string; auth: string | null }[] = []
    const fake = (async (url: URL, init?: RequestInit) => {
      calls.push({ url: url.toString(), auth: new Headers(init?.headers).get("authorization") })
      if (calls.length === 1) throw new Error("ECONNREFUSED")
      return new Response("", { status: calls.length === 2 ? 503 : 200 })
    }) as unknown as typeof fetch

    await waitForHealth({ origin, password: "pw", signal: new AbortController().signal, fetch: fake, sleep: instant })

    expect(calls).toHaveLength(3)
    expect(calls[0]!.url).toBe(`${origin}${BELLUD_HEALTH_PATH}`)
    expect(calls[0]!.auth).toBe(`Basic ${Buffer.from("bellucode:pw").toString("base64")}`)
  })

  test("rejects with the abort reason when the deadline passes", async () => {
    const controller = new AbortController()
    const fake = (async () => new Response("", { status: 503 })) as unknown as typeof fetch
    let sleeps = 0
    const sleep = async () => {
      if (++sleeps === 3) controller.abort(new Error("deadline"))
    }

    await expect(waitForHealth({ origin, password: "pw", signal: controller.signal, fetch: fake, sleep })).rejects.toThrow(
      "deadline",
    )
    expect(sleeps).toBe(3)
  })
})

describe("SidecarStartupError", () => {
  test("keeps the user-facing message fixed and the stderr tail as detail", () => {
    const error = new SidecarStartupError("panic: boom")
    expect(error.message).toBe("Sidecar server failed to start")
    expect(error.detail).toBe("panic: boom")
    expect(BELLUD_READY_TIMEOUT_MS).toBe(30_000)
  })
})
