import { describe, expect, test } from "bun:test"
import { dict as en } from "@/runtime/i18n/en"
import { createServerTransport } from "./client"
import { apiGroupFromUrl, createGroupUnavailableReporter, unavailableApiGroup } from "./group-unavailable"

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const url = "http://x/api/experimental/graph/find"

describe("unavailableApiGroup", () => {
  test("names the group for a Go-server stub failure", async () => {
    const res = json(503, { _tag: "ServiceUnavailableError", message: "Graph routes are served by the Go server" })
    expect(await unavailableApiGroup(url, res)).toBe("experimental.graph")
    expect(await unavailableApiGroup(url, json(500, { message: "Findings routes are served by the Go server" }))).toBe(
      "experimental.graph",
    )
  })
  test("names the group for a bare 404", async () => {
    expect(await unavailableApiGroup(url, new Response("not found", { status: 404 }))).toBe("experimental.graph")
  })
  test("ignores ordinary errors", async () => {
    expect(await unavailableApiGroup(url, json(404, { _tag: "NotFoundError", message: "no such entity" }))).toBeUndefined()
    expect(await unavailableApiGroup(url, json(400, { message: "bad" }))).toBeUndefined()
    expect(await unavailableApiGroup(url, json(401, {}))).toBeUndefined()
    expect(await unavailableApiGroup(url, new Response("{}", { status: 200 }))).toBeUndefined()
    expect(await unavailableApiGroup("http://x/api/session", new Response("", { status: 404 }))).toBeUndefined()
  })
  test("derives the group from the path", () => {
    expect(apiGroupFromUrl("http://x/api/experimental/sbom/list?a=1")).toBe("experimental.sbom")
    expect(apiGroupFromUrl("http://x/api/experimental/sbom")).toBe("experimental.sbom")
    expect(apiGroupFromUrl("http://x/api/experimental/sbom?a=1")).toBe("experimental.sbom")
  })
})

// Transport and unit level. Mounting `createServerSdkContext` needs the platform, server and sync providers, so the
// toast wiring is covered through the reporter it uses and the transport it builds, not through a mounted view.
describe("group unavailable reporting", () => {
  test("the error text names the group", () => {
    expect(en["error.apiGroupUnavailable.title"]).toContain("{{group}}")
    expect(en["error.apiGroupUnavailable.description"]).toContain("{{group}}")
  })

  test("shows each group once per server", () => {
    const shown: string[] = []
    const first = createGroupUnavailableReporter((group) => shown.push(`a:${group}`))
    const second = createGroupUnavailableReporter((group) => shown.push(`b:${group}`))
    first("experimental.sbom")
    first("experimental.sbom")
    first("experimental.graph")
    second("experimental.sbom")
    expect(shown).toEqual(["a:experimental.sbom", "a:experimental.graph", "b:experimental.sbom"])
  })

  test("an SDK call to a missing group reports it once, without a retry, and hands the caller its own failure", async () => {
    const requests: string[] = []
    const reported: string[] = []
    const fetch = (async (input: string | URL | Request) => {
      requests.push(input instanceof Request ? input.url : String(input))
      return json(503, { _tag: "ServiceUnavailableError", message: "SBOM routes are served by the Go server" })
    }) as typeof globalThis.fetch
    const transport = createServerTransport({
      http: { url: "http://127.0.0.1:4100" },
      fetch,
      onGroupUnavailable: (group) => reported.push(group),
    })
    // The caller gets the failure back from its own call, so the view handles it in place: nothing in the transport
    // throws past the call or swaps the client, which is what would force the owning component to remount.
    const api = transport.api
    const outcome = await transport.api.experimental.sbom.list().then(
      () => "resolved",
      () => "rejected",
    )
    expect(outcome).toBe("rejected")
    expect(requests).toHaveLength(1)
    expect(new URL(requests[0]!).pathname).toBe("/api/experimental/sbom")
    expect(reported).toEqual(["experimental.sbom"])
    expect(transport.api).toBe(api)
  })
})
