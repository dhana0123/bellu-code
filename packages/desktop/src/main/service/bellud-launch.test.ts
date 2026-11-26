import { describe, expect, test } from "bun:test"
import { belludArgs, belludExecutableName, parseListening } from "./bellud-launch"

describe("belludArgs", () => {
  test("runs the compiled CLI through --cli-bin on a random loopback port", () => {
    expect(belludArgs({ cliBinary: "/res/bellucode-cli" })).toEqual([
      "serve",
      "--hostname",
      "127.0.0.1",
      "--port",
      "0",
      "--cli-bin",
      "/res/bellucode-cli",
    ])
  })

  test("falls back to --repo when the CLI runs from source", () => {
    expect(belludArgs({ repo: "/work/bellucode" }).slice(-2)).toEqual(["--repo", "/work/bellucode"])
  })

  test("prefers the binary and rejects an empty target", () => {
    expect(belludArgs({ cliBinary: "/a", repo: "/b" })).not.toContain("--repo")
    expect(() => belludArgs({})).toThrow()
  })
})

describe("parseListening", () => {
  test("reads the origin from bellud's log line", () => {
    expect(parseListening("[bellud] 2026/01/02 03:04:05 listening on 127.0.0.1:43211")).toBe("http://127.0.0.1:43211")
    expect(parseListening("[bellud] 2026/01/02 03:04:05 listening on [::1]:5000")).toBe("http://[::1]:5000")
  })

  test("ignores other lines", () => {
    expect(parseListening("[bellud] warning: graph unavailable: x")).toBeUndefined()
    expect(parseListening("[ts-child] listening on nowhere")).toBeUndefined()
  })
})

test("belludExecutableName", () => {
  expect(belludExecutableName("win32")).toBe("bellud.exe")
  expect(belludExecutableName("linux")).toBe("bellud")
})
