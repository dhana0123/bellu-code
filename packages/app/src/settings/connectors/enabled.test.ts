import { describe, expect, test } from "bun:test"
import { connectorsAvailable, connectorsConfigFlag } from "./enabled"

const doc = (experimental: { connectors?: boolean; all_flags?: boolean }) => ({ type: "document", info: { experimental } })

describe("connectors availability", () => {
  test("the highest-priority experimental document decides the flag", () => {
    expect(connectorsConfigFlag([doc({ connectors: true }), doc({ connectors: false })])).toBe(false)
    expect(connectorsConfigFlag([doc({ connectors: false }), doc({ connectors: true })])).toBe(true)
  })
  test("all_flags turns it on and unset config defers to the probe", () => {
    expect(connectorsConfigFlag([doc({ all_flags: true })])).toBe(true)
    expect(connectorsConfigFlag([{ type: "directory" }])).toBeUndefined()
    expect(connectorsConfigFlag(undefined)).toBeUndefined()
  })
  test("requires the flag not off and a successful enabled probe", () => {
    expect(connectorsAvailable({ flag: undefined, probe: { enabled: true } })).toBe(true)
    expect(connectorsAvailable({ flag: false, probe: { enabled: true } })).toBe(false)
    expect(connectorsAvailable({ flag: true, probe: undefined })).toBe(false)
    expect(connectorsAvailable({ flag: true, probe: { enabled: false } })).toBe(false)
  })
})
