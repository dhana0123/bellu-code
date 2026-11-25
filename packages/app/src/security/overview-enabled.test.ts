import { describe, expect, test } from "bun:test"
import { overviewAvailable, overviewConfigFlag } from "./overview-enabled"
import { SECURITY_PAGES, isSecurityPage } from "./nav-items"

const doc = (experimental: { security_overview?: boolean; all_flags?: boolean }) => ({
  type: "document",
  info: { experimental },
})

describe("overview flag", () => {
  test("highest-priority document decides, then all_flags", () => {
    expect(overviewConfigFlag([doc({ security_overview: true }), doc({ security_overview: false })])).toBe(false)
    expect(overviewConfigFlag([doc({ all_flags: true })])).toBe(true)
    expect(overviewConfigFlag(undefined)).toBeUndefined()
  })

  test("needs a successful probe and no config opt-out", () => {
    expect(overviewAvailable({ flag: undefined, probe: { enabled: true } })).toBe(true)
    expect(overviewAvailable({ flag: false, probe: { enabled: true } })).toBe(false)
    expect(overviewAvailable({ flag: undefined, probe: undefined })).toBe(false)
  })
})

describe("security nav items", () => {
  test("overview is the first page and is no longer coming soon", () => {
    expect(SECURITY_PAGES[0].page).toBe("overview")
    expect(isSecurityPage("overview")).toBe(true)
  })
})
