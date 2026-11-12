import { expect, test } from "bun:test"
import { selectTheme, selectThemeMode, supportsThemeMode, themeModes } from "@bellucode/theme/tui"
import { getBelluCodeTheme } from "../../../src/theme"

test("selects complete light and dark themes independently", () => {
  const light = selectTheme(getBelluCodeTheme(), "light")
  const dark = selectTheme(getBelluCodeTheme(), "dark")
  expect(selectTheme(getBelluCodeTheme())).toEqual(light)
  expect(light.hue).toEqual(getBelluCodeTheme().light.hue)
  expect(dark.text).toEqual(getBelluCodeTheme().base.text)
  expect(dark.hue).toEqual(getBelluCodeTheme().dark.hue)
  expect(selectThemeMode(getBelluCodeTheme(), "dark")).toEqual({ theme: dark, mode: "dark" })
})

test("selects the available mode when the requested mode is missing", () => {
  const lightOnly = { base: getBelluCodeTheme().base, light: getBelluCodeTheme().light } as const
  const darkOnly = { base: getBelluCodeTheme().base, dark: getBelluCodeTheme().dark } as const

  expect(themeModes(lightOnly)).toEqual(["light"])
  expect(themeModes(darkOnly)).toEqual(["dark"])
  expect(supportsThemeMode(lightOnly, "light")).toBeTrue()
  expect(supportsThemeMode(lightOnly, "dark")).toBeFalse()
  expect(selectThemeMode(lightOnly, "dark")).toEqual({ theme: selectTheme(getBelluCodeTheme(), "light"), mode: "light" })
  expect(selectThemeMode(darkOnly, "light")).toEqual({ theme: selectTheme(getBelluCodeTheme(), "dark"), mode: "dark" })
})
