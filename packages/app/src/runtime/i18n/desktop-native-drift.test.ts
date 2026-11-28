import { describe, expect, test } from "bun:test"
import { readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { DESKTOP_NATIVE_ENGLISH, DESKTOP_NATIVE_KEYS, DESKTOP_NATIVE_LOCALES } from "./desktop-native"

// Shared_UI locale files are consumed identically by Web_Client and Desktop_App, so the only drift
// surface is the desktop-native key set and its main-process consumers.

/** Keys that intentionally fall back to English in every non-English locale (macOS permission prompts). */
const ENGLISH_FALLBACK_EVERYWHERE = new Set<string>(DESKTOP_NATIVE_KEYS.filter((key) => key.endsWith("Usage")))

/** Locales whose spellcheck menu strings intentionally fall back to English. */
const SPELLCHECK_FALLBACK_LOCALES = ["pa", "am", "dv", "dz", "fo", "km", "lo", "mn", "my", "ne", "si", "tg", "tk"]
const SPELLCHECK_KEYS = ["desktop.contextMenu.spellcheck", "desktop.contextMenu.spellcheckLanguages"]

const ENGLISH_FALLBACK_BY_LOCALE: Record<string, ReadonlySet<string>> = Object.fromEntries(
  SPELLCHECK_FALLBACK_LOCALES.map((locale) => [locale, new Set(SPELLCHECK_KEYS)]),
)

function allowed(locale: string, key: string) {
  return ENGLISH_FALLBACK_EVERYWHERE.has(key) || ENGLISH_FALLBACK_BY_LOCALE[locale]?.has(key) === true
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return sourceFiles(path)
    return /\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name) ? [path] : []
  })
}

describe("desktop native i18n drift", () => {
  test("every DESKTOP_NATIVE_LOCALES entry has a locale file and vice versa", () => {
    const files = readdirSync(import.meta.dir)
      .map((name) => /^([a-z]{2,3})\.ts$/.exec(name)?.[1])
      .filter((locale): locale is string => locale !== undefined)
    const declared = new Set<string>(DESKTOP_NATIVE_LOCALES)
    for (const locale of DESKTOP_NATIVE_LOCALES) {
      expect(files.includes(locale), `locale ${locale} has no locale file`).toBe(true)
    }
    for (const locale of files) {
      expect(declared.has(locale), `locale file ${locale}.ts is missing from DESKTOP_NATIVE_LOCALES`).toBe(true)
    }
  })

  test("every nativeT key used by the desktop main process exists in DESKTOP_NATIVE_ENGLISH", () => {
    const root = join(import.meta.dir, "../../../../desktop/src/main")
    const used = new Map<string, string>()
    for (const file of sourceFiles(root)) {
      for (const match of readFileSync(file, "utf8").matchAll(/\bnativeT\(\s*["'`]([^"'`]+)["'`]/g)) {
        used.set(match[1], file)
      }
    }
    expect(used.size, "no nativeT calls found; scan path is wrong").toBeGreaterThan(0)
    for (const [key, file] of used) {
      expect(Object.hasOwn(DESKTOP_NATIVE_ENGLISH, key), `${key} used in ${file} is missing from DESKTOP_NATIVE_ENGLISH`).toBe(
        true,
      )
    }
  })

  test("every non-English locale defines each native key unless it is on the English-fallback allow-list", async () => {
    for (const locale of DESKTOP_NATIVE_LOCALES) {
      if (locale === "en") continue
      const { dict } = (await import(`./${locale}`)) as { dict: Record<string, unknown> }
      for (const key of DESKTOP_NATIVE_KEYS) {
        if (allowed(locale, key)) continue
        expect(dict[key], `locale ${locale} is missing native key ${key}`).toBeDefined()
      }
    }
  })

  test("the allow-list only names real keys and locales", () => {
    const keys = new Set<string>(DESKTOP_NATIVE_KEYS)
    const locales = new Set<string>(DESKTOP_NATIVE_LOCALES)
    expect(ENGLISH_FALLBACK_EVERYWHERE.size).toBe(6)
    for (const [locale, set] of Object.entries(ENGLISH_FALLBACK_BY_LOCALE)) {
      expect(locales.has(locale), `allow-list locale ${locale} is not supported`).toBe(true)
      for (const key of set) expect(keys.has(key), `allow-list key ${key} for ${locale} is unknown`).toBe(true)
    }
  })

  test("allow-listed fallbacks stay necessary", async () => {
    for (const locale of DESKTOP_NATIVE_LOCALES) {
      if (locale === "en") continue
      const { dict } = (await import(`./${locale}`)) as { dict: Record<string, unknown> }
      for (const key of DESKTOP_NATIVE_KEYS) {
        if (!allowed(locale, key)) continue
        expect(dict[key], `locale ${locale} now defines ${key}; remove it from the allow-list`).toBeUndefined()
      }
    }
  })
})
