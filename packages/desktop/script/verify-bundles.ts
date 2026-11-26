import path from "node:path"
import { Script, SourceTextModule } from "node:vm"

import { stat } from "node:fs/promises"

const targets = ["main", "preload"] as const

// Resources that electron-builder copies into the installer. Packaging must not start without all of them.
export function requiredResources(os: string) {
  const ext = os === "win32" ? ".exe" : ""

  return [`bellucode-cli${ext}`, `bellud${ext}`]
}

// Fails closed: throws naming every missing or empty required resource, before anything is packaged or
// any previous artifact is touched.
export async function verifyResources(resourcesDir: string, os: string) {
  const missing: string[] = []

  for (const name of requiredResources(os)) {
    const file = path.join(resourcesDir, name)
    const info = await stat(file).catch(() => undefined)

    if (!info?.isFile() || info.size === 0) missing.push(file)
  }

  if (missing.length > 0)
    throw new Error(`Missing required desktop resources (not packaging):\n${missing.map((f) => `  - ${f}`).join("\n")}`)
}

// Parses every built main and preload bundle without executing it, catching syntax and early
// redeclaration errors even in chunks that the app loads lazily at runtime.
export async function verifyBundles(outDir: string) {
  const glob = new Bun.Glob("**/*.{js,cjs,mjs}")
  const failures: string[] = []

  for (const target of targets) {
    const dir = path.join(outDir, target)
    const files = await Array.fromAsync(glob.scan({ cwd: dir, onlyFiles: true })).catch(() => [])

    if (files.length === 0) throw new Error(`Expected built chunks in ${dir}, found none`)

    const errors = await Promise.all(
      files.sort().map(async (file) => {
        const label = `${target}/${file.replaceAll("\\", "/")}`
        const error = parseError(await Bun.file(path.join(dir, file)).text(), label)

        return error ? `${label}: ${error}` : undefined
      }),
    )

    failures.push(...errors.filter((item): item is string => item !== undefined))
  }

  if (failures.length > 0) throw new Error(`Desktop bundle syntax check failed:\n${failures.join("\n")}`)
}

function parseError(code: string, identifier: string) {
  const source = code.replace(/^#!.*\r?\n/, "\n")

  try {
    if (identifier.endsWith(".cjs")) {
      new Script(`(function (exports, require, module, __filename, __dirname) { ${source}\n})`, {
        filename: identifier,
      })

      return undefined
    }

    new SourceTextModule(source, { identifier })

    return undefined
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
}
