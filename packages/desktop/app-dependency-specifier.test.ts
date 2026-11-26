import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const SECTIONS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] as const
const NAME = "@bellucode/app"
const REQUIRED = "workspace:*"

type Manifest = Partial<Record<(typeof SECTIONS)[number], Record<string, string>>>

// Returns human-readable problems; empty means the manifest is valid.
export function checkAppSpecifier(manifest: Manifest): string[] {
  const problems: string[] = []
  let found = false
  for (const section of SECTIONS) {
    const spec = manifest[section]?.[NAME]
    if (spec === undefined) continue
    found = true
    if (spec !== REQUIRED) problems.push(`${section}: ${NAME} is "${spec}", expected "${REQUIRED}"`)
  }
  if (!found) problems.push(`${NAME} is not declared in any of ${SECTIONS.join(", ")}`)
  return problems
}

test("desktop package.json pins @bellucode/app to workspace:*", () => {
  const manifest = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as Manifest
  expect(checkAppSpecifier(manifest)).toEqual([])
})

test("rejects non-workspace specifiers and missing declarations", () => {
  expect(checkAppSpecifier({ dependencies: { [NAME]: "^1.0.0" } })).toEqual([
    `dependencies: ${NAME} is "^1.0.0", expected "workspace:*"`,
  ])
  expect(checkAppSpecifier({ dependencies: { [NAME]: REQUIRED }, devDependencies: { [NAME]: "1.2.3" } })).toHaveLength(1)
  expect(checkAppSpecifier({ dependencies: {} })).toHaveLength(1)
})
