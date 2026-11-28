import { describe, expect, test } from "bun:test"
import path from "node:path"
import ts from "typescript"

// Requirement 5.6: every member of the desktop `Platform` arm (PlatformBase plus
// platform, os, windowID, openDirectoryPickerDialog) must be implemented by
// `createDesktopPlatform` or listed as unsupported.
//
// Both sides come from the TypeScript checker rather than a hand-kept list, so a new
// interface member or a dropped implementation fails here by name. (This package's
// tsconfig excludes *.test.ts, and `createDesktopPlatform` needs window/IPC globals that
// plain `bun test` lacks, so a compile-time mapped type or a runtime call is not usable.)
//
// Optional members get no exemption: the desktop renderer must implement them or list
// them as unsupported. Required members are always implemented by the return type, so the
// check also reports them if they ever go missing.

// Members the desktop renderer deliberately does not implement. Mirrors the "unsupported"
// entries in .kiro/specs/desktop-web-ui-sync/parity-inventory.md (that file is gitignored,
// so it is never read at runtime). Currently empty: all 39 members are implemented.
const unsupported: readonly string[] = []

function analyze() {
  const dir = import.meta.dir
  const configPath = path.join(dir, "../../../tsconfig.json")
  const config = ts.readConfigFile(configPath, ts.sys.readFile)
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, path.dirname(configPath))
  const file = path.join(dir, "index.ts")
  const program = ts.createProgram([file], { ...parsed.options, noEmit: true, composite: false, incremental: false })
  const checker = program.getTypeChecker()
  const source = program.getSourceFile(file)!
  let fn: ts.FunctionDeclaration | undefined
  ts.forEachChild(source, (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === "createDesktopPlatform") fn = node
  })
  if (!fn) throw new Error("createDesktopPlatform not found")

  // Interface members: the desktop arm of the declared return type `Platform`.
  const returnType = checker.getTypeFromTypeNode(fn.type!)
  const arm = returnType.isUnion() ? returnType.types.find((t) => t.getProperty("openDirectoryPickerDialog")) : returnType
  if (!arm) throw new Error("desktop arm of Platform not found")
  const interfaceMembers = checker.getPropertiesOfType(arm).map((symbol) => ({
    name: symbol.name,
    optional: (symbol.flags & ts.SymbolFlags.Optional) !== 0,
  }))

  // Implemented members: properties of the returned object literal, spreads included.
  const ret = fn.body?.statements.find(ts.isReturnStatement)?.expression
  if (!ret || !ts.isObjectLiteralExpression(ret)) throw new Error("createDesktopPlatform must return an object literal")
  const implemented = checker.getPropertiesOfType(checker.getTypeAtLocation(ret)).map((symbol) => symbol.name)
  return { interfaceMembers, implemented }
}

describe("desktop Platform coverage", () => {
  const { interfaceMembers, implemented } = analyze()
  const names = interfaceMembers.map((member) => member.name)

  test("interface has the 39 known members", () => {
    expect(names).toHaveLength(39)
    expect(names).toEqual(expect.arrayContaining(["platform", "os", "windowID", "openDirectoryPickerDialog", "openExternal"]))
  })

  test("every member is implemented or listed as unsupported", () => {
    const missing = names.filter((name) => !implemented.includes(name) && !unsupported.includes(name))
    expect(missing, `Platform members neither implemented nor unsupported: ${missing.join(", ")}`).toEqual([])
  })

  test("no member is both implemented and unsupported", () => {
    const both = unsupported.filter((name) => implemented.includes(name))
    expect(both, `Members both implemented and unsupported: ${both.join(", ")}`).toEqual([])
  })

  test("unsupported list only names real members", () => {
    expect(unsupported.filter((name) => !names.includes(name))).toEqual([])
  })
})
