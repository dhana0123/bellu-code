import { describe, expect, test } from "bun:test"
import path from "node:path"
import { Glob } from "bun"
import { desktopInstall, docsInstalls, installs, sdkInstalls } from "../src/lib/install-commands"

// The site shows Bellu Code 2. These names install Bellu Code 1 (see src/lib/install-commands.ts):
// the opencode-ai npm package, the unversioned install script, the tap's bellucode formula and the
// bellucode-bin AUR package. Scoped @opencode-ai/... packages are code samples, not installs.
const v1 = [
  { name: "the opencode-ai npm package", pattern: /(?<![@\w/-])opencode-ai(?![\w/-])/ },
  { name: "the Bellu Code 1 install script", pattern: /opencode\.ai\/install\b/ },
  { name: "the tap's Bellu Code 1 formula", pattern: /anomalyco\/tap\/bellucode(?![\w-])/ },
  { name: "the bellucode-bin AUR package", pattern: /\bbellucode-bin\b/ },
  { name: "the AUR bellucode package", pattern: /\b(paru|yay|pacman) -S bellucode(?![\w-])/ },
]

const app = path.join(import.meta.dir, "..")
// Site copy and the sources of every generated text file (llms.txt, llms-full.txt, the .md pages,
// the view-source comment, voice answers). Not .output: a stale build would fail the test.
const roots = ["src", "public", "script"]
const text = /\.(tsx?|jsx?|css|md|mdx|txt|json|html|xml|webmanifest)$/
// Stored GitHub data (script/github-snapshot.ts): past release notes may name Bellu Code 1 packages
// as history, not as an install command.
const stored = new Set(["src/lib/github-snapshot.json"])

async function files() {
  const found = await Promise.all(
    roots.map((root) =>
      Array.fromAsync(new Glob(`${root}/**/*`).scan({ cwd: app, onlyFiles: true, dot: true })).then(
        (files) => files.map((file) => file.replaceAll("\\", "/")),
        () => [],
      ),
    ),
  )
  return found.flat().filter((file) => text.test(file) && !stored.has(file) && !file.includes("node_modules"))
}

describe("install commands", () => {
  test("every command installs Bellu Code 2", () => {
    const commands = [
      ...installs.map((item) => item.command),
      ...docsInstalls.map((item) => item.code),
      ...sdkInstalls.map((item) => item.command),
      desktopInstall.command,
    ]
    commands.forEach((command) => v1.forEach((item) => expect(command).not.toMatch(item.pattern)))
    expect(installs.map((item) => item.command)).toEqual([
      "curl -fsSL https://opencode.ai/v2/install | bash",
      "npm install -g @bellucode/cli",
      "bun install -g --trust @bellucode/cli",
      "brew install anomalyco/tap/bellucode-v2",
      "paru -S bellucode-beta",
    ])
  })

  test("site copy and generated text name no Bellu Code 1 install", async () => {
    const list = await files()
    expect(list.length).toBeGreaterThan(100)
    const hits = (
      await Promise.all(
        list.map(async (file) =>
          (await Bun.file(path.join(app, file)).text()).split("\n").flatMap((line, index) =>
            // Comments may name the Bellu Code 1 packages to explain why the site doesn't.
            /^\s*(\/\/|\*|\/\*)/.test(line)
              ? []
              : v1.filter((item) => item.pattern.test(line)).map((item) => `${file}:${index + 1} ${item.name}`),
          ),
        ),
      )
    ).flat()
    expect(hits).toEqual([])
  })
})
