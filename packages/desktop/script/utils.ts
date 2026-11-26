import { chmod, copyFile, mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { delimiter, dirname, join, resolve } from "node:path"
import { Option, Schema } from "effect"

const CLI_VERSION = "dev"

const Manifest = Schema.fromJsonString(Schema.Struct({ version: Schema.NonEmptyString }))

export type Channel = "dev" | "beta" | "prod"

export function resolveChannel(): Channel {
  const raw = process.env.BELLUCODE_CHANNEL

  if (raw === "dev" || raw === "beta" || raw === "prod") return raw

  if (raw === "latest") return "prod"

  return "dev"
}

export const CLI_BINARIES: Array<{ target: string; package: string; os: string; cpu: string }> = [
  {
    target: "darwin-arm64",
    package: "@bellucode/cli-darwin-arm64",
    os: "darwin",
    cpu: "arm64",
  },
  {
    target: "darwin-x64",
    package: "@bellucode/cli-darwin-x64-baseline",
    os: "darwin",
    cpu: "x64",
  },
  {
    target: "windows-arm64",
    package: "@bellucode/cli-windows-arm64",
    os: "win32",
    cpu: "arm64",
  },
  {
    target: "windows-x64",
    package: "@bellucode/cli-windows-x64-baseline",
    os: "win32",
    cpu: "x64",
  },
  {
    target: "linux-x64",
    package: "@bellucode/cli-linux-x64-baseline",
    os: "linux",
    cpu: "x64",
  },
  {
    target: "linux-arm64",
    package: "@bellucode/cli-linux-arm64",
    os: "linux",
    cpu: "arm64",
  },
]

// bellud is the Go sidecar server. It cross-compiles natively, so each CLI target maps to a GOOS/GOARCH pair.
// In the packaged app it spawns the bundled bellucode-cli binary (via --cli-bin), so no bun or CLI sources ship.
export const BELLUD_BINARIES: Array<{ target: string; goos: string; goarch: string }> = [
  { target: "darwin-arm64", goos: "darwin", goarch: "arm64" },
  { target: "darwin-x64", goos: "darwin", goarch: "amd64" },
  { target: "windows-arm64", goos: "windows", goarch: "arm64" },
  { target: "windows-x64", goos: "windows", goarch: "amd64" },
  { target: "linux-x64", goos: "linux", goarch: "amd64" },
  { target: "linux-arm64", goos: "linux", goarch: "arm64" },
]

export function getCurrentBellud(target = process.env.BELLUCODE_TARGET ?? nativeTarget()) {
  const config = BELLUD_BINARIES.find((item) => item.target === target)
  if (!config) throw new Error(`bellud configuration not available for target '${target}'`)
  return config
}

// Builds services/bellud with the same flags as its plain `build` script (`go build -trimpath ./cmd/bellud`)
// for the current target, writing the binary straight into resources/ so services/bellud/dist is untouched.
export async function buildBelludToResources(root: string, dest = windowsify("resources/bellud")) {
  const { $ } = await import("bun")
  const bellud = getCurrentBellud()
  const out = resolve(dest)
  const env = {
    ...process.env,
    PATH: `${process.env.PATH ?? ""}${delimiter}/usr/local/go/bin`,
    GOOS: bellud.goos,
    GOARCH: bellud.goarch,
  }
  await $`go build -trimpath -o ${out} ./cmd/bellud`.cwd(root).env(env)
  await prepareCli(out)
  console.log(`Built bellud for ${bellud.goos}/${bellud.goarch} to ${dest}`)
}

function nativeTarget() {
  const { platform, arch } = process

  if (platform === "darwin") return arch === "arm64" ? "darwin-arm64" : "darwin-x64"

  if (platform === "win32") return arch === "arm64" ? "windows-arm64" : "windows-x64"

  if (platform === "linux") return arch === "arm64" ? "linux-arm64" : "linux-x64"
  throw new Error(`Unsupported platform: ${platform}/${arch}`)
}

export function getCurrentCli(target = process.env.BELLUCODE_TARGET ?? nativeTarget()) {
  const binaryConfig = CLI_BINARIES.find((item) => item.target === target)

  if (!binaryConfig) throw new Error(`CLI configuration not available for target '${target}'`)

  return binaryConfig
}

export function nodePtyPackage(target?: string) {
  const cli = getCurrentCli(target)

  return `@lydell/node-pty-${cli.os}-${cli.cpu}`
}

export async function downloadCliToResources(version = CLI_VERSION, dest = windowsify("resources/bellucode-cli")) {
  const { $ } = await import("bun")
  const cli = getCurrentCli()
  const directory = await mkdtemp(join(tmpdir(), "bellucode-cli-"))

  try {
    await $`bun install --no-save --cwd ${directory} ${`${cli.package}@${version}`} ${`--os=${cli.os}`} ${`--cpu=${cli.cpu}`}`
    await copyCliToResources(join(directory, "node_modules", cli.package), dest)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }

  console.log(`Copied ${cli.package}@${version} to ${dest}`)
}

export async function copyBuiltCliToResources(root: string, dest = windowsify("resources/bellucode-cli")) {
  const cli = getCurrentCli()
  const directory = cli.package.replace("@bellucode/", "")
  await copyCliToResources(join(root, directory), dest)
}

// The package directory is an npm package: its package.json version is the string the executable
// prints for --version. Writing it next to the executable spares the desktop a ~400 ms spawn of the
// 200 MB binary on first launch.
async function copyCliToResources(pkg: string, dest: string) {
  const cli = getCurrentCli()
  await copyFile(join(pkg, "bin", cli.os === "win32" ? "bellucode.exe" : "bellucode"), dest)
  await prepareCli(dest)

  const manifest = Option.getOrUndefined(
    Schema.decodeUnknownOption(Manifest)(await Bun.file(join(pkg, "package.json")).text()),
  )

  if (!manifest) throw new Error(`Bundled CLI package has no version: ${pkg}`)
  await Bun.write(versionFile(dest), manifest.version)
}

export function versionFile(cli: string) {
  return join(dirname(cli), "bellucode-cli.version")
}

async function prepareCli(dest: string) {
  const { $ } = await import("bun")

  if (process.platform !== "win32") await chmod(dest, 0o755)

  if (process.platform === "darwin") await $`codesign --force --sign - ${dest}`
}

export function windowsify(path: string) {
  if (path.endsWith(".exe")) return path

  return `${path}${process.platform === "win32" ? ".exe" : ""}`
}
