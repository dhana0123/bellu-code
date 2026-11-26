#!/usr/bin/env bun
import { $ } from "bun"
import { exists } from "node:fs/promises"
import path from "node:path"
import {
  buildBelludToResources,
  copyBuiltCliToResources,
  downloadCliToResources,
  getCurrentCli,
  resolveChannel,
} from "./utils"
import { verifyBundles, verifyResources } from "./verify-bundles"

// Prepares resources/ (icons, metainfo, the bundled CLI, the bellud sidecar) for BELLUCODE_CHANNEL and builds the app into out/.
// The CLI comes from ../cli/dist when it holds the target; otherwise dev downloads the published dev CLI,
// beta the beta CLI, and prod fails.
const dir = path.resolve(import.meta.dir, "..")

const cli = path.resolve(dir, "../cli/dist")

const channel = resolveChannel()

process.chdir(dir)

await $`bun ./script/copy-icons.ts ${channel}`

await $`bun ./script/copy-metainfo.ts ${channel}`

const built = await exists(path.join(cli, getCurrentCli().package.replace("@bellucode/", "")))

if (channel === "prod" && !built)
  throw new Error(`Production desktop builds bundle the CLI from ${cli}; build it first`)

if (built) await copyBuiltCliToResources(cli)

if (!built) await downloadCliToResources(channel === "beta" ? "beta" : undefined)
// bellud is the sidecar server; it spawns the bellucode-cli binary copied above, so both must be in resources/.
await buildBelludToResources(path.resolve(dir, "../../services/bellud"))

await verifyResources(path.join(dir, "resources"), getCurrentCli().os)

await $`bunx electron-vite build`

await verifyBundles(path.join(dir, "out"))
