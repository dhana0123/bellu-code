// Pure helpers for launching `bellud`, the Sidecar_Server. Kept free of Electron so they can be unit tested.
//
// bellud's contract (services/bellud/cmd/bellud/main.go):
//   - `serve --hostname H --port P` plus `--cli-bin PATH` (compiled bellucode-cli) or `--repo DIR` (bun + packages/cli).
//   - Basic auth with username `bellucode` and the password from BELLUCODE_PASSWORD; with no password every request is rejected.
//   - It writes no registration file. It logs `[bellud] <date> <time> listening on <host:port>` to stderr once serving.

export const BELLUD_USERNAME = "bellucode"

export function belludExecutableName(platform: NodeJS.Platform = process.platform) {
  return platform === "win32" ? "bellud.exe" : "bellud"
}

export interface BelludTarget {
  /** Compiled bellucode-cli binary that bellud spawns. */
  readonly cliBinary?: string
  /** Repository root containing packages/cli, for development runs that use bun. */
  readonly repo?: string
}

export function belludArgs(target: BelludTarget) {
  const args = ["serve", "--hostname", "127.0.0.1", "--port", "0"]

  if (target.cliBinary) return [...args, "--cli-bin", target.cliBinary]
  if (target.repo) return [...args, "--repo", target.repo]
  throw new Error("bellud needs a bellucode-cli binary or a repository root")
}

/** The origin from a bellud `listening on` log line, or undefined for any other line. */
export function parseListening(line: string) {
  const match = /^\[bellud\] .*\blistening on (\S+:\d+)\s*$/.exec(line)
  const address = match?.[1]

  if (!address) return undefined
  const origin = `http://${address}`

  return URL.canParse(origin) ? new URL(origin).origin : undefined
}
