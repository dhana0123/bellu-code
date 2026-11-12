import type { WslBellucodeCheck, WslServersState } from "./contract"

/** A configured distro's settings row, from main's state alone. A server still starting can be updated or removed. */
export function wslRowView(state: WslServersState | undefined, distro: string) {
  const job = state?.distroJobs[distro]
  const check = state?.bellucodeChecks[distro]
  const action = bellucodeAction(check)
  const runtime = state?.servers.find((item) => item.config.distro === distro)?.runtime.kind
  const free = !job || job === "starting"

  return {
    version: check?.version ?? null,
    button: action ? { label: job === "updating" ? "server.updating" : action, disabled: !free } : null,
    retry: !job && (runtime === "failed" || runtime === "stopped"),
    removable: free,
  }
}

function bellucodeAction(check: WslBellucodeCheck | undefined) {
  if (!check) return

  if (!check.resolvedPath) return "onboarding.installBellucode"

  if (check.matchesDesktop === false) return "onboarding.updateBellucode"
}
