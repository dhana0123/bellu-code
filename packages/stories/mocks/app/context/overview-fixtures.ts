// Security Overview responses for stories: `?args=scenario:<name>` picks one, and the fake SDK serves it.
const titles = [
  ["cloud_infrastructure", "Cloud infrastructure", "Resources and networks", "connector"],
  ["identity", "Identity", "Users and permissions", "connector"],
  ["vulnerabilities", "Vulnerabilities", "CVEs and packages", "scanner"],
  ["network_exposure", "Network exposure", "Connectivity and reachability", "connector"],
  ["secrets", "Secrets", "Credentials and access", "scanner"],
  ["data_security", "Data security", "Databases and sensitive data", "connector"],
  ["code_and_dependencies", "Code and dependencies", "Repositories and IaC", "connector"],
  ["runtime", "Runtime", "Activity and threats", "scanner"],
  ["ai_security", "AI security", "Models and agents", "connector"],
] as const
const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
const severities = ["critical", "high", "medium", "low", "info"] as const
function category(index: number, populated: boolean) {
  const [id, title, subtitle, source] = titles[index]!
  return {
    category: id,
    title,
    subtitle,
    entityCount: populated ? 1200 + index : 0,
    // Populated cards cycle through a different number of issues (0 to 3) and leave some severities at zero.
    severity: populated ? { ...zero, critical: index % 3, high: index + 1, info: 7 } : zero,
    topIssues: populated
      ? Array.from({ length: index % 4 }, (_, issue) => ({
          id: `${id}-issue-${issue}`,
          title: `${title} issue ${issue + 1}`,
          severity: severities[issue]!,
          riskScore: 90 - issue * 10,
        }))
      : [],
    emptyState: populated ? undefined : { missingSource: source, setupLink: "/security/connectors" },
    kinds: {},
  }
}
export function overviewFixture(scenario: string) {
  // `mixed` leaves every third category without a feeding source.
  return {
    revision: 1,
    categories: titles.map((_, index) => category(index, scenario === "empty" ? false : scenario !== "mixed" || index % 3 !== 2)),
  }
}
