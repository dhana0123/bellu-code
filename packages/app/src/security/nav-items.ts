// The security pages the sidebar lists, in order. Only built pages belong here; add the rest as they ship.
export const SECURITY_PAGES = [
  { page: "graph", icon: "security-graph", label: "home.security.graph" },
  { page: "findings", icon: "security-findings", label: "home.security.findings" },
  { page: "connectors", icon: "plug", label: "settings.connectors.title" },
] as const

export type SecurityPage = (typeof SECURITY_PAGES)[number]["page"]

export const securityPath = (page: SecurityPage) => `/security/${page}`

export const isSecurityPage = (value: string | undefined): value is SecurityPage =>
  SECURITY_PAGES.some((item) => item.page === value)

// Pages that are not built yet. Each one announces that it is coming soon instead of opening a route.
export const SECURITY_SOON = [
  { icon: "security-dashboard", label: "home.security.dashboards" },
  { icon: "security-issues", label: "home.security.issues" },
  { icon: "security-threat", label: "home.security.threatScore" },
  { icon: "security-sbom", label: "security.nav.sbom" },
  { icon: "cube", label: "security.nav.bom" },
  { icon: "server", label: "security.nav.inventory" },
  { icon: "security-scanners", label: "home.security.scanners" },
  { icon: "security-agents", label: "home.security.agents" },
  { icon: "security-simulations", label: "home.security.simulations" },
] as const
