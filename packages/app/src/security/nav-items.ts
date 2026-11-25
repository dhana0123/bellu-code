// The security pages the sidebar lists, in order. Only built pages belong here; add the rest as they ship.
export const SECURITY_PAGES = [
  // Listed only while the `security_overview` flag is on; see `useSecurityNav`.
  { page: "overview", icon: "security-dashboard", label: "home.security.overview" },
  { page: "graph", icon: "security-graph", label: "home.security.graph" },
  { page: "findings", icon: "security-findings", label: "home.security.findings" },
  // Listed only while the `security_scanners` flag is on; see `useSecurityNav`.
  { page: "bom", icon: "security-sbom", label: "security.nav.bom" },
  // Listed only while the `security_scanners` flag is on; see `useSecurityNav`.
  { page: "scanners", icon: "security-scanners", label: "home.security.scanners" },
  // Listed only while the `security_posture` flag is on; see `useSecurityNav`.
  { page: "issues", icon: "security-issues", label: "home.security.issues" },
  { page: "connectors", icon: "plug", label: "settings.connectors.title" },
] as const

export type SecurityPage = (typeof SECURITY_PAGES)[number]["page"]

export const securityPath = (page: SecurityPage) => `/security/${page}`

export const isSecurityPage = (value: string | undefined): value is SecurityPage =>
  SECURITY_PAGES.some((item) => item.page === value)

// Pages that are not built yet. Each one announces that it is coming soon instead of opening a route.
export const SECURITY_SOON = [
  { icon: "security-threat", label: "home.security.threatScore" },
  { icon: "server", label: "security.nav.inventory" },
  { icon: "security-agents", label: "home.security.agents" },
  { icon: "security-simulations", label: "home.security.simulations" },
] as const

// Shown first among the unbuilt pages while the Overview page is off.
export const SECURITY_DASHBOARDS_SOON = { icon: "security-dashboard", label: "home.security.dashboards" } as const
