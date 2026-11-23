import type {
  Component,
  DependencyType,
  Finding,
  Provider,
  Resource,
  ResourceType,
  Severity,
  Subscription,
  Tech,
} from "./model"

// Dummy data for the Findings page. Nothing here comes from a scanner.

export const PROJECT_NAMES = ["payments", "platform", "data-pipeline", "mobile-backend"] as const

/** Counts the summary cards start from, so the mock data resembles a real tenant. */
const SEVERITY_WEIGHTS: ReadonlyArray<readonly [Severity, number]> = [
  ["critical", 1162],
  ["high", 7956],
  ["medium", 14066],
  ["low", 7765],
]

// name, version, kind, dependency, tech, weight
const COMPONENTS: ReadonlyArray<readonly [string, string, string, DependencyType, Tech, number]> = [
  ["jackson-databind", "2.13.4.2", "Java Code Library", "library", "java", 30],
  ["Firefox", "146.0.1", "Hosted Technology", "library", "browser", 14],
  ["pillow", "10.3.0", "Python Code Library", "library", "python", 12],
  ["log4j-core", "2.17.1", "Java Code Library", "library", "java", 12],
  ["pyyaml", "5.4", "Python Code Library", "library", "python", 9],
  ["grafana", "8.3.0", "Go Code Library", "library", "go", 9],
  ["openssl", "1.1.1n-0+deb10u3", "DPKG OS Package", "os-package", "os", 20],
  ["libc6", "2.28-10+deb10u1", "DPKG OS Package", "os-package", "os", 20],
  ["apache2", "2.4.38-3+deb10u3", "DPKG OS Package", "os-package", "os", 10],
  ["postgresql-11", "11.16-0+deb10u1", "DPKG OS Package", "os-package", "os", 8],
  ["curl", "7.64.0-4+deb10u2", "DPKG OS Package", "os-package", "os", 14],
  ["zlib1g", "1:1.2.11.dfsg-1", "DPKG OS Package", "os-package", "os", 10],
  ["libxml2", "2.9.4+dfsg1-7+deb10u2", "DPKG OS Package", "os-package", "os", 10],
  ["busybox", "1.30.1-4", "DPKG OS Package", "os-package", "os", 6],
  ["lodash", "4.17.15", "JavaScript Code Library", "library", "javascript", 14],
  ["minimist", "1.2.5", "JavaScript Code Library", "library", "javascript", 8],
  ["express", "4.16.0", "JavaScript Code Library", "library", "javascript", 8],
  ["axios", "0.21.1", "JavaScript Code Library", "library", "javascript", 8],
  ["django", "3.2.0", "Python Code Library", "library", "python", 9],
  ["urllib3", "1.25.8", "Python Code Library", "library", "python", 9],
  ["requests", "2.19.0", "Python Code Library", "library", "python", 7],
  ["spring-core", "5.3.18", "Java Code Library", "library", "java", 9],
  ["netty-codec", "4.1.68", "Java Code Library", "library", "java", 7],
  ["tomcat-embed-core", "9.0.54", "Java Code Library", "library", "java", 7],
  ["golang.org/x/net", "0.7.0", "Go Code Library", "library", "go", 8],
  ["github.com/docker/docker", "20.10.7", "Go Code Library", "library", "go", 6],
  ["node", "14.17.0", "Hosted Technology", "library", "javascript", 6],
  ["/usr/local/bin/helm", "3.8.0", "Binary File", "file-path", "go", 5],
  ["/opt/app/lib/libssl.so.1.1", "1.1.1k", "Binary File", "file-path", "os", 5],
  ["/usr/bin/runc", "1.0.0", "Binary File", "file-path", "go", 4],
]

const CVE_DESCRIPTIONS: Record<Severity, readonly string[]> = {
  critical: [
    "Remote attackers can execute arbitrary code through a crafted request that is deserialized without validation.",
    "A path traversal flaw lets unauthenticated users read arbitrary files from the host.",
    "An out-of-bounds write allows code execution when a specially crafted file is parsed.",
  ],
  high: [
    "A crafted input triggers a heap buffer overflow that can crash the process or leak memory.",
    "Improper input validation allows an authenticated user to escalate privileges.",
    "A server-side request forgery issue lets attackers reach internal network services.",
  ],
  medium: [
    "A regular expression with catastrophic backtracking allows denial of service with a short input.",
    "Missing certificate validation in some code paths can expose traffic to interception.",
    "Sensitive data can be written to log files when verbose logging is enabled.",
  ],
  low: [
    "A timing difference in comparison may reveal limited information about secret values.",
    "Unbounded memory growth occurs on malformed headers, with limited practical impact.",
    "An informational disclosure exposes the software version in error pages.",
  ],
}

const SUBSCRIPTIONS: readonly Subscription[] = [
  { provider: "aws", name: "aws-prod-main", id: "123456789012" },
  { provider: "aws", name: "aws-staging", id: "210987654321" },
  { provider: "azure", name: "azure-corp-prod", id: "8f1c2a34-77d1-4b0e-a1c5-3c9e2d41b6aa" },
  { provider: "gcp", name: "gcp-data-platform", id: "data-platform-482910" },
  { provider: "gcp", name: "gcp-ml-sandbox", id: "ml-sandbox-117204" },
  { provider: "github", name: "acme-corp", id: "org-90412" },
]

const SERVICES = [
  "checkout-service",
  "payments-api",
  "auth-gateway",
  "inventory-sync",
  "notification-worker",
  "report-builder",
  "search-indexer",
  "user-profile",
  "billing-engine",
  "edge-proxy",
  "ml-scoring",
  "etl-runner",
]

export function generateFindings(count = 31_215, seed = 7): Finding[] {
  const random = prng(seed)
  const components = COMPONENTS.map(
    (row, index): Component => ({
      id: `cmp-${index}`,
      name: row[0],
      version: row[1],
      kind: row[2],
      dependency: row[3],
      tech: row[4],
    }),
  )
  const componentCumulative = cumulative(COMPONENTS.map((row) => row[5]))
  const resources = generateResources(random)
  const pool = generateCvePool(random)

  return Array.from({ length: count }, (_, index) => {
    const cve = pool[Math.floor(random() * pool.length)]
    const component = components[pick(componentCumulative, random())]
    // Squaring concentrates findings on a few resources, like a real estate with a few very noisy images.
    const resource = resources[Math.floor(random() ** 2 * resources.length)]
    const critical = random() < 0.55 ? Math.floor(random() ** 2 * 60) : 0
    const high = random() < 0.7 ? Math.floor(random() ** 2 * 320) : 0
    const medium = random() < 0.8 ? Math.floor(random() ** 2 * 140) : 0
    const low = random() < 0.5 ? Math.floor(random() ** 2 * 80) : 0
    const hasFix = random() < 0.55
    return {
      id: `fnd-${index}`,
      cve: cve.id,
      severity: cve.severity,
      status: "unresolved",
      resource,
      component,
      fixVersion: hasFix ? fixVersionFor(component, random) : undefined,
      exploitable: random() < 0.18,
      related: { critical, high, medium, low },
      description: cve.description,
      cvss: cve.cvss,
      searchText: `${cve.id} ${component.name} ${component.version} ${resource.name}`.toLowerCase(),
    }
  })
}

let cache: Finding[] | undefined
/** The generated dataset is built once and shared, since 30k rows cost a few tens of milliseconds. */
export function getFindings() {
  return (cache ??= generateFindings())
}

/** Related risk issues a finding links to, derived from its counts so the dataset stays small. */
export function relatedIssuesFor(finding: Finding) {
  const titles: Record<Severity, readonly string[]> = {
    critical: ["Internet-exposed workload with remote code execution", "Publicly reachable admin interface"],
    high: ["Overly permissive role attached to workload", "Secret stored in environment variable"],
    medium: ["Outdated base image", "Missing network segmentation"],
    low: ["Verbose logging enabled", "Unused open port"],
  }
  return (["critical", "high", "medium", "low"] as const).flatMap((severity) =>
    finding.related[severity] === 0
      ? []
      : titles[severity].map((title, index) => ({
          id: `${finding.id}-${severity}-${index}`,
          severity,
          title,
          count: Math.max(1, Math.round(finding.related[severity] / (index + 1))),
        })),
  )
}

function generateResources(random: () => number): Resource[] {
  const types: ResourceType[] = ["container-image", "serverless", "virtual-machine", "repository"]
  const typeCumulative = cumulative([55, 20, 15, 10])
  return Array.from({ length: 320 }, (_, index) => {
    const type = types[pick(typeCumulative, random())]
    const service = SERVICES[Math.floor(random() * SERVICES.length)]
    const subscription = subscriptionFor(type, random)
    const hex = Array.from({ length: 64 }, () => Math.floor(random() * 16).toString(16)).join("")
    const name =
      type === "container-image"
        ? `${subscription.id}.dkr.ecr.us-east-1.amazonaws.com/${PROJECT_NAMES[index % PROJECT_NAMES.length]}/${service}:${1 + (index % 4)}.${index % 20}.${index % 7}@sha256:${hex}`
        : type === "serverless"
          ? `arn:aws:lambda:us-east-1:${subscription.id}:function:${service}-${index}`
          : type === "virtual-machine"
            ? `i-0${hex.slice(0, 16)}-${service}`
            : `github.com/acme-corp/${service}-${index}`
    return { id: `res-${index}`, name, type, subscription }
  })
}

function subscriptionFor(type: ResourceType, random: () => number): Subscription {
  const providers: Provider[] = type === "repository" ? ["github"] : ["aws", "azure", "gcp"]
  const options = SUBSCRIPTIONS.filter((item) => providers.includes(item.provider))
  return options[Math.floor(random() * options.length)]
}

function generateCvePool(random: () => number) {
  const severityCumulative = cumulative(SEVERITY_WEIGHTS.map((entry) => entry[1]))
  const seen = new Set<string>(["CVE-2021-43798"])
  const pool = [
    {
      id: "CVE-2021-43798",
      severity: "high" as Severity,
      cvss: 7.5,
      description: "Grafana allows unauthenticated directory traversal through the plugin static file endpoint.",
    },
  ]
  while (pool.length < 900) {
    const id = `CVE-${2015 + Math.floor(random() * 11)}-${1000 + Math.floor(random() * 45000)}`
    if (seen.has(id)) continue
    seen.add(id)
    const severity = SEVERITY_WEIGHTS[pick(severityCumulative, random())][0]
    const descriptions = CVE_DESCRIPTIONS[severity]
    const base = { critical: 9, high: 7, medium: 4, low: 0.5 }[severity]
    pool.push({
      id,
      severity,
      cvss: Math.round((base + random() * (severity === "critical" ? 1 : 2.5)) * 10) / 10,
      description: descriptions[Math.floor(random() * descriptions.length)],
    })
  }
  return pool
}

function fixVersionFor(component: Component, random: () => number) {
  if (component.dependency === "os-package")
    return `${component.version.split(/[+-]/)[0]}+dfsg-3+deb10u${7 + Math.floor(random() * 3)}`
  const parts = component.version.split(".").map((part) => Number.parseInt(part, 10) || 0)
  parts[Math.min(1, parts.length - 1)] += 1 + Math.floor(random() * 2)
  return parts.join(".")
}

function cumulative(weights: readonly number[]) {
  const total = weights.reduce((sum, weight) => sum + weight, 0)
  return weights.reduce<number[]>((acc, weight) => [...acc, (acc.at(-1) ?? 0) + weight / total], [])
}

function pick(cumulativeWeights: readonly number[], value: number) {
  const index = cumulativeWeights.findIndex((limit) => value < limit)
  return index === -1 ? cumulativeWeights.length - 1 : index
}

// mulberry32: a small seeded generator, so every visit shows the same dataset.
function prng(seed: number) {
  let state = seed
  return () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
