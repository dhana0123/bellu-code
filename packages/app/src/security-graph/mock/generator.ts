import { areaIds, areaOrder } from "../model"
import type {
  AreaKey,
  AttackPath,
  Boundary,
  Entity,
  EntityType,
  GraphData,
  GraphDelta,
  Metadata,
  Relation,
  Relationship,
  Severity,
  Tag,
} from "../model"
import type { GraphSize } from "../source"

/** Stable ids of the reference sample. The sample is present at every size. */
export const SAMPLE_IDS = {
  loginApi: "sample:api:login",
  limApi: "sample:module:lim-api",
  limComponent: "sample:component:lim",
  loginFile: "sample:file:login-ts",
  handleLogin: "sample:function:handle-login",
  validateUser: "sample:function:validate-user",
  authService: "sample:service:auth",
  authComponent: "sample:component:auth",
  log4j: "sample:dependency:log4j",
  log4jCve: "sample:vulnerability:cve-2019-17571",
  javaLibs: "sample:component:java-libs",
  userStore: "sample:component:user-store",
  userDb: "sample:data-model:user-db",
  piiModel: "sample:data-model:pii",
  thirdParty: "sample:component:third-party",
  stripe: "sample:external:stripe",
  auth0: "sample:external:auth0",
  openai: "sample:external:openai",
  untrustedBoundary: "sample:boundary:untrusted",
  writtenToLog: "sample:rel:written-to-log",
  attackPath: "sample:attack-path:internet-to-pii",
  attackPathViaService: "sample:attack-path:internet-to-pii-via-auth",
} as const

export const sizes: Record<GraphSize, number> = { "100": 100, "5k": 5_000, "50k": 50_000 }

const observedAt = 1_700_000_000_000

const risk = (label: string): Tag => ({ label, severity: "risk" })
const info = (label: string): Tag => ({ label, severity: "info" })

type AreaSpec = { component: EntityType; mid: EntityType; leaves: EntityType[]; language?: string[] }

const areaSpecs: Record<AreaKey, AreaSpec> = {
  application: { component: "repository", mid: "module", leaves: ["file", "function", "api"], language: ["TypeScript", "Java", "Go"] },
  backend: { component: "service", mid: "module", leaves: ["file", "function", "api"], language: ["Go", "Java", "Python"] },
  frontend: { component: "repository", mid: "module", leaves: ["file", "function"], language: ["TypeScript", "JavaScript"] },
  database: { component: "cloud-resource", mid: "data-model", leaves: ["data-model", "function"], language: ["SQL"] },
  cloud: { component: "cloud-resource", mid: "cloud-resource", leaves: ["identity", "cloud-resource", "security-control"] },
  external: { component: "external-service", mid: "external-service", leaves: ["api", "external-service"] },
  dependencies: { component: "package", mid: "dependency", leaves: ["dependency", "vulnerability"] },
  security: { component: "security-control", mid: "security-control", leaves: ["security-control", "vulnerability"] },
  agents: { component: "ai-agent", mid: "ai-agent", leaves: ["ai-agent", "function"] },
}

const words = [
  "alpha", "atlas", "beacon", "cipher", "delta", "ember", "falcon", "gamma", "harbor", "iris", "jade", "kernel",
  "lumen", "matrix", "nimbus", "orbit", "prism", "quartz", "relay", "signal", "tango", "umbra", "vector", "willow",
]
const repos = ["bellu-core", "bellu-web", "payments", "identity", "ingest", "gateway", "reports", "mobile", "infra", "ml-platform", "notifier", "search"]
const envs = ["prod", "staging", "dev"]
const riskTags = ["Internet Exposed", "Sensitive Logic", "PII", "Hardcoded Secret", "Outdated Dependency"]
const relationPool: Relation[] = ["calls", "calls", "reads", "writes", "uses", "depends_on", "exposes", "assumes"]
const filledSeverities: Severity[] = ["low", "medium", "high", "info", "remediated", "validated"]
const vulnSeverities: Severity[] = ["critical", "high", "high", "medium", "medium", "low"]

/** Deterministic PRNG (mulberry32). */
function seeded(seed: number) {
  let a = seed >>> 0
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  return {
    next,
    int: (n: number) => Math.floor(next() * n),
    pick: <T>(list: readonly T[]) => list[Math.floor(next() * list.length)] as T,
  }
}

const seeds: Record<GraphSize, number> = { "100": 1001, "5k": 5005, "50k": 50050 }

/** Pure, deterministic and iterative: the same size always yields the same graph. */
export function generateGraph(size: GraphSize): GraphData {
  const target = sizes[size]
  const rng = seeded(seeds[size])
  const entities: Entity[] = []
  const relationships: Relationship[] = []
  const boundaries: Boundary[] = []
  const attackPaths: AttackPath[] = []
  const leaves: Entity[] = []
  const boundaryMembers: Record<string, string[]> = { "boundary:trusted": [], "boundary:public": [] }
  let ids = 0
  let rels = 0

  const rel = (id: string, source: string, target: string, relation: Relation, metadata: Metadata = {}) => {
    relationships.push({ id, source, target, relation, directed: true, metadata })
    return id
  }
  const nextRel = (source: string, target: string, relation: Relation, metadata: Metadata = {}) =>
    rel(`rel:${rels++}`, source, target, relation, metadata)

  const put = (e: Omit<Entity, "tags" | "metadata" | "provenance"> & Partial<Pick<Entity, "tags" | "metadata">>) => {
    const entity: Entity = {
      tags: [],
      metadata: {},
      ...e,
      provenance: { source: "mock", observedAt },
    }
    entities.push(entity)
    return entity
  }

  // L1 areas
  for (const key of areaOrder) {
    put({
      id: areaIds[key],
      type: "cluster",
      name: areaLabels[key],
      tags: [],
      metadata: { area: key },
    })
  }

  addSample(put, rel, boundaries, attackPaths, leaves, boundaryMembers)

  // Filler hierarchy, area > component > module/service > file/function.
  const full = () => entities.length >= target
  const component = (key: AreaKey) => {
    const spec = areaSpecs[key]
    const repo = rng.pick(repos)
    const env = rng.pick(envs)
    const service = `${rng.pick(words)}-svc`
    const language = spec.language ? rng.pick(spec.language) : undefined
    const ctx = { repo, env, service, language }
    const comp = put({
      id: `n:${ids++}`,
      type: spec.component,
      name: `${cap(rng.pick(words))} ${cap(rng.pick(words))}`,
      parentId: areaIds[key],
      ...ctx,
      tags: language ? [info(language)] : [],
    })
    if (key === "backend" || key === "database") comp.boundaryId = "boundary:trusted"
    if (key === "frontend") comp.boundaryId = "boundary:public"
    if (comp.boundaryId) boundaryMembers[comp.boundaryId]?.push(comp.id)
    const mids = 2 + rng.int(4)
    for (let m = 0; m < mids && !full(); m++) {
      const mid = put({
        id: `n:${ids++}`,
        type: spec.mid,
        name: `${cap(rng.pick(words))}${cap(rng.pick(words))}`,
        parentId: comp.id,
        ...ctx,
        boundaryId: comp.boundaryId,
      })
      const count = 3 + rng.int(10)
      for (let l = 0; l < count && !full(); l++) leaves.push(leaf(mid, spec, key, ctx))
    }
  }

  const leaf = (parent: Entity, spec: AreaSpec, key: AreaKey, ctx: Pick<Entity, "repo" | "env" | "service" | "language">) => {
    const type = rng.pick(spec.leaves)
    const id = `n:${ids++}`
    const tags: Tag[] = []
    const metadata: Metadata = {}
    if (ctx.language && (type === "file" || type === "function")) tags.push(info(ctx.language))
    if (rng.next() < 0.06) tags.push(risk(rng.pick(riskTags)))
    if (key === "external" && type === "external-service") {
      tags.push(info("External"))
      metadata.secretRef = `vault://mock/${id}`
    }
    if ((type === "identity" || type === "cloud-resource") && rng.next() < 0.3) metadata.secretRef = `vault://mock/${id}`
    if (type === "vulnerability") metadata.cve = `CVE-20${10 + rng.int(15)}-${1000 + rng.int(9000)}`
    const severity =
      type === "vulnerability"
        ? rng.pick(vulnSeverities)
        : rng.next() < 0.05
          ? rng.pick(filledSeverities)
          : undefined
    const entity = put({
      id,
      type,
      name: type === "function" ? `${rng.pick(words)}${cap(rng.pick(words))}()` : `${rng.pick(words)}-${rng.pick(words)}`,
      parentId: parent.id,
      repo: ctx.repo,
      env: ctx.env,
      service: ctx.service,
      language: ctx.language,
      severity,
      tags,
      metadata,
      boundaryId: parent.boundaryId,
      sourceLocation:
        type === "file" || type === "function" ? { path: `src/${ctx.service}/${id.slice(2)}.ts`, line: 1 + rng.int(400) } : undefined,
    })
    return entity
  }

  while (!full()) {
    const before = entities.length
    for (const key of areaOrder) {
      if (full()) break
      component(key)
    }
    if (entities.length === before) break
  }

  // Cross-cutting relationships between leaves.
  const pool = leaves
  for (let i = 0; i < pool.length; i++) {
    if (rng.next() > 0.9) continue
    const src = pool[i]!
    const tgt = pool[rng.int(pool.length)]!
    if (src.id === tgt.id) continue
    nextRel(src.id, tgt.id, rng.pick(relationPool))
  }

  // Filler attack paths: random walks from Internet Exposed leaves.
  const adjacency = new Map<string, Relationship[]>()
  for (const r of relationships) {
    const list = adjacency.get(r.source)
    if (list) list.push(r)
    else adjacency.set(r.source, [r])
  }
  const wantPaths = Math.max(2, Math.floor(target / 500))
  for (let attempt = 0, made = 0; attempt < wantPaths * 20 && made < wantPaths && pool.length > 0; attempt++) {
    const entry = pool[rng.int(pool.length)]!
    const steps: string[] = []
    const seen = new Set<string>([entry.id])
    let at = entry.id
    for (let hop = 0; hop < 4; hop++) {
      const out = adjacency.get(at)?.filter((r) => !seen.has(r.target))
      if (!out || out.length === 0) break
      const step = rng.pick(out)
      steps.push(step.id)
      seen.add(step.target)
      at = step.target
    }
    if (steps.length < 2) continue
    const last = entities.find((e) => e.id === at)
    if (!last) continue
    if (!entry.tags.some((t) => t.label === "Internet Exposed")) entry.tags.push(risk("Internet Exposed"))
    if (!last.tags.some((t) => t.label === "PII")) last.tags.push(risk("PII"))
    attackPaths.push({
      id: `path:${made}`,
      steps,
      entry: entry.id,
      target: at,
      severity: rng.pick<Severity>(["critical", "high", "medium"]),
      evidence: [`Reachable from ${entry.name} in ${steps.length} hops`],
      remediation: "Restrict the exposed entry point and require authorization on the intermediate calls.",
    })
    made++
  }

  const trusted = boundaryMembers["boundary:trusted"] ?? []
  boundaries.push(
    { id: "boundary:trusted", label: "Trusted network", memberIds: trusted },
    { id: "boundary:public", label: "Public edge", memberIds: boundaryMembers["boundary:public"] ?? [] },
  )

  return { entities, relationships, boundaries, attackPaths }
}

/** Deterministic delta for `GraphSource.subscribe`: a new finding on the sample validateUser function. */
export function generateDelta(data: GraphData, n: number): GraphDelta {
  const parent = data.entities.find((e) => e.id === SAMPLE_IDS.validateUser)
  const id = `delta:finding:${n}`
  const entity: Entity = {
    id,
    type: "vulnerability",
    name: `Finding ${n}: unvalidated input`,
    parentId: parent ? parent.id : areaIds.security,
    severity: n % 2 === 0 ? "high" : "medium",
    tags: [risk("Sensitive Logic")],
    metadata: { cve: `CVE-2024-${9000 + n}` },
    provenance: { source: "mock", observedAt: observedAt + n * 1000 },
  }
  const relationships: Relationship[] = parent
    ? [{ id: `delta:rel:${n}`, source: parent.id, target: id, relation: "exposes", directed: true, metadata: {} }]
    : []
  return { entities: [entity], relationships }
}

const areaLabels: Record<AreaKey, string> = {
  application: "Application",
  backend: "Backend",
  frontend: "Frontend",
  database: "Database",
  cloud: "Cloud Infrastructure",
  external: "External APIs",
  dependencies: "Dependencies",
  security: "Security",
  agents: "AI Agents",
}

function cap(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

type Put = (
  e: Omit<Entity, "tags" | "metadata" | "provenance"> & Partial<Pick<Entity, "tags" | "metadata">>,
) => Entity
type Rel = (id: string, source: string, target: string, relation: Relation, metadata?: Metadata) => string

function addSample(
  put: Put,
  rel: Rel,
  boundaries: Boundary[],
  attackPaths: AttackPath[],
  leaves: Entity[],
  boundaryMembers: Record<string, string[]>,
) {
  const S = SAMPLE_IDS
  // Application: Lim module with the /login API.
  put({ id: S.limComponent, type: "repository", name: "Lim", parentId: areaIds.application, repo: "lim", env: "prod", language: "Java", tags: [info("Java")] })
  put({ id: S.limApi, type: "module", name: "Lim.API", parentId: S.limComponent, repo: "lim", env: "prod", language: "Java", tags: [info("Java")] })
  put({
    id: S.loginApi,
    type: "api",
    name: "/login",
    parentId: S.limApi,
    repo: "lim",
    service: "lim-api",
    env: "prod",
    language: "Java",
    severity: "high",
    tags: [risk("Internet Exposed"), info("POST")],
    metadata: { method: "POST", path: "/login" },
  })
  put({ id: S.loginFile, type: "file", name: "login.ts", parentId: S.limApi, repo: "lim", service: "lim-api", env: "prod", language: "TypeScript", tags: [info("TypeScript")], sourceLocation: { path: "src/auth/login.ts", line: 1 } })
  const handle = put({ id: S.handleLogin, type: "function", name: "handleLogin()", parentId: S.loginFile, repo: "lim", service: "lim-api", env: "prod", language: "TypeScript", tags: [risk("Sensitive Logic")], sourceLocation: { path: "src/auth/login.ts", line: 12 } })
  const validate = put({ id: S.validateUser, type: "function", name: "validateUser()", parentId: S.loginFile, repo: "lim", service: "lim-api", env: "prod", language: "TypeScript", severity: "medium", tags: [risk("Sensitive Logic")], sourceLocation: { path: "src/auth/login.ts", line: 48 } })

  // Backend: auth service.
  put({ id: S.authComponent, type: "service", name: "Auth", parentId: areaIds.backend, repo: "lim", env: "prod", boundaryId: "boundary:trusted" })
  put({ id: S.authService, type: "service", name: "Auth Service", parentId: S.authComponent, repo: "lim", service: "auth", env: "prod", boundaryId: "boundary:trusted", tags: [info("Go")] })
  boundaryMembers["boundary:trusted"]!.push(S.authComponent)

  // Database: PII model.
  put({ id: S.userStore, type: "cloud-resource", name: "User Store", parentId: areaIds.database, env: "prod", boundaryId: "boundary:trusted" })
  put({ id: S.userDb, type: "data-model", name: "UserDB", parentId: S.userStore, env: "prod", boundaryId: "boundary:trusted" })
  put({ id: S.piiModel, type: "data-model", name: "UserProfile", parentId: S.userDb, env: "prod", severity: "high", boundaryId: "boundary:trusted", tags: [risk("PII")], metadata: { fields: "email,name,address" } })
  boundaryMembers["boundary:trusted"]!.push(S.userStore)

  // Dependencies: log4j with a Critical CVE.
  put({ id: S.javaLibs, type: "package", name: "Java Libraries", parentId: areaIds.dependencies, language: "Java" })
  const log4j = put({
    id: S.log4j,
    type: "dependency",
    name: "log4j:log4j 1.2.12",
    parentId: S.javaLibs,
    language: "Java",
    severity: "critical",
    tags: [risk("Outdated Dependency")],
    metadata: { group: "log4j", artifact: "log4j", version: "1.2.12" },
  })
  put({
    id: S.log4jCve,
    type: "vulnerability",
    name: "CVE-2019-17571",
    parentId: S.log4j,
    severity: "critical",
    tags: [risk("Critical CVE")],
    metadata: { cve: "CVE-2019-17571", cvss: 9.8 },
  })

  // External services inside the Untrusted boundaries boundary.
  put({ id: S.thirdParty, type: "external-service", name: "Third-party APIs", parentId: areaIds.external, boundaryId: S.untrustedBoundary })
  const external = [
    put({ id: S.stripe, type: "external-service", name: "Stripe", parentId: S.thirdParty, boundaryId: S.untrustedBoundary, tags: [info("External")], metadata: { brand: "stripe", secretRef: "vault://mock/stripe-key" } }),
    put({ id: S.auth0, type: "external-service", name: "Auth0", parentId: S.thirdParty, boundaryId: S.untrustedBoundary, tags: [info("External")], metadata: { brand: "auth0", secretRef: "vault://mock/auth0-client" } }),
    put({ id: S.openai, type: "external-service", name: "OpenAI", parentId: S.thirdParty, boundaryId: S.untrustedBoundary, tags: [info("External")], metadata: { brand: "openai", secretRef: "vault://mock/openai-key" } }),
  ]
  boundaries.push({ id: S.untrustedBoundary, label: "Untrusted boundaries", memberIds: [S.thirdParty, ...external.map((e) => e.id)] })

  // Relationships.
  const callHandle = rel("sample:rel:login-handle", S.loginApi, handle.id, "calls")
  const callValidate = rel("sample:rel:handle-validate", handle.id, validate.id, "calls")
  const readPii = rel("sample:rel:validate-pii", validate.id, S.piiModel, "reads")
  rel(S.writtenToLog, handle.id, log4j.id, "writes", { label: "Written to log" })
  rel("sample:rel:handle-auth0", handle.id, S.auth0, "calls")
  rel("sample:rel:handle-stripe", handle.id, S.stripe, "calls")
  rel("sample:rel:handle-openai", handle.id, S.openai, "calls")
  const loginAuth = rel("sample:rel:login-auth", S.loginApi, S.authService, "calls")
  const authPii = rel("sample:rel:auth-pii", S.authService, S.piiModel, "reads")

  attackPaths.push(
    {
      id: S.attackPath,
      steps: [callHandle, callValidate, readPii],
      entry: S.loginApi,
      target: S.piiModel,
      severity: "critical",
      evidence: ["/login is reachable from the internet without a WAF", "validateUser() reads the UserProfile PII model", "PII is also written to the log4j 1.2.12 logger"],
      remediation: "Require authentication before validateUser(), stop writing PII to logs and upgrade log4j.",
    },
    {
      id: S.attackPathViaService,
      steps: [loginAuth, authPii],
      entry: S.loginApi,
      target: S.piiModel,
      severity: "high",
      evidence: ["Auth Service reads UserProfile on behalf of /login"],
      remediation: "Scope the Auth Service database role to the columns it needs.",
    },
  )
  leaves.push(handle, validate)
}
