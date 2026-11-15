import type { useLanguage } from "@/runtime/i18n/language"
import type { Brand, EdgeKind, NodeKind, Tag } from "./model"

/** A key `language.t` accepts: plural variants go through `language.plural`. */
type Key = Parameters<ReturnType<typeof useLanguage>["t"]>[0]

/** Radius in pixels of the node circle at the default zoom, before the importance adjustment. */
export const NODE_RADIUS = 24

// Node fills encode the type and stay the same in every theme. All other colors come from the theme tokens (graph.css).
export const KIND_COLOR = {
  api: "#2F5597",
  "data-model": "#F5A623",
  dependency: "#8B6FE0",
  "internal-dependency": "#8B6FE0",
  module: "#16B8A6",
  framework: "#2FC9B8",
  // A service has no fill of its own: it takes the theme's raised surface, read by the renderer.
  service: "#FFFFFF",
  repository: "#3B82C4",
  "cloud-resource": "#E8833A",
  package: "#8B6FE0",
  vulnerability: "#D64550",
  account: "#4C6A92",
} as const satisfies Record<NodeKind, string>

/** Type label of each node kind. A service has none: it shows its category instead. */
export const KIND_KEY = {
  api: "security.graph.kind.api",
  "data-model": "security.graph.kind.dataModel",
  dependency: "security.graph.kind.dependency",
  "internal-dependency": "security.graph.kind.internalDependency",
  module: "security.graph.kind.module",
  framework: "security.graph.kind.framework",
  repository: "security.graph.kind.repository",
  "cloud-resource": "security.graph.kind.cloudResource",
  package: "security.graph.kind.package",
  vulnerability: "security.graph.kind.vulnerability",
  account: "security.graph.kind.account",
} as const satisfies Record<Exclude<NodeKind, "service">, Key>

export const CATEGORY_KEY = {
  stripe: "security.graph.category.payment",
  auth0: "security.graph.category.authentication",
  openai: "security.graph.category.generativeAi",
} as const satisfies Record<Brand, Key>

export const BRAND_NAME = { stripe: "Stripe", auth0: "Auth0", openai: "OpenAI" } as const satisfies Record<Brand, string>

export const TAG_KEY = {
  "internet-exposed": "security.graph.tag.internetExposed",
  "sensitive-logic": "security.graph.tag.sensitiveLogic",
  pii: "security.graph.tag.pii",
  "written-to-log": "security.graph.tag.writtenToLog",
  "used-in-code": "security.graph.tag.usedInCode",
  "test-logic": "security.graph.tag.testLogic",
  "web-client": "security.graph.tag.webClient",
  "writes-to-log": "security.graph.tag.writesToLog",
} as const satisfies Record<Tag, Key>

/** Red is reserved for risk. Every other tag is neutral. */
export const RISK_TAGS: ReadonlySet<Tag> = new Set(["internet-exposed", "sensitive-logic", "pii", "written-to-log"])

export const EDGE_KEY = {
  uses: "security.graph.edge.uses",
  contains: "security.graph.edge.contains",
  runs_on: "security.graph.edge.runs_on",
  on: "security.graph.edge.on",
  owned_by: "security.graph.edge.owned_by",
  attached_to: "security.graph.edge.attached_to",
  mounts: "security.graph.edge.mounts",
  depends_on: "security.graph.edge.depends_on",
  resolves_to: "security.graph.edge.resolves_to",
  found_in: "security.graph.edge.found_in",
  affected_by: "security.graph.edge.affected_by",
  same_as: "security.graph.edge.same_as",
  likely_same_as: "security.graph.edge.likely_same_as",
  related: "security.graph.edge.related",
} as const satisfies Record<EdgeKind, Key>

export const BOUNDARY_KEY = "security.graph.boundary" as const satisfies Key
export type { Key as GraphKey }

/** Lens names and descriptions the app has copy for. A lens id outside this map shows the name the server sends. */
export const LENS_KEY = {
  "code-to-cloud": {
    name: "security.graph.lens.code-to-cloud.name",
    description: "security.graph.lens.code-to-cloud.description",
  },
  cloud: { name: "security.graph.lens.cloud.name", description: "security.graph.lens.cloud.description" },
  "blast-radius": {
    name: "security.graph.lens.blast-radius.name",
    description: "security.graph.lens.blast-radius.description",
  },
  "attack-path": {
    name: "security.graph.lens.attack-path.name",
    description: "security.graph.lens.attack-path.description",
  },
  "vulnerability-reachability": {
    name: "security.graph.lens.vulnerability-reachability.name",
    description: "security.graph.lens.vulnerability-reachability.description",
  },
} as const satisfies Record<string, { name: Key; description: Key }>
