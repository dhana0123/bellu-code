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
} as const satisfies Record<NodeKind, string>

/** Type label of each node kind. A service has none: it shows its category instead. */
export const KIND_KEY = {
  api: "security.graph.kind.api",
  "data-model": "security.graph.kind.dataModel",
  dependency: "security.graph.kind.dependency",
  "internal-dependency": "security.graph.kind.internalDependency",
  module: "security.graph.kind.module",
  framework: "security.graph.kind.framework",
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
} as const satisfies Record<EdgeKind, Key>

export const BOUNDARY_KEY = "security.graph.boundary" as const satisfies Key
export type { Key as GraphKey }
