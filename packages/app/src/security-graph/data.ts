import type { GraphData } from "./model"

/** Dummy attack-surface graph. A real source replaces it later; the shape stays the same. */
export const GRAPH_DATA: GraphData = {
  nodes: [
    { id: "m-lim", kind: "module", name: "Lim.API", importance: 1, count: 23, language: "csharp", tags: ["internet-exposed", "used-in-code"] },
    { id: "m-auth", kind: "module", name: "Auth.Gateway", importance: 0.95, count: 12, language: "csharp", tags: ["internet-exposed"] },
    { id: "m-ord", kind: "module", name: "Orders.Service", importance: 0.9, count: 8, language: "java", tags: ["used-in-code"] },
    { id: "m-pay", kind: "module", name: "Payments.Core", importance: 1, count: 5, language: "java", tags: ["sensitive-logic", "pii"] },
    { id: "m-notif", kind: "module", name: "Notifier", importance: 0.6, count: 3, language: "csharp", tags: ["test-logic"] },

    { id: "api-login", kind: "api", name: "/login", importance: 0.85, tags: ["internet-exposed", "sensitive-logic"] },
    { id: "api-orders", kind: "api", name: "/orders", importance: 0.75, tags: ["internet-exposed"] },
    { id: "api-charge", kind: "api", name: "/payments/charge", importance: 0.85, count: 2, tags: ["internet-exposed", "pii"] },
    { id: "api-users", kind: "api", name: "/users/{id}", importance: 0.7, tags: ["pii", "written-to-log"] },
    { id: "api-ai", kind: "api", name: "/ai/summarize", importance: 0.6, tags: ["sensitive-logic"] },
    { id: "api-health", kind: "api", name: "/health", importance: 0.3, tags: ["used-in-code"] },

    { id: "dm-customer", kind: "data-model", name: "Customer", importance: 0.8, count: 14, tags: ["pii", "written-to-log"] },
    { id: "dm-order", kind: "data-model", name: "Order", importance: 0.6 },
    { id: "dm-payment", kind: "data-model", name: "PaymentMethod", importance: 0.8, tags: ["pii", "sensitive-logic"] },
    { id: "dm-session", kind: "data-model", name: "Session", importance: 0.5, tags: ["writes-to-log"] },

    { id: "dep-log4j", kind: "dependency", name: "log4j:log4j: 1.2.12", importance: 0.45, tags: ["writes-to-log"] },
    { id: "dep-jackson", kind: "dependency", name: "jackson-databind: 2.9.8", importance: 0.4, tags: ["used-in-code"] },
    { id: "dep-express", kind: "dependency", name: "express: 4.17.1", importance: 0.35, tags: ["used-in-code"] },
    { id: "dep-lodash", kind: "dependency", name: "lodash: 4.17.15", importance: 0.25 },
    { id: "dep-axios", kind: "dependency", name: "axios: 0.21.0", importance: 0.25 },

    { id: "idep-auth", kind: "internal-dependency", name: "internal-auth-sdk", importance: 0.5, count: 4 },
    { id: "idep-shared", kind: "internal-dependency", name: "shared-utils", importance: 0.4 },

    { id: "fw-aspnet", kind: "framework", name: "ASP.NET Core", importance: 0.6, tags: ["used-in-code"] },
    { id: "fw-spring", kind: "framework", name: "Spring Boot", importance: 0.6, tags: ["used-in-code"] },
    { id: "fw-react", kind: "framework", name: "React", importance: 0.5, tags: ["web-client"] },

    { id: "svc-stripe", kind: "service", name: "Stripe", importance: 0.9, brand: "stripe" },
    { id: "svc-auth0", kind: "service", name: "Auth0", importance: 0.9, brand: "auth0" },
    { id: "svc-openai", kind: "service", name: "OpenAI", importance: 0.9, brand: "openai" },
  ],
  edges: [
    { source: "m-lim", target: "api-login", kind: "contains" },
    { source: "m-lim", target: "api-health", kind: "contains" },
    { source: "m-lim", target: "api-ai", kind: "contains", curvature: 0.12 },
    { source: "m-auth", target: "api-users", kind: "contains" },
    { source: "m-ord", target: "api-orders", kind: "contains" },
    { source: "m-pay", target: "api-charge", kind: "contains" },
    { source: "m-ord", target: "dm-order", kind: "contains", curvature: -0.1 },

    { source: "api-users", target: "dm-customer", kind: "uses" },
    { source: "api-orders", target: "dm-order", kind: "uses" },
    { source: "api-charge", target: "dm-payment", kind: "uses" },
    { source: "api-login", target: "dm-session", kind: "uses" },
    { source: "dm-order", target: "dm-customer", kind: "uses", curvature: 0.14 },

    { source: "m-lim", target: "fw-aspnet", kind: "uses" },
    { source: "m-auth", target: "fw-aspnet", kind: "uses" },
    { source: "m-notif", target: "fw-aspnet", kind: "uses" },
    { source: "m-ord", target: "fw-spring", kind: "uses" },
    { source: "m-pay", target: "fw-spring", kind: "uses" },
    { source: "fw-react", target: "api-login", kind: "uses", curvature: -0.12 },
    { source: "fw-react", target: "api-orders", kind: "uses" },

    { source: "m-pay", target: "dep-log4j", kind: "uses" },
    { source: "m-ord", target: "dep-log4j", kind: "uses" },
    { source: "m-pay", target: "dep-jackson", kind: "uses" },
    { source: "m-ord", target: "dep-jackson", kind: "uses" },
    { source: "m-lim", target: "dep-axios", kind: "uses" },
    { source: "m-lim", target: "dep-lodash", kind: "uses" },
    { source: "m-notif", target: "dep-express", kind: "uses" },
    { source: "m-notif", target: "dep-lodash", kind: "uses" },

    { source: "m-lim", target: "idep-auth", kind: "uses" },
    { source: "m-auth", target: "idep-auth", kind: "uses" },
    { source: "idep-auth", target: "idep-shared", kind: "uses" },
    { source: "m-ord", target: "idep-shared", kind: "uses" },
    { source: "m-pay", target: "idep-shared", kind: "uses" },

    { source: "m-pay", target: "svc-stripe", kind: "uses" },
    { source: "m-auth", target: "svc-auth0", kind: "uses" },
    { source: "api-ai", target: "svc-openai", kind: "uses" },
  ],
}
