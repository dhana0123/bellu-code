import { Cve } from "@bellucode/schema/cve"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, UnknownError] as const
const mode = Schema.optional(Cve.Mode).annotate({ description: "Data source: db, graph or both. Graph modes need the security_cve_graph flag." })
const positive = Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1))))

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.cve.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.cve`: routes under /api/experimental/cve, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 * The static paths are declared before `/:id` so they are never matched as an id.
 */
export const ExperimentalCveGroup = HttpApiGroup.make("server.cve")
  .add(
    HttpApiEndpoint.get("lookup", "/api/experimental/cve/lookup", {
      query: {
        id: Schema.optional(Schema.String).annotate({ description: "CVE or alias identifier." }),
        purl: Schema.optional(Schema.String).annotate({ description: "Package URL." }),
        version: Schema.optional(Schema.String).annotate({ description: "Package version." }),
        cpe: Schema.optional(Schema.String).annotate({ description: "CPE string." }),
        mode,
      },
      success: Cve.LookupResult,
      error: errors,
    }).annotateMerge(experimental("lookup", "Look up CVEs", "Look up vulnerabilities by identifier, package URL or CPE.")),
  )
  .add(
    HttpApiEndpoint.get("graph", "/api/experimental/cve/graph", {
      query: {
        id: Schema.optional(Schema.String).annotate({ description: "CVE identifier to start from." }),
        relTypes: Schema.optional(Schema.String).annotate({ description: "Comma-separated relationship types." }),
        nodeTypes: Schema.optional(Schema.String).annotate({ description: "Comma-separated node types." }),
        depth: Schema.optional(positive).annotate({ description: "Traversal depth (positive integer)." }),
        limit: Schema.optional(positive).annotate({ description: "Maximum number of nodes (positive integer)." }),
      },
      success: Cve.Graph,
      error: errors,
    }).annotateMerge(experimental("graph", "Get CVE graph", "Get the CVE relationship graph. Needs the security_cve_graph flag.")),
  )
  .add(
    HttpApiEndpoint.get("status", "/api/experimental/cve/status", {
      success: Cve.Status,
      error: errors,
    }).annotateMerge(experimental("status", "Get CVE status", "Get the CVE data source mode, database freshness and graph reachability.")),
  )
  .add(
    HttpApiEndpoint.put("setMode", "/api/experimental/cve/mode", {
      payload: Cve.ModeInput,
      success: Cve.ModeResult,
      error: errors,
    }).annotateMerge(experimental("setMode", "Set CVE mode", "Change the CVE data source mode and record the change in the audit log.")),
  )
  .add(
    HttpApiEndpoint.get("get", "/api/experimental/cve/:id", {
      params: { id: Cve.ID },
      query: { mode },
      success: Cve.Detail,
      error: errors,
    }).annotateMerge(experimental("get", "Get CVE", "Get one CVE record with its weaknesses, exploits, affected packages and related CVEs.")),
  )
