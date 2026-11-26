import { Bom } from "@bellucode/schema/bom"
import { Sbom } from "@bellucode/schema/sbom"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/http-api"
import { InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, UnknownError] as const

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.bom.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.bom`: routes under /api/experimental/bom, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalBomGroup = HttpApiGroup.make("server.bom")
  .add(
    HttpApiEndpoint.get("sbomList", "/api/experimental/bom/sbom", {
      success: Sbom.SummaryList,
      error: errors,
    }).annotateMerge(experimental("sbomList", "List SBOM bills of materials", "List one SBOM summary per asset.")),
  )
  .add(
    HttpApiEndpoint.get("sbomExport", "/api/experimental/bom/sbom/:assetId/export", {
      params: { assetId: Sbom.AssetID },
      query: {
        format: Schema.optional(Sbom.ExportFormat).annotate({ description: "Document format. Defaults to the server default." }),
        version: Schema.optional(Schema.String).annotate({ description: "Specification version of the document." }),
      },
      success: Schema.Uint8Array.pipe(HttpApiSchema.asUint8Array({ contentType: "application/json" })),
      error: errors,
    }).annotateMerge(
      experimental(
        "sbomExport",
        "Export SBOM bill of materials",
        "Download the latest SBOM of an asset as a CycloneDX or SPDX JSON document attachment.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.get("ai", "/api/experimental/bom/ai", {
      success: Bom.Document,
      error: errors,
    }).annotateMerge(
      experimental("ai", "Get AI-BOM", "Get the AI-BOM components, incomplete provider gaps and findings."),
    ),
  )
  .add(
    HttpApiEndpoint.get("aiExport", "/api/experimental/bom/ai/export", {
      query: {
        format: Schema.optional(Sbom.ExportFormat).annotate({ description: "Document format. Defaults to the server default." }),
        version: Schema.optional(Schema.String).annotate({ description: "Specification version of the document." }),
      },
      success: Schema.Uint8Array.pipe(HttpApiSchema.asUint8Array({ contentType: "application/json" })),
      error: errors,
    }).annotateMerge(
      experimental("aiExport", "Export AI-BOM", "Download the AI-BOM as a CycloneDX or SPDX JSON document attachment."),
    ),
  )
  .add(
    HttpApiEndpoint.get("cloud", "/api/experimental/bom/cloud", {
      success: Bom.Document,
      error: errors,
    }).annotateMerge(
      experimental("cloud", "Get Cloud-BOM", "Get the Cloud-BOM components, incomplete provider gaps and findings."),
    ),
  )
  .add(
    HttpApiEndpoint.get("cloudExport", "/api/experimental/bom/cloud/export", {
      query: {
        format: Schema.optional(Sbom.ExportFormat).annotate({ description: "Document format. Defaults to the server default." }),
        version: Schema.optional(Schema.String).annotate({ description: "Specification version of the document." }),
      },
      success: Schema.Uint8Array.pipe(HttpApiSchema.asUint8Array({ contentType: "application/json" })),
      error: errors,
    }).annotateMerge(
      experimental("cloudExport", "Export Cloud-BOM", "Download the Cloud-BOM as a CycloneDX or SPDX JSON document attachment."),
    ),
  )
