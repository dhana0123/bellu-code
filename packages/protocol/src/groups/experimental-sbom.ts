import { Sbom } from "@bellucode/schema/sbom"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/http-api"
import { InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, UnknownError] as const
const AssetParams = { assetId: Sbom.AssetID }

const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.sbom.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.sbom`: routes under /api/experimental/sbom, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalSbomGroup = HttpApiGroup.make("server.sbom")
  .add(
    HttpApiEndpoint.get("list", "/api/experimental/sbom", {
      success: Sbom.SummaryList,
      error: errors,
    }).annotateMerge(experimental("list", "List SBOMs", "List one SBOM summary per asset.")),
  )
  .add(
    HttpApiEndpoint.get("get", "/api/experimental/sbom/:assetId", {
      params: AssetParams,
      query: {
        limit: Schema.optional(
          Schema.NumberFromString.pipe(Schema.decodeTo(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 1000 })))),
        ).annotate({ description: "Maximum number of packages to return (1-1000, default 100)." }),
        cursor: Schema.optional(Schema.String).annotate({ description: "Opaque cursor from a previous page." }),
      },
      success: Sbom.Detail,
      error: errors,
    }).annotateMerge(experimental("get", "Get SBOM", "Get the SBOM summary of an asset and one page of its packages.")),
  )
  .add(
    HttpApiEndpoint.get("export", "/api/experimental/sbom/:assetId/export", {
      params: AssetParams,
      query: {
        format: Schema.optional(Sbom.ExportFormat).annotate({ description: "Document format. Defaults to the server default." }),
        version: Schema.optional(Schema.String).annotate({ description: "Specification version of the document." }),
      },
      success: Schema.Uint8Array.pipe(HttpApiSchema.asUint8Array({ contentType: "application/json" })),
      error: errors,
    }).annotateMerge(
      experimental(
        "export",
        "Export SBOM",
        "Download the latest SBOM of an asset as a CycloneDX or SPDX JSON document attachment.",
      ),
    ),
  )
