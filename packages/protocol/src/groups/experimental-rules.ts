import { Rules } from "@bellucode/schema/rules"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { InvalidRequestError, NotFoundError, UnknownError } from "../errors.js"

const errors = [InvalidRequestError, NotFoundError, UnknownError] as const
const experimental = (name: string, summary: string, description: string) =>
  OpenApi.annotations({
    identifier: `experimental.rules.${name}`,
    summary,
    description: `${description} Experimental: may change without compatibility guarantees.`,
    transform: (operation) => ({ ...operation, tags: ["experimental"] }),
  })

/**
 * `server.rules`: routes under /api/experimental/rules, served by the Go server.
 * The TypeScript server registers no handlers for them (see `Api` wiring in packages/server).
 */
export const ExperimentalRulesGroup = HttpApiGroup.make("server.rules")
  .add(
    HttpApiEndpoint.get("packs", "/api/experimental/rules/packs", {
      success: Rules.PackList,
      error: errors,
    }).annotateMerge(experimental("packs", "List rule packs", "List the rule packs with version, enabled state and rule count.")),
  )
  .add(
    HttpApiEndpoint.get("packRules", "/api/experimental/rules/packs/:id/rules", {
      params: { id: Rules.ID },
      success: Rules.RuleList,
      error: errors,
    }).annotateMerge(
      experimental("packRules", "List pack rules", "List the rules of one pack with their effective and default severity."),
    ),
  )
  .add(
    HttpApiEndpoint.put("override", "/api/experimental/rules/overrides", {
      payload: Rules.OverrideInput,
      success: Rules.OverrideResult,
      error: errors,
    }).annotateMerge(
      experimental(
        "override",
        "Override rule or pack",
        "Enable, disable or change the severity of a rule, or of a whole pack when ruleId is omitted, and return the updated rule or pack. Answers 404 when the pack or rule is unknown.",
      ),
    ),
  )
  .add(
    HttpApiEndpoint.get("compliance", "/api/experimental/rules/compliance", {
      query: {
        benchmark: Schema.optional(Rules.ID).annotate({
          description: "Benchmark to report on. Without it the response lists the available benchmarks.",
        }),
      },
      success: Rules.ComplianceResult,
      error: errors,
    }).annotateMerge(
      experimental(
        "compliance",
        "Get compliance",
        "List the available benchmarks, or the control results of one benchmark. Answers 404 when the benchmark is unknown.",
      ),
    ),
  )
