#!/usr/bin/env bun
// Writes internal/contract/schemas.json: per operationId response schemas (status -> content type -> schema)
// plus shared components, derived from the TS protocol OpenAPI document.
// Usage: bun services/bellud/script/gen-contract-schemas.ts [--check]
import { fileURLToPath } from "node:url"
const protocol = fileURLToPath(new URL("../../../packages/protocol/", import.meta.url))
const { OpenApi } = await import(Bun.resolveSync("effect/http-api", protocol))
const { ClientApi } = await import("../../../packages/protocol/src/client.js")
const doc = OpenApi.fromApi(ClientApi) as any
const methods = ["get", "put", "post", "delete", "options", "head", "patch"]
const operations: Record<string, any> = {}
for (const item of Object.values<any>(doc.paths))
  for (const m of methods) {
    const op = item[m]
    if (!op?.operationId) continue
    const responses: Record<string, any> = {}
    for (const [status, r] of Object.entries<any>(op.responses ?? {})) {
      const content: Record<string, any> = {}
      for (const [ct, v] of Object.entries<any>(r.content ?? {})) content[ct] = v.schema ?? {}
      responses[status] = content
    }
    operations[op.operationId] = { responses }
  }
const sorted = Object.fromEntries(Object.entries(operations).sort(([a], [b]) => a.localeCompare(b)))
const out = { operations: sorted, components: doc.components?.schemas ?? {} }
const target = fileURLToPath(new URL("../internal/contract/schemas.json", import.meta.url))
const text = JSON.stringify(out, null, 1) + "\n"
if (process.argv.includes("--check")) {
  if ((await Bun.file(target).text()) !== text) {
    console.error("schemas.json is stale. Run `bun services/bellud/script/gen-contract-schemas.ts`.")
    process.exit(1)
  }
  process.exit(0)
}
await Bun.write(target, text)
