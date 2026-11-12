#!/usr/bin/env bun
// Writes internal/openapi/gocontract.json: the Go-owned `/api/experimental/graph/*` operations from the TS `Api`
// OpenAPI document, plus the component schemas they reference.
// Usage: bun services/bellud/script/gen-gocontract.ts [--check]
import { fileURLToPath } from "node:url"
const protocol = fileURLToPath(new URL("../../../packages/protocol/", import.meta.url))
const { OpenApi } = await import(Bun.resolveSync("effect/http-api", protocol))
const { ClientApi } = await import("../../../packages/protocol/src/client.js")
const doc = OpenApi.fromApi(ClientApi) as any
const prefix = "/api/experimental/graph/"
const paths: Record<string, unknown> = {}
for (const key of Object.keys(doc.paths).sort()) if (key.startsWith(prefix)) paths[key] = doc.paths[key]
const schemas: Record<string, unknown> = {}
const all = doc.components?.schemas ?? {}
const visit = (value: unknown): void => {
  if (Array.isArray(value)) return value.forEach(visit)
  if (value === null || typeof value !== "object") return
  for (const [k, v] of Object.entries(value)) {
    if (k === "$ref" && typeof v === "string" && v.startsWith("#/components/schemas/")) {
      const name = v.slice("#/components/schemas/".length)
      if (!(name in schemas) && name in all) {
        schemas[name] = all[name]
        visit(all[name])
      }
    } else visit(v)
  }
}
visit(paths)
const out = {
  openapi: doc.openapi,
  info: doc.info,
  paths,
  components: { schemas: Object.fromEntries(Object.entries(schemas).sort(([a], [b]) => a.localeCompare(b))) },
}
const target = fileURLToPath(new URL("../internal/openapi/gocontract.json", import.meta.url))
const text = JSON.stringify(out, null, 2) + "\n"
if (process.argv.includes("--check")) {
  if ((await Bun.file(target).text()) !== text) {
    console.error("gocontract.json is stale. Run `bun services/bellud/script/gen-gocontract.ts`.")
    process.exit(1)
  }
  process.exit(0)
}
await Bun.write(target, text)
