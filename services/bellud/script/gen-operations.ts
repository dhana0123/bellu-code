#!/usr/bin/env bun
// Writes the protocol operation list (method, path, group, stream) from the TS `Api` OpenAPI document.
// Usage: bun services/bellud/script/gen-operations.ts [--check]
import { fileURLToPath } from "node:url"

// `effect` is installed under packages/protocol, so resolve it from there.
const protocol = fileURLToPath(new URL("../../../packages/protocol/", import.meta.url))
const { OpenApi } = await import(Bun.resolveSync("effect/http-api", protocol))

const methods = ["get", "put", "post", "delete", "options", "head", "patch"] as const
const { ClientApi } = await import("../../../packages/protocol/src/client.js")
const doc = OpenApi.fromApi(ClientApi)

const operations = Object.entries(doc.paths)
  .flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      if (!operation) return []
      const stream =
        "x-websocket" in operation ||
        Object.values(operation.responses ?? {}).some((response) => "text/event-stream" in (response.content ?? {}))
      return [
        {
          method: method.toUpperCase(),
          path,
          operationId: operation.operationId ?? "",
          group: operation.tags?.[0] ?? "",
          stream,
        },
      ]
    }),
  )
  .sort((a, b) => (a.path === b.path ? a.method.localeCompare(b.method) : a.path.localeCompare(b.path)))

const target = fileURLToPath(new URL("../internal/server/routes/testdata/operations.json", import.meta.url))
const text = JSON.stringify(operations, null, 2) + "\n"
if (process.argv.includes("--check")) {
  if ((await Bun.file(target).text()) !== text) {
    console.error("operations.json is stale. Run `bun services/bellud/script/gen-operations.ts`.")
    process.exit(1)
  }
  process.exit(0)
}
await Bun.write(target, text)
