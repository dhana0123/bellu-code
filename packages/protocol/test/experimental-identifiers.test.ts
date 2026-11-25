import { expect, test } from "bun:test"
import { OpenApi } from "effect/http-api"
import { ClientApi } from "../src/client.js"

const methods = ["get", "put", "post", "delete", "patch", "head", "options", "trace"] as const

test("routes under /api/experimental, and only those, have experimental.* identifiers", () => {
  const operations = Object.entries(OpenApi.fromApi(ClientApi).paths).flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      return operation ? [{ path, identifier: operation.operationId }] : []
    }),
  )
  const offenders = operations
    .filter(
      ({ path, identifier }) =>
        (path === "/api/experimental" || path.startsWith("/api/experimental/")) !==
        identifier.startsWith("experimental."),
    )
    .map(({ path, identifier }) => `${identifier} ${path}`)

  expect(operations.length).toBeGreaterThan(100)
  expect(offenders).toEqual([])
})

test("graph endpoints are exactly /api/experimental/graph/* <-> experimental.graph.*, with the experimental description", () => {
  const operations = Object.entries(OpenApi.fromApi(ClientApi).paths).flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      return operation ? [{ path, identifier: operation.operationId, description: operation.description }] : []
    }),
  )
  const byPath = operations.filter(({ path }) => path.startsWith("/api/experimental/graph/"))
  const byIdentifier = operations.filter(({ identifier }) => identifier.startsWith("experimental.graph."))
  const names = ["changes", "diff", "entity", "find", "history", "intelStatus", "lenses", "neighbors", "overlay", "schema", "slice", "status"]
  expect(byPath.map(({ identifier }) => identifier).sort()).toEqual(names.map((name) => `experimental.graph.${name}`))
  // both directions: path prefix <=> identifier prefix
  expect(byIdentifier.map(({ path }) => path).sort()).toEqual(byPath.map(({ path }) => path).sort())
  for (const { description } of byPath) expect(description).toEndWith("Experimental: may change without compatibility guarantees.")
})

test("connector endpoints are exactly /api/experimental/connectors/* <-> experimental.connectors.*, with the experimental description", () => {
  const operations = Object.entries(OpenApi.fromApi(ClientApi).paths).flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      return operation ? [{ path, identifier: operation.operationId, description: operation.description }] : []
    }),
  )
  const byPath = operations.filter(({ path }) => path.startsWith("/api/experimental/connectors/"))
  const byIdentifier = operations.filter(({ identifier }) => identifier.startsWith("experimental.connectors."))
  expect(byPath.length).toBeGreaterThan(0)
  expect(byIdentifier.map(({ path }) => path).sort()).toEqual(byPath.map(({ path }) => path).sort())
  expect(byIdentifier.map(({ identifier }) => identifier).sort()).toEqual(
    byPath.map(({ identifier }) => identifier).sort(),
  )
  for (const { description } of byPath)
    expect(description).toEndWith("Experimental: may change without compatibility guarantees.")
})

test("overview and findings endpoints map /api/experimental/<group>/* <-> experimental.<group>.*, with the experimental description", () => {
  const operations = Object.entries(OpenApi.fromApi(ClientApi).paths).flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      return operation ? [{ path, identifier: operation.operationId, description: operation.description }] : []
    }),
  )
  for (const group of ["overview", "findings"]) {
    const byPath = operations.filter(({ path }) => path === `/api/experimental/${group}` || path.startsWith(`/api/experimental/${group}/`))
    const byIdentifier = operations.filter(({ identifier }) => identifier.startsWith(`experimental.${group}.`))
    expect(byPath.length).toBeGreaterThan(0)
    expect(byIdentifier.map(({ path }) => path).sort()).toEqual(byPath.map(({ path }) => path).sort())
    for (const { description } of byPath) expect(description).toEndWith("Experimental: may change without compatibility guarantees.")
  }
  expect(
    operations.filter(({ identifier }) => /^experimental\.(overview|findings)\./.test(identifier)).map(({ identifier }) => identifier).sort(),
  ).toEqual([
    "experimental.findings.get",
    "experimental.findings.list",
    "experimental.findings.setStatus",
    "experimental.overview.categories",
  ])
})

test("scans, sbom and bom endpoints map /api/experimental/<group>/* <-> experimental.<group>.*, with the experimental description", () => {
  const operations = Object.entries(OpenApi.fromApi(ClientApi).paths).flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      return operation ? [{ path, identifier: operation.operationId, description: operation.description }] : []
    }),
  )
  for (const group of ["scans", "sbom", "bom"]) {
    const byPath = operations.filter(({ path }) => path === `/api/experimental/${group}` || path.startsWith(`/api/experimental/${group}/`))
    const byIdentifier = operations.filter(({ identifier }) => identifier.startsWith(`experimental.${group}.`))
    expect(byPath.length).toBeGreaterThan(0)
    expect(byIdentifier.map(({ path }) => path).sort()).toEqual(byPath.map(({ path }) => path).sort())
    for (const { description } of byPath) expect(description).toEndWith("Experimental: may change without compatibility guarantees.")
  }
  expect(
    operations.filter(({ identifier }) => /^experimental\.(scans|sbom|bom)\./.test(identifier)).map(({ identifier }) => identifier).sort(),
  ).toEqual([
    "experimental.bom.sbomExport",
    "experimental.bom.sbomList",
    "experimental.sbom.export",
    "experimental.sbom.get",
    "experimental.sbom.list",
    "experimental.scans.cancel",
    "experimental.scans.enqueue",
    "experimental.scans.get",
    "experimental.scans.list",
    "experimental.scans.scanners",
    "experimental.scans.schedule",
  ])
})

test("issues, rules and data endpoints map /api/experimental/<group>/* <-> experimental.<group>.*, with the experimental description", () => {
  const operations = Object.entries(OpenApi.fromApi(ClientApi).paths).flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      return operation ? [{ path, identifier: operation.operationId, description: operation.description }] : []
    }),
  )
  for (const group of ["issues", "rules", "data"]) {
    const byPath = operations.filter(({ path }) => path.startsWith(`/api/experimental/${group}`))
    const byIdentifier = operations.filter(({ identifier }) => identifier.startsWith(`experimental.${group}.`))
    expect(byPath.length).toBeGreaterThan(0)
    expect(byIdentifier.map(({ path }) => path).sort()).toEqual(byPath.map(({ path }) => path).sort())
    for (const { description } of byPath) expect(description).toEndWith("Experimental: may change without compatibility guarantees.")
  }
  expect(
    operations.filter(({ identifier }) => /^experimental\.(issues|rules|data)\./.test(identifier)).map(({ identifier }) => identifier).sort(),
  ).toEqual([
    "experimental.data.store",
    "experimental.data.stores",
    "experimental.issues.get",
    "experimental.issues.list",
    "experimental.issues.setStatus",
    "experimental.rules.compliance",
    "experimental.rules.override",
    "experimental.rules.packRules",
    "experimental.rules.packs",
  ])
})
test("cve endpoints map /api/experimental/cve/* <-> experimental.cve.*, with the experimental description", () => {
  const operations = Object.entries(OpenApi.fromApi(ClientApi).paths).flatMap(([path, item]) =>
    methods.flatMap((method) => {
      const operation = item[method]
      return operation ? [{ path, identifier: operation.operationId, description: operation.description }] : []
    }),
  )
  const byPath = operations.filter(({ path }) => path.startsWith("/api/experimental/cve/"))
  const byIdentifier = operations.filter(({ identifier }) => identifier.startsWith("experimental.cve."))
  expect(byIdentifier.map(({ path }) => path).sort()).toEqual(byPath.map(({ path }) => path).sort())
  for (const { description } of byPath) expect(description).toEndWith("Experimental: may change without compatibility guarantees.")
  expect(byIdentifier.map(({ identifier }) => identifier).sort()).toEqual([
    "experimental.cve.get",
    "experimental.cve.graph",
    "experimental.cve.lookup",
    "experimental.cve.setMode",
    "experimental.cve.status",
  ])
})
