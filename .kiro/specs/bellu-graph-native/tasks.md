# Implementation Plan: Bellu Graph Engine

## Overview

Build the Engine under `services/bellud/internal/bellugraph/internal/bge/` next to the old tree, bottom-up:

1. codec and identity;
2. store;
3. Projection and planning;
4. engine core;
5. reads, snapshots and retention;
6. local IDs, resolution and subscriptions;
7. MCP and OTLP;
8. the Facade swap and conformance run;
9. GraphQL, SSE and the debug page;
10. bellud wiring;
11. removal of the old tree and tooling, docs and the leftover check.

Go is at `/usr/local/go/bin`. Run commands from `services/bellud` unless noted.

**Clean-room rule (applies to every task):** do not open, read, grep or diff any file under `services/bellud/internal/bellugraph` except `facade/**` and `internal/bge/**`, and do not fetch upstream source. Work only from `requirements.md`, `design.md`, the Facade package and its callers. Use the design's encodings and algorithms. Never write the Upstream_Name.

## Tasks

- [x] 1. Scaffold the Engine module tree
  - [x] 1.1 Create the `bge` package skeleton and error sentinels
    - Before creating it, confirm that `internal/bellugraph/internal/bge` does not exist (`test ! -e`). Do not list or read sibling directories.
    - Create `bge/doc.go`, which describes the Bellu Graph Engine as original in-tree work.
    - Create `bge/errs/errs.go` with `Validation`, `NotFound`, `Unavailable`, `Locked`, `Corrupt`, `InsecurePermissions`, `Forbidden` and `Overflow`.
    - Add `tool github.com/99designs/gqlgen` to `go.mod`, then run `go mod tidy`.
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 21.6_

- [x] 2. Codec, identity, URIs and cursors
  - [x] 2.1 Implement `bge/codec`
    - Implement `Value`, `FromAny`/`ToAny` (supported types; NaN and Inf rejected; `-0` normalized), the canonical map encoding, the event envelope with CRC-32C for all 7 event types, and the Snapshot header and records, exactly as in the design's Data Models.
    - _Requirements: 3.1, 5.12, 18.6_
  - [x]* 2.2 Write property test for event codec round trip
    - **Property 1: Event codec round trip and corruption detection**
    - **Validates: Requirements 3.2, 18.6**
  - [x]* 2.3 Write property test for attribute values
    - **Property 2: Attribute values round trip**
    - **Validates: Requirements 5.12**
  - [x] 2.4 Implement `bge/ident`
    - Kind registry: the 15 Facade kinds plus `endpoint`.
    - `Hash` with the `bellugraph.id.v1` identity input.
    - Relation registry with Impact_Direction and the reverse default.
    - `Label`, `IsSecretName` and the state-attribute rule.
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 8.7_
  - [x]* 2.5 Write unit tests for `ident`
    - Golden vectors from the design table, error messages naming the kind or attribute, Impact_Direction table, and `IsSecretName` examples.
    - _Requirements: 5.1, 5.6, 8.7_
  - [x] 2.6 Implement `bge/uri`
    - `Format` and `Parse` for entity, relation and event URIs; errors wrap `errs.Validation`.
    - _Requirements: 21.3, 21.4, 21.5_
  - [x]* 2.7 Write property test for URIs
    - **Property 26: URI round trip**
    - **Validates: Requirements 21.3, 21.4, 21.5**
  - [x] 2.8 Implement `bge/query/cursor.go`
    - Keyset cursors with kind and query-hash binding.
    - _Requirements: 6.2, 6.3_
  - [x]* 2.9 Write property test for cursors
    - **Property 27: Cursor integrity**
    - **Validates: Requirements 6.3**

- [x] 3. Pebble store
  - [x] 3.1 Implement `bge/store`
    - Read-only preflight and writable open at `<dir>/default`.
    - `m/format` (`bellugraph-store/1`); missing or unknown format → `errs.Corrupt` with the delete hint.
    - Lock errors become `errs.Locked`, naming `<dir>/default/LOCK`.
    - The keyspace from the design: `e/`, `x/ent`, `x/rel`, `x/vt`, `s/`, `m/seq` and `m/base`.
    - Atomic synced batch writes, iterators over a Pebble snapshot, Snapshot write/list/validate/load, and chunked retention deletes.
    - _Requirements: 3.3, 18.1, 18.2, 18.5, 18.6, 18.9, 24.1, 24.2_
  - [x]* 3.2 Write unit tests for `store`
    - Fresh open writes the format.
    - A Pebble DB without `m/format` (simulating the previous engine) and an unknown version both fail with `errs.Corrupt` and leave files byte- and mode-identical.
    - Lock contention, a corrupt `MANIFEST`/`CURRENT`, and an invalid Snapshot that is skipped.
    - _Requirements: 13.3, 18.5, 18.6, 18.9, 24.2_

- [x] 4. Projection, planning and the test model
  - [x] 4.1 Implement `bge/graph`
    - `EntityState`, `RelState`, `Scope`, `Annotation` and `Graph` with the sorted per-kind ID index and the `(protocol, port)` port index.
    - `Fold` as the only mutator, `Clone`, and Snapshot export and import.
    - _Requirements: 3.9, 5.8, 5.9, 5.13_
  - [x] 4.2 Implement `bge/plan`
    - Validation, entity classification (created, attribute-updated, state-changed, unchanged) with per-collector attribute ownership, relation checks, ModeFull removals (including relations touching removed entities), retire-conflict detection, and ScopeDelta.
    - The function is pure over `plan.View`.
    - _Requirements: 3.5, 3.6, 3.10, 5.7, 5.9, 5.10, 5.11, 5.12, 11.7, 19.3_
  - [x] 4.3 Implement test generators and the reference model in `bge/internal/gen`
    - Generators for kinds, identities, values, Batch sequences over a small ID universe, multi-collector schedules, out-of-order Valid_Times, fake clocks and HTML strings.
    - `model.Fold`, the naive interpreter independent of `graph` and `query`.
    - _Requirements: 22.1_
  - [x]* 4.4 Write unit tests for `plan`
    - Each validation case names the relation type, endpoint, kind or attribute.
    - _Requirements: 3.5, 3.6_

- [x] 5. Engine core write path
  - [x] 5.1 Implement `bge/metrics`
    - Every metric from the design table on a private registry; `Handler()` serves the Prometheus text format.
    - _Requirements: 20.1, 20.2, 20.3_
  - [x] 5.2 Implement `bge/engine` core
    - `Options`, `Open` (preflight load, writable open, catch-up), state and transition logging, `Apply` (all 7 pipeline steps), `Annotate`, the `Annotations` view (`Get(id) (Annotation, bool, error)`, `Count() (int, error)`) and `Close`.
    - Declare every `Core` field the later tasks need (hub, Local_ID registry, snapshot counters, clock), so that later tasks only add files.
    - _Requirements: 3.1, 3.3, 3.4, 3.7, 3.8, 3.10, 4.1, 4.2, 4.3, 5.13, 18.8, 20.4, 20.6, 24.4_
  - [x]* 5.3 Write property test for log ordering
    - **Property 4: Log ordering**
    - **Validates: Requirements 3.1, 3.2, 4.2, 4.3**
  - [x]* 5.4 Write property test for rejected batches
    - **Property 5: Rejected batches change nothing**
    - **Validates: Requirements 3.4, 3.5, 3.6**
  - [x]* 5.5 Write property test against the reference model
    - **Property 6: Apply matches the reference model**
    - **Validates: Requirements 4.1, 5.7, 5.8, 5.9, 5.10, 5.11, 19.3**
  - [x]* 5.6 Write property test for re-applying a batch
    - **Property 7: Re-applying a batch is a no-op**
    - **Validates: Requirements 3.10**
  - [x]* 5.7 Write property test for annotations
    - **Property 12: Annotations are operator-owned**
    - **Validates: Requirements 5.13**

- [x] 6. Engine reads, as-of and diff
  - [x] 6.1 Implement the current-state reads
    - `engine/read.go`, `query/find.go` and `query/neighbors.go`: `Entity`, `Find` (AND filter, sorted, keyset pages, Total), `Neighbors` (level BFS, ordering, optional `DerivedFn`), `History`, `Changes` (both orders) and `Digest`.
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 8.2_
  - [x]* 6.2 Write property test for Find and pagination
    - **Property 13: Find and pagination**
    - **Validates: Requirements 6.1, 6.2, 6.8**
  - [x]* 6.3 Write property test for History and Changes
    - **Property 14: History and Changes filters**
    - **Validates: Requirements 6.6, 6.7**
  - [x]* 6.4 Write property test for Neighbors
    - **Property 15: Neighbors equal naive BFS**
    - **Validates: Requirements 6.4, 12.6**
  - [x] 6.5 Implement as-of reads and diff
    - `engine/asof.go` and `query/diff.go`: `StateAt` (Snapshot with `maxVT ≤ at`, plus the filtered fold), single-entity as-of, the horizon check, `Diff` with caps and `Truncated`, and flapping via `x/vt`.
    - _Requirements: 4.4, 4.5, 4.6, 4.7, 8.3, 13.6_
  - [x]* 6.6 Write property test for as-of reads
    - **Property 9: As-of equals the naive fold**
    - **Validates: Requirements 4.4, 4.7**
  - [x]* 6.7 Write property test for diff and flapping
    - **Property 11: Diff and flapping match the model**
    - **Validates: Requirements 4.5, 8.3**

- [x] 7. Snapshots, retention and crash recovery
  - [x] 7.1 Implement the maintenance loop in `engine/maintain.go`
    - Snapshots every 5 min when the log advanced, after 10,000 events, and on Close; keep the 8 newest plus the base.
    - Hourly retention: binary search, boundary Snapshot, `m/base`, then chunked deletes.
    - The cadence is injectable through `Options`.
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_
  - [x]* 7.2 Write property test for replay equality
    - **Property 8: Replay equality**
    - **Validates: Requirements 3.8, 3.9, 13.2**
  - [x]* 7.3 Write property test for retention
    - **Property 10: Retention preserves as-of at or after the horizon**
    - **Validates: Requirements 13.4, 13.5, 13.6**
  - [x] 7.4 Write the crash-recovery test
    - `TestCrashMidApply` re-executes the test binary with `BGE_CRASH_CHILD=1`, kills the child with `SIGKILL` during `Apply`, reopens the store, and checks all-or-none per Batch. It runs 20 rounds and is skipped under `-short` and on Windows.
    - _Requirements: 18.10, 22.2_

- [x] 8. Local IDs, endpoint resolution, traversal and subscriptions
  - [x] 8.1 Implement `bge/localid`
    - `For`, `Lookup` and `Sweep` with a 15 min idle limit and 24 h tombstones, a `crypto/rand` alphabet and an injectable clock.
    - _Requirements: 11.2, 11.3, 11.4, 11.6_
  - [x]* 8.2 Write property test for Local_IDs
    - **Property 23: Local_ID lifecycle**
    - **Validates: Requirements 11.3, 11.4, 11.6**
  - [x] 8.3 Implement resolution and traversal
    - `bge/resolve` (the endpoint matching rule, `DerivedFn`, `Dependents`).
    - `query/path.go` (deterministic undirected BFS, the `exhausted` flag, shared neighbors and non-secret shared attributes).
    - `query/impact.go` (flow BFS with `via` paths).
    - `engine/traverse.go` (`Path`, `Impact`, `Resolve` for `@`, `bellugraph://` and Entity_ID, `LocalID`, and the sweep tick).
    - _Requirements: 8.4, 8.5, 8.6, 11.5, 12.1, 12.2, 12.3, 12.4, 12.5_
  - [x]* 8.4 Write property test for find_path
    - **Property 16: Shortest path and definite non-connection**
    - **Validates: Requirements 8.4, 8.5**
  - [x]* 8.5 Write property test for impact_of
    - **Property 17: Impact follows declared directions**
    - **Validates: Requirements 8.6, 8.7**
  - [x]* 8.6 Write property test for endpoint resolution
    - **Property 18: Endpoint resolution matches the rule and writes nothing**
    - **Validates: Requirements 12.2, 12.3, 12.4, 12.5**
  - [x]* 8.7 Write property test for entity references
    - **Property 24: Entity references are interchangeable**
    - **Validates: Requirements 11.5**
  - [x] 8.8 Implement subscriptions
    - `bge/subscribe` (hub, filter, 256-entry buffer, overflow close) and `engine/subscribe.go` (register under `applyMu`, replay `(from, L]`, then live; `from < baseSeq` → gone).
    - Publish from the Apply and Annotate step 6.
    - _Requirements: 14.1, 14.2, 14.3, 14.4_
  - [x]* 8.9 Write property test for subscriptions
    - **Property 25: Subscriptions deliver exactly the committed changes**
    - **Validates: Requirements 14.1, 14.2, 14.3**

- [x] 9. Checkpoint: Engine packages
  - Run `go vet ./internal/bellugraph/internal/bge/...` and `go test ./internal/bellugraph/internal/bge/...`. Ensure all tests pass, ask the user if questions arise.

- [x] 10. MCP server and OTLP receiver
  - [x] 10.1 Implement the `bge/mcpserver` tools
    - Server with title and instructions naming the Bellu Graph Engine.
    - The 12 typed tools with descriptions and inferred schemas, Entity_Ref arguments, the shared verbosity projection, the `recent_changes` byte budget and digest, the `find_path` not-connected result, `impact_of`, `telemetry_keys` without secret names, and `annotate_entity` through an injected annotate function that requires the `write` Caller role.
    - _Requirements: 7.1, 7.2, 7.3, 7.9, 7.10, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 10.1, 10.2, 10.3, 10.4, 10.5, 11.1, 11.2, 15.6, 15.7_
  - [x] 10.2 Add MCP resources and prompts
    - `bellugraph://schema`, the `bellugraph://{kind}/{hex}` template with resource-not-found errors, and the prompts `investigate_incident`, `blast_radius` and `explain_entity` with declared arguments and embedded entity resources.
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_
  - [x] 10.3 Implement `bge/otlp`
    - OTLP/HTTP `POST /v1/logs` (protobuf, JSON, gzip, 4 MiB) and the resource-to-Batch mapping with the `otlp/` collector prefix.
    - Partial versus full mode, partial-success responses, and caller resolution through an injected authorizer.
    - `Serve(listener)` and `Shutdown(ctx)`.
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5_
  - [x]* 10.4 Write property test for the recent_changes budget
    - **Property 19: recent_changes budget and digest**
    - **Validates: Requirements 8.1, 8.2**
  - [x]* 10.5 Write property test for verbosity
    - **Property 20: Verbosity shapes**
    - **Validates: Requirements 10.2, 10.3, 10.4**
  - [x]* 10.6 Write property test for secret-named values
    - **Property 21: Secret-named values are never emitted**
    - **Validates: Requirements 7.9, 8.5, 9.5**
  - [x]* 10.7 Write unit tests for `mcpserver`
    - Tool list and schemas, resources and not-found, prompts, invalid verbosity, and the forbidden annotate for the `read` role.
    - _Requirements: 7.1, 7.2, 9.1, 9.2, 9.3, 9.4, 10.5, 15.7_
  - [x]* 10.8 Write property test for OTLP conversion
    - **Property 28: OTLP conversion round trip**
    - **Validates: Requirements 19.2**
  - [x]* 10.9 Write unit tests for `otlp`
    - Encodings, partial success, `400`/`401`/`403`/`413`/`503`.
    - _Requirements: 19.1, 19.4, 19.5_

- [x] 11. Swap the Facade onto the Engine
  - [x] 11.1 Add the additive Facade surface in `facade/types.go` and a new `facade/roles.go`
    - `Role`, `Grant`, `Config.Grants`, `Caller`, `WithCaller`/`CallerFrom` and `ErrForbidden`.
    - New fields: `Entity.Annotations`, `Edge.Derived`, `NeighborOpts.Resolve` and `Diff.Flapping`/`Flap`.
    - The `Extended` interface and `ExtendedOf`.
    - Point the existing error vars at `bge/errs` sentinels without changing their names or types.
    - _Requirements: 2.2, 2.3, 15.6_
  - [x] 11.2 Rewrite the Facade internals on `bge/engine`
    - Rewrite `engine.go`, `ingest.go`, `query.go`, `convert.go`, `identity.go`, `mcp.go` and the `config.go` package doc.
    - Keep `engine{cfg, log, stack, audit, auditFile}`, the umask and `tightenFiles` logic, the lock/corrupt classification and logging, the open timeout, the unavailable engine, the caller resolution order, and audit-then-annotate.
    - Start the OTLP receiver only when `OTLPListen` is set.
    - Remove every import of the old engine packages and every comment mentioning vendoring, upstream or syncing.
    - Keep `LoadConfig` and the five `BELLU_GRAPH_*` variables unchanged.
    - _Requirements: 2.1, 2.2, 2.5, 21.1, 21.2, 7.4, 7.5, 7.6, 7.7, 7.8, 18.3, 18.4, 18.7, 19.1, 25.5_
  - [x] 11.3 Re-export the new Facade names in `internal/graph/graph.go`
    - Add the new names with type aliases and constants, purely additive.
    - _Requirements: 2.3_
  - [x] 11.4 Replace the golden vectors in `TestIdentityHashGolden`
    - Use the three Entity_IDs from the design's Data Models table, the only permitted edit to existing tests.
    - The existing identity properties in that file then cover **Property 3: Identity hash determinism and injectivity**, and the Facade suite serves as the conformance suite.
    - _Requirements: 2.4, 5.2, 5.3, 5.4, 5.5, 5.6, 22.3_

- [x] 12. Checkpoint: Facade conformance
  - Run `go build ./...`, `go vet ./...`, `go test ./internal/bellugraph/facade/... ./internal/graph/... ./internal/api/graph/... ./internal/server/... ./internal/collectors/... ./internal/mcptoken/... ./internal/agentcfg/... ./internal/contract/...`. Existing tests must pass unmodified, apart from task 11.4. Ensure all tests pass, ask the user if questions arise.

- [x] 13. GraphQL API
  - [x] 13.1 Implement `bge/gql`
    - `schema.graphqls` as in the design, `gqlgen.yml`, `//go:generate go tool gqlgen generate` with the generated code committed, and hand-written resolvers.
    - `asOf` support, `annotateEntity` through the Facade annotate function (audited, `write` role), and the `changes` subscription from the hub.
    - POST, SSE and websocket transports; introspection; complexity limit 5000; our depth-12 extension; the error presenter codes.
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8, 14.7, 11.1, 11.2_
  - [x]* 13.2 Write property test for API equivalence
    - **Property 30: API equivalence**
    - **Validates: Requirements 7.3, 16.6**
  - [x]* 13.3 Write unit tests for `gql`
    - Each query with and without `asOf`, the mutation (audited, forbidden for `read`), the subscription over SSE and websocket, the limits and the error codes.
    - _Requirements: 16.1, 16.3, 16.4, 16.5, 16.7, 16.8, 14.7_

- [x] 14. SSE, Debug UI and Facade handlers
  - [x] 14.1 Implement `bge/sse`
    - Filters, `Last-Event-ID`/`from` resume, `change` frames with seq IDs, 15 s keep-alive, and the `graph_gone`/`graph_overflow` error events.
    - _Requirements: 14.5, 14.6_
  - [x]* 14.2 Write unit tests for `sse`
    - Framing, resume without gap, gone, overflow, keep-alive with a fake ticker.
    - _Requirements: 14.5, 14.6_
  - [x] 14.3 Implement `bge/debugui`
    - Embedded templates and CSS, GET-only search, entity, neighbor (depth 1–3) and history views with `as_of`, the CSP, nosniff and Referrer-Policy headers, and `405` for other methods.
    - _Requirements: 17.1, 17.2, 17.3, 17.5_
  - [x]* 14.4 Write property test for Debug UI escaping
    - **Property 29: Debug UI escapes every value**
    - **Validates: Requirements 17.1, 17.5**
  - [x] 14.5 Add the `Handlers` type and `HandlersOf` in `facade/handlers.go`
    - GraphQL, Subscribe, Debug and Metrics handlers from the ready engine; `UnavailableHandler` otherwise.
    - _Requirements: 2.3, 7.8, 20.3_

- [x] 15. bellud wiring and token roles
  - [x] 15.1 Extend `internal/mcptoken` with roles
    - `Role`, `Set`, `NewSet(write)` and `RoleOf`. Existing exports and their tests stay unchanged; update the package doc to say tokens are accepted on graph routes.
    - _Requirements: 15.1, 15.9_
  - [x] 15.2 Register the new Go-owned routes
    - In `internal/server/routes/generate.go`, add `* /graphql` (stream), `GET /subscribe` (stream), `GET /debug`, `GET /debug/*`, `GET /metrics` and `POST /batches` under `/api/experimental/graph`.
    - Regenerate `routes.yaml` with the existing generator so that `TestGenerate` passes.
    - _Requirements: 14.5, 15.3, 16.1, 17.1, 20.3_
  - [x] 15.3 Update `internal/api/graph`
    - Widen `idPattern` to Local_IDs and resolve refs through `facade.ExtendedOf`.
    - Add `POST /batches` (JSON Batch, 4 MiB limit, Receipt, `400`/`503`).
    - _Requirements: 11.5, 15.5, 15.8_
  - [x] 15.4 Wire `cmd/bellud/main.go`
    - Build the `mcptoken.Set` with the existing token as `Write` and pass `Grants`.
    - Write `graph-tokens.json` (read and ingest tokens, 0600, temp file and rename).
    - Set `GoAuth` to token-or-bellud for the token-accepting routes; MCP stays token-only.
    - Add the role middleware (Caller from token or bellud credentials, required-role table, `403 graph_forbidden`).
    - Mount `HandlersOf` and the new routes.
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 17.4, 20.3_
  - [x]* 15.5 Write the role matrix tests
    - Exhaustive role × route table (read, ingest, write, bellud credentials, none) across MCP, GraphQL, SSE, HTTP reads, `POST /batches`, debug and metrics, plus the `graph-tokens.json` mode and content.
    - _Requirements: 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 17.4_
  - [x]* 15.6 Write property test for logs and metrics
    - **Property 22: No attribute values in logs or metrics**
    - **Validates: Requirements 20.5**

- [x] 16. Checkpoint: full stack on the new Engine
  - Run `go build ./...`, `go vet ./...` and `go test ./...`. Confirm with `go list -deps ./internal/bellugraph/facade` that the Facade imports no old engine package. Ensure all tests pass, ask the user if questions arise.

- [x] 17. Remove the vendored engine and sync tooling
  - [x] 17.1 Delete the Vendored_Tree and attribution files
    - Delete every path under `services/bellud/internal/bellugraph` except `facade/` and `internal/bge/`, using `git rm -r` on the top-level entries without opening them.
    - This includes `NOTICE`, `UPSTREAM.md`, `LICENSE` and the other copied top-level files.
    - _Requirements: 23.1, 23.3_
  - [x] 17.2 Delete the sync tooling and its build and CI hooks
    - Delete `internal/syncgraph`, `internal/rename`, `cmd/sync-bellu-graph`, `services/bellud/script/rename.map.yaml`, `services/bellud/script/bellu-graph.sum` and `script/sync-bellu-graph`.
    - Remove the `sync-graph` target, the `TestFixtureV1` line and the sync wording from the root `Makefile`.
    - Remove the `script/sync-bellu-graph/**` path filter and the "Vendored sync-tool leftover check" step from `.github/workflows/bellud.yml`.
    - _Requirements: 23.2, 23.4, 23.5_
  - [x] 17.3 Run `go mod tidy` and rebuild
    - Run `go mod tidy`, `go build ./...`, `go vet ./...` and `go test ./...`. Confirm that modules used only by the old tree are gone from `go.mod`/`go.sum`.
    - _Requirements: 23.6, 22.4_

- [x] 18. Documentation and the upstream-name check
  - [x] 18.1 Update the `go-server-bellu-graph` spec
    - Edit `requirements.md`, `design.md`, `tasks.md` and `tasks.meta.json`: drop the sync tool, rename map, Allow_List, NOTICE and upstream references, and describe the in-tree Bellu Graph Engine with a pointer to this spec.
    - _Requirements: 23.7, 25.5_
  - [x] 18.2 Update `services/bellud/README.md`
    - Replace "Sync the Bellu Graph engine" with an in-tree Engine section: features, routes, token roles and `graph-tokens.json`.
    - Add the upgrade note: delete `~/.local/share/bellucode/graph` (copy `audit.jsonl` first if needed); collectors rebuild the graph.
    - _Requirements: 23.8, 24.3, 25.5_
  - [x] 18.3 Add `script/check-no-upstream-name` and run it in CI
    - Write a POSIX shell script that builds the term from two fragments and runs a case-insensitive search over the repository paths (`git ls-files` plus untracked, non-ignored files) and contents, excluding `.git`, `node_modules`, `dist` and the Finnish words in `fi.ts`. It prints each match and exits `1` on any match.
    - Add a CI step in `.github/workflows/bellud.yml` that runs it from the repository root.
    - _Requirements: 25.1, 25.2, 25.3, 25.4_

- [x] 19. Final checkpoint
  - From `services/bellud`, run `go build ./...`, `go vet ./...` and `go test ./...`. From the repository root, run `script/check-no-upstream-name`, which must find zero matches. Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP. The crash-recovery test (7.4) and the conformance checkpoints are required.
- Each property test uses `pgregory.net/rapid`, runs at least 100 iterations, and carries `// Feature: bellu-graph-native, Property N: <text>`.
- Existing tests are not edited, apart from task 11.4. If one fails, fix the Engine, not the test.
- Clean-room rule: implementers never open the old engine files, not even while deleting them in 17.1.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "2.4", "2.6", "2.8"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.5", "2.7", "2.9", "3.1", "4.1"] },
    { "id": 3, "tasks": ["3.2", "4.2", "4.3", "5.1", "8.1"] },
    { "id": 4, "tasks": ["4.4", "5.2", "8.2"] },
    { "id": 5, "tasks": ["5.3", "5.4", "5.5", "5.6", "5.7", "6.1"] },
    { "id": 6, "tasks": ["6.2", "6.3", "6.4", "6.5", "8.3", "8.8"] },
    { "id": 7, "tasks": ["6.6", "6.7", "7.1", "8.4", "8.5", "8.6", "8.7", "8.9"] },
    { "id": 8, "tasks": ["7.2", "7.3", "7.4", "10.1", "10.3"] },
    { "id": 9, "tasks": ["10.2", "10.8", "10.9", "11.1"] },
    { "id": 10, "tasks": ["10.4", "10.5", "10.6", "10.7", "11.2"] },
    { "id": 11, "tasks": ["11.3", "11.4", "13.1", "14.1", "14.3"] },
    { "id": 12, "tasks": ["13.3", "14.2", "14.4", "14.5", "15.1"] },
    { "id": 13, "tasks": ["13.2", "15.2", "15.3"] },
    { "id": 14, "tasks": ["15.4"] },
    { "id": 15, "tasks": ["15.5", "15.6"] },
    { "id": 16, "tasks": ["17.1"] },
    { "id": 17, "tasks": ["17.2"] },
    { "id": 18, "tasks": ["17.3"] },
    { "id": 19, "tasks": ["18.1", "18.2", "18.3"] }
  ]
}
```
