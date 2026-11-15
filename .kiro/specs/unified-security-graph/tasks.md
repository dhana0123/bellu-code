# Implementation Plan: Unified Security Graph

## Overview

The work is split into seven demoable groups, each followed by a checkpoint, and a final checkpoint. Go code lives under `services/bellud/internal` and the UI under `packages/app/src/security-graph`, as laid out in `design.md`. Tests cover pure logic only: the property-based tests for the Correctness Properties in `design.md`. They are optional sub-tasks marked with `*`. No unit, example, or integration test tasks are included.

Path convention: `internal/...` means `services/bellud/internal/...`. Run Go commands from `services/bellud` and TypeScript commands from the package directory, never from the repo root (except `bun run check`). Before writing any test, read the `unit-tests` skill under `.bellucode/skills`. Do not restart any running service.

## Tasks

- [x] 1. Group 1: README, registry kinds and relations, canonical key package
  - [x] 1.1 Write the Graph_README
    - Create `docs/features/security-graph/README.md`.
    - Cover the architecture (pipeline and package layout), the naming contract (`canonical_key`, kinds, relation types, attribute names to avoid), the lens catalog, and the intel flow.
    - Define the Latest_Pointer fields, state that the pointer is a mutable object and that Bellud applies a cache lifetime of 0 (conditional GET per run), and describe the Bellud behavior for each failure case in the design's failure table.
    - Describe how to add a new Collector.
    - Credit Graphify (Apache-2.0, Python) for the ideas of extracted versus inferred edges, weakest-hop confidence, and bounded subgraph answers, and state that no Graphify code is copied.
    - State that the protocol, client, and route table are regenerated with `bun run generate` from `packages/client` after the experimental routes change.
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

  - [x] 1.2 Register the `package` and `vulnerability` kinds and the new relation types
    - Edit `internal/bellugraph/internal/bge/ident/ident.go`: add kinds `package` (identity `connection`, `scope`, `purl`) and `vulnerability` (identity `id`) to `Kinds` and `identityAttrs`.
    - Add `affected_by`, `same_as`, and `likely_same_as` to `relDirections`, each with direction Reverse.
    - Keep Entity_IDs of existing kinds unchanged. Confirm attribute names avoid the secret-name fragments and `data`.
    - Edit the facade (`internal/bellugraph/facade`) only if it enumerates kinds or relation types.
    - _Requirements: 2.1, 2.3, 2.4, 2.7_

  - [x] 1.3 Create the canonical key package
    - Create `internal/canonical/key.go` with `Key(kind, raw string) (string, bool)` for ARN, purl, CVE or GHSA id, image digest, and git URL, following the normalization table in the design.
    - Export the attribute name constant `canonical_key` and the kind constants.
    - _Requirements: 2.2_

  - [x] 1.4 Write property test for Entity_ID stability
    - Create or extend `internal/bellugraph/facade/identity_property_test.go` using `pgregory.net/rapid`.
    - **Property 1: Entity_ID depends only on kind and identity attributes**
    - Include one pinned golden ID per pre-existing kind.
    - **Validates: Requirements 2.1, 2.2**

  - [x] 1.5 Write property test for canonical key normalization
    - Create `internal/canonical/key_property_test.go`.
    - **Property 2: Canonical_Key normalization is idempotent and spelling-invariant**
    - **Validates: Requirements 2.2**

- [x] 2. Checkpoint - Group 1
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Group 2: Collector extensions (GitHub packages, AWS exposure, Run_Status)
  - [x] 3.1 Add GitHub package collection from SBOM
    - Edit the GitHub connector files in `internal/connectors/github` (`collector.go`, the API interface and client, and the manifest).
    - Add `SBOM(ctx, owner, repo) ([]Package, error)` reading `GET /repos/{o}/{r}/dependency-graph/sbom`, add the read operation to the manifest, and add `package` to its entities.
    - Emit one `package` entity per SBOM package with a purl (`connection`, `scope`, `purl`, `canonical_key`, `name`, `ecosystem`) and a `depends_on` relation from the repo. Cap at 5,000 packages per repo and set `packages_truncated=true` beyond that.
    - Set `canonical_key` (`git:`) on `github_repo` entities. Keep dependabot alerts as `github_alert`.
    - Edit the Docker collector under `internal/connectors` to set `canonical_key` (`sha256:`) on `image` entities whose id is a digest.
    - _Requirements: 2.2, 3.1, 3.4_

  - [x] 3.2 Add AWS internet exposure and canonical keys
    - Edit `internal/connectors/aws` (`collector.go` and its API types): add `OpenToInternet` to `SecurityGroup` and `PublicIP` to `Instance`.
    - Add the pure function `exposed(instance, groups) bool` and set `internet_exposed = "true"` on exposed instances and on open security groups.
    - Set `canonical_key` (`arn:`) on every `aws_resource`.
    - _Requirements: 2.2, 3.2, 3.3_

  - [x] 3.3 Add Run_Status reporting for rate limits, authorization errors, and denied scopes
    - Add the optional `collectors.StatusReporter` interface in `internal/collectors`.
    - Add `RunStatus`, `RateLimitWait` and the three fields to `internal/connectors/lifecycle` (`LastSync` and the supervisor), written from what the collector reports.
    - Edit `internal/connectors/broker` so the rate-limit path returns the wait it performed.
    - Edit the GitHub and AWS collectors to record rate-limit waits, end the run with an authorization error on rejected credentials, and record denied scopes (including a 403 or 404 on one repo's SBOM) while continuing with the remaining scopes.
    - _Requirements: 3.4, 3.5, 3.6, 3.7, 3.8_

  - [x] 3.4 Write property test for internet exposure
    - Create `internal/connectors/aws/exposure_property_test.go`.
    - **Property 5: Internet exposure follows security group rules and public address**
    - **Validates: Requirements 3.3**

- [x] 4. Checkpoint - Group 2
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Group 3: Intel model, bundle, store, syncer, and status route
  - [x] 5.1 Port the intel model
    - Create `internal/intel/model` with `Vuln`, `AffectedPackage`, `SemverRange`, `CVSS`, `Severity`, `Contains`, version comparison, `SplitPurl`, and `MatchPackage`, ported from the Bellu Cyber reference. Add no JSON tags, so field names match `intel.jsonl`.
    - Do not import `github.com/bellu/bellu-ai-cyber`.
    - _Requirements: 5.2, 5.4, 5.5_

  - [x] 5.2 Port the bundle verifier, pointer parser, and pinned key loader
    - Create `internal/intel/bundle` with `Pointer`, `ParsePointer`, `Verify`, JSONL parsing, and `LoadPinnedKey` (`BELLU_INTEL_PUBKEY` overriding the embedded `pinned_key.txt`).
    - Enforce the archive limits (8 members, 1 GiB total, 512 MiB per member, decoder memory limit) and the three fixed member names. Verify the signature first, then size and sha256 of every listed file, then reject unlisted members.
    - Move `github.com/klauspost/compress` to a direct dependency in `services/bellud/go.mod`.
    - Put the test-only `Build` and `ExportJSONL` helpers in a `_test.go` file.
    - _Requirements: 4.1, 4.2, 4.7, 4.8_

  - [x] 5.3 Implement the Pebble intel store
    - Create `internal/intel/store` with `Replace` (generation-based import and single-batch flip), `Get`, `ByPurl`, `Meta`, and `RecordError`, using the key layout in the design.
    - Delete non-active generations on open. Never load the whole corpus into memory on read.
    - _Requirements: 4.3, 4.6, 4.7, 5.7_

  - [x] 5.4 Implement the Syncer
    - Create `internal/intel/sync` with `Syncer`, `Run`, `RunOnce`, and `Status`.
    - Conditional GET of the pointer with only the fixed headers and no body, query, or cookies. Download with a size limit, check sha256, verify, then import. Record each failure kind from the design's failure table and keep the previous corpus.
    - Support a local bundle path with no network access. Run every 24 h plus up to 10 % jitter, first run 30 s after boot, retry after 1 h on failure. Call an `onImported` callback after a successful import.
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 1.4_

  - [x] 5.5 Add the intel status route and wire the intel stack into Bellud
    - Create `internal/api/graph/lens.go` with the `WithIntel` option and the `GET /api/experimental/graph/intel/status` handler (`state`, `version`, `records`, `last_synced_at`, `last_error`).
    - Edit `cmd/bellud/main.go` `openGraph`: open the intel store (`BELLU_INTEL_DIR`, default beside `BELLU_GRAPH_DIR`), build and start the Syncer, pass the status function to `apigraph.New`, and stop in the order Syncer, Runner, engine, intel store.
    - The route-table and protocol entries for this route are added with the other routes in task 9.4.
    - _Requirements: 4.9, 1.4_

  - [x] 5.6 Write property test for package matching
    - Create `internal/intel/model/match_property_test.go` with a reference comparator written independently of the production version comparison.
    - **Property 9: Package matching follows the half-open range rule**
    - **Validates: Requirements 5.2, 5.4, 5.5**

  - [x] 5.7 Write property test for bundle verification
    - Create `internal/intel/bundle/verify_property_test.go`.
    - **Property 6: Verification rejects any tampered bundle and leaves the corpus unchanged**
    - **Validates: Requirements 4.2, 4.6, 4.7**

  - [x] 5.8 Write property test for pointer parsing
    - Create `internal/intel/bundle/pointer_property_test.go`.
    - **Property 8: Pointer parsing round trips and never panics**
    - **Validates: Requirements 4.8**

  - [x] 5.9 Write property test for store import round trip
    - Create `internal/intel/store/store_property_test.go` using a temporary Pebble directory.
    - **Property 7: Import then lookup round trips by id and purl**
    - **Validates: Requirements 4.3**

- [x] 6. Checkpoint - Group 3
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Group 4: Correlator and risk scorer
  - [x] 7.1 Port the risk scorer
    - Create `internal/risk/score.go` with `Compute` and `Bucket`, using the formula and constants from the design, clamping every input and treating `NaN` as the lower bound. Use a package-local severity type.
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8_

  - [x] 7.2 Implement the pure correlation plan
    - Create `internal/correlate/plan.go` with `Lookup`, `Pkg`, `Plan`, and `PlanSameAs`.
    - `Plan` emits `vulnerability` entities (with `canonical_key`, `summary`, `cvss`, `epss`, `kev`, `severity`, `fixed_in`) and `affected_by` relations for matching packages only.
    - `PlanSameAs` emits `same_as` stars to the smallest-ID anchor for key groups spanning at least two connections, and `likely_same_as` for the repo-name heuristic. Relations carry no attributes.
    - _Requirements: 2.5, 2.6, 2.7, 5.1, 5.2, 5.3, 5.4, 5.5, 5.7_

  - [x] 7.3 Implement the Correlator collector and wire it into Bellud
    - Create `internal/correlate/correlator.go` implementing `collectors.Collector` (name `correlator:intel`, interval 5 min). Return an error when the store has no active generation. Page through packages and keyed entities, build the batch with `Plan` and `PlanSameAs`, and rely on the Runner's full-observation semantics to retire stale vulnerabilities and relations.
    - Subscribe to the change feed, ignore irrelevant kinds and its own output, debounce 2 s, and call `Runner.RunOnce` under a mutex. Wake it from the Syncer `onImported` callback.
    - Edit `cmd/bellud/main.go` to append the Correlator to the collector list.
    - _Requirements: 2.5, 2.6, 5.1, 5.6, 5.7_

  - [x] 7.4 Write property test for the risk score
    - Create `internal/risk/score_property_test.go`.
    - **Property 11: Risk score is bounded, deterministic, monotone, and clamps inputs**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.8**

  - [x] 7.5 Write property test for severity buckets
    - Create `internal/risk/bucket_property_test.go`.
    - **Property 12: Severity buckets are monotone and KEV floors at high**
    - **Validates: Requirements 6.6, 6.7**

  - [x] 7.6 Write property test for cross-connection relation planning
    - Create `internal/correlate/samekey_property_test.go`.
    - **Property 3: Relations are planned only across connections, by key**
    - **Validates: Requirements 2.5, 2.6**

  - [x] 7.7 Write property test for the correlation plan
    - Create `internal/correlate/plan_property_test.go`.
    - **Property 10: The correlation plan contains exactly the matching vulnerabilities**
    - **Validates: Requirements 5.3, 5.6**

- [x] 8. Checkpoint - Group 4
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Group 5: Lens engine, HTTP routes, regeneration, MCP extras
  - [x] 9.1 Implement the pure lens building blocks
    - Create `internal/lens` files for `Slice`, `Node`, `SliceEdge`, `Group`, `Path`, `Risk`, `Confidence(relType)`, path confidence (weakest hop), `Prune`, and `Budget` (deterministic order: root, risk score, hops, Entity_ID).
    - Include the per-kind attribute allowlist.
    - _Requirements: 2.7, 2.8, 7.2, 7.9, 7.11_

  - [x] 9.2 Implement the lens catalog, engine, and service
    - Create `internal/lens/engine.go`, `catalog.go`, `source.go`, and `service.go`.
    - Define the five lenses (`code-to-cloud` default, `cloud`, `blast-radius`, `attack-path`, `vulnerability-reachability`) as Go definitions.
    - Add the read-only `Source` interface and the adapter over `facade.Engine`, type-asserting `facade.Extended` once at `Bind` and returning `ErrUnavailable` otherwise.
    - Build `blast-radius` from `Impact`, `attack-path` from `Path` results from each internet-exposed entity (max 50), and compute vulnerability risk with `risk.Compute`. Return `ErrUnknownLens{ID}` for unknown ids.
    - _Requirements: 1.5, 7.1, 7.2, 7.3, 7.4, 7.7, 7.8, 7.9_

  - [x] 9.3 Add the lens and slice HTTP routes
    - Edit `internal/api/graph/lens.go`: add the `WithLens` option and the handlers `GET /api/experimental/graph/lenses` and `GET /api/experimental/graph/slice` (default lens when `lens` is absent, 404 naming an unknown id, 400 with `field` for bad parameters, 503 `graph_unavailable`, 5 s deadline, clamped `depth` and `limit`, HTTP budget of 500 nodes and 1,000 edges).
    - Edit `cmd/bellud/main.go` to create `lens.Service` before `graph.Open`, call `Bind` after open, and pass it to `apigraph.New`.
    - _Requirements: 7.5, 7.6, 7.7, 7.8, 1.5_

  - [x] 9.4 Add protocol schemas and regenerate the client and route table
    - Create `packages/protocol/src/groups/experimental-graph.ts` with `experimental.graph.lenses`, `experimental.graph.slice`, and `experimental.graph.intelStatus`, each described with "Experimental: may change without compatibility guarantees."
    - Add `Graph.Lens`, `Graph.LensSlice`, and `Graph.IntelStatus` schemas in `packages/schema/src/graph.ts`. Register no TS handlers, because Go owns them.
    - Run from the repo root: `bun services/bellud/script/gen-operations.ts`. Run from `services/bellud`: `go test ./internal/server/routes -run TestGenerate -update -count=1`. Run from `packages/client`: `bun run generate`. If the contract tests report drift, run `bun services/bellud/script/gen-gocontract.ts`. Do not edit generated client files by hand.
    - _Requirements: 7.5, 7.6, 4.9, 10.6_

  - [x] 9.5 Add the MCP tools
    - Add `Config.MCPExtras func(*mcp.Server)` to the facade config and call it from `MCPHandler` after `mcpserver.New`. Add the four tool names to `MCPTools` in `internal/bellugraph/facade/mcp.go`.
    - Create `internal/lens/lensmcp` with `slice`, `attack_paths`, `blast_radius`, and `reachable_vulns`, all with `ReadOnlyHint: true`, a default limit of 100 (max 200), `Budget` applied, and an `extracted` or `inferred` tag on every edge and path.
    - Edit `cmd/bellud/main.go` to pass the extras to `graph.Open`.
    - _Requirements: 1.3, 7.10, 7.11_

  - [x] 9.6 Write property test for confidence
    - Create `internal/lens/confidence_property_test.go`.
    - **Property 4: Confidence is determined by relation type, and a path takes its weakest hop**
    - **Validates: Requirements 2.7, 2.8**

  - [x] 9.7 Write property test for pruning
    - Create `internal/lens/prune_property_test.go`.
    - **Property 13: Pruned slices have no dangling edges**
    - **Validates: Requirements 7.2, 7.9**

  - [x] 9.8 Write property test for the blast radius slice
    - Create `internal/lens/blast_property_test.go`.
    - **Property 14: Blast radius slice equals the impact result**
    - **Validates: Requirements 7.3**

  - [x] 9.9 Write property test for budgeted answers
    - Create `internal/lens/budget_property_test.go`.
    - **Property 15: Budgeted answers are bounded and tagged**
    - **Validates: Requirements 7.2, 7.11**

  - [x] 9.10 Write property test for unknown lens ids
    - Create `internal/lens/unknown_property_test.go`.
    - **Property 16: Unknown lens ids are rejected by name**
    - **Validates: Requirements 7.7, 7.8**

- [x] 10. Checkpoint - Group 5
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Group 6: UI lens switcher, slice rendering, layouts, details, empty state
  - [x] 11.1 Extend the state machine with lens selection
    - Edit `packages/app/src/security-graph/machine.ts` per the design: `loading`, `ready` (with `pending`, `error`, `follow`), `failed`, `disposed` states; `lenses-loaded`, `select`, `loaded`, `slice-failed`, `panned`, `follow`, `failed`, `disposed` events; `fetch-slice` and `persist-lens` effects; attempt ids that reject stale results; and the selectors.
    - Add `resolveLens(stored, lenses, defaultLens)` and persist the lens with `persisted(Persist.global("security-graph.lens"), …)`.
    - _Requirements: 8.1, 8.2, 8.8, 8.9_

  - [x] 11.2 Add slice-to-render-model mapping and i18n keys
    - Create `packages/app/src/security-graph/slice.ts` with `toGraphData(slice)` mapping kinds, relation types, tags, importance, and dashed rendering for `inferred` edges.
    - Edit `packages/app/src/security-graph/graph.css` and the node kind color map for the new node kinds, using theme tokens for everything except type fills.
    - Add English-only keys to `packages/app/src/runtime/i18n/en.ts` for lens names and descriptions, the slice error, follow toggle labels, node details labels, kinds, and edge types.
    - _Requirements: 8.2, 8.6, 8.10_

  - [x] 11.3 Add radial and chain layouts
    - Edit `packages/app/src/security-graph/layout.ts`: add the `kind` argument (`force`, `radial`, `chain`) to `computeLayout`, keep the force path unchanged, and add the pure synchronous radial (ring spacing 170) and chain (column 240, row 150) layouts. Add `layoutFor(lensId)` mapping `blast-radius` to radial, `attack-path` to chain, and the rest to the existing layout.
    - _Requirements: 8.3, 8.4, 8.5_

  - [x] 11.4 Wire the page: lens switcher, slice driver, vulnerability details, empty state
    - Edit `packages/app/src/security-graph/page.tsx` and the renderer mount file in the same folder.
    - Load lenses and slices through `sdk.api.experimental.graph`, with one `AbortController` per attempt and a 20 s first-load fallback. Follow the Suspense guard in `packages/app/AGENTS.md`.
    - Add the Lens_Switcher to the page header. Mount a new graph per lens and kill the old mount only after the new layout is ready, so a failed switch keeps the previous canvas and shows the error message.
    - Show severity, KEV flag, and EPSS in the node details of a vulnerability node.
    - Render the existing dummy graph and hide the switcher while no Connection exists.
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 8.10_

  - [x] 11.5 Write property test for lens resolution
    - Create `packages/app/src/security-graph/machine.resolve.test.ts` (read the `unit-tests` skill first).
    - **Property 17: Lens resolution restores the stored lens only when listed**
    - **Validates: Requirements 8.8**

  - [x] 11.6 Write property test for failed and stale slice results
    - Create `packages/app/src/security-graph/machine.slice.test.ts`.
    - **Property 18: Failed or stale slice results never replace the rendered graph**
    - **Validates: Requirements 8.2, 8.9**

  - [x] 11.7 Write property test for the radial layout
    - Create `packages/app/src/security-graph/layout.radial.test.ts`.
    - **Property 19: Radial layout places nodes by hop count**
    - **Validates: Requirements 8.3**

  - [x] 11.8 Write property test for the chain layout
    - Create `packages/app/src/security-graph/layout.chain.test.ts`.
    - **Property 20: Chain layout increases left to right along every path**
    - **Validates: Requirements 8.4**

- [x] 12. Checkpoint - Group 6
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. Group 7: Agent overlay (hub, scripted replay, SSE route, follow mode, tooltip card)
  - [x] 13.1 Implement the overlay package
    - Create `internal/overlay` with `Event` (`seq`, `entity`, `action` of `focus_node`, `walk_path`, or `proposed_change`, `path`, `explanation`), strict decoding that rejects unknown actions, `Hub` (`Publish`, `Subscribe` with a 64-slot buffer that closes an overflowing subscriber, no history), and `Replay` for the scripted `demo` script (one event every 1.5 s, then end). The package must not import the facade.
    - _Requirements: 9.1, 9.2, 9.6, 9.7_

  - [x] 13.2 Add the overlay SSE route and its protocol entry
    - Edit `internal/api/graph/lens.go`: add `WithOverlay` and `GET /api/experimental/graph/overlay` with `id`, `event: overlay`, `data`, and a 15 s keepalive. The `replay` query builds the demo script from the default lens slice.
    - Edit `cmd/bellud/main.go` to create the hub and pass it to `apigraph.New`.
    - Add `experimental.graph.overlay` (`stream: true`) to `packages/protocol/src/groups/experimental-graph.ts` and `Graph.OverlayEvent` to `packages/schema/src/graph.ts`. Regenerate with the same steps as task 9.4, including `bun run generate` from `packages/client`.
    - _Requirements: 9.1, 9.2, 9.6, 9.7, 10.6_

  - [x] 13.3 Add the overlay client, follow mode, and tooltip card
    - Create `packages/app/src/security-graph/overlay.ts`: open the stream with the app's authenticated fetch, decode frames with the `Graph.OverlayEvent` schema, and add the pure `playable(events, nodeIds)` that keeps only events for rendered entities in order and trims absent ids from `path`.
    - Edit the renderer mount file to return a handle with `focus`, `highlight`, `walk`, `card`, `onPan`, and `kill`. Report user pans only outside programmatic camera animation.
    - Edit `packages/app/src/security-graph/page.tsx` to add the follow toggle, dispatch `panned` and `follow`, and show the tooltip card with the explanation while follow mode is on.
    - Add any remaining English i18n keys to `packages/app/src/runtime/i18n/en.ts`.
    - _Requirements: 9.2, 9.3, 9.4, 9.5, 8.10_

  - [x] 13.4 Write property test for overlay events and ordering
    - Create `internal/overlay/hub_property_test.go`.
    - **Property 21: Overlay events round trip and keep order**
    - **Validates: Requirements 9.1, 9.2**

  - [x] 13.5 Write property test for playable events
    - Create `packages/app/src/security-graph/overlay.test.ts`.
    - **Property 22: Playable events are exactly those naming rendered entities**
    - **Validates: Requirements 9.5**

- [x] 14. Checkpoint - Group 7
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Final checkpoint
  - Record the process start time of each running service, then run these once and in this order. Do not restart any service.
  - From `services/bellud`: `go build ./...` and `go vet ./...`.
  - `bun typecheck` in `packages/client`, `packages/ui`, and `packages/app`.
  - `bun run build` in `packages/app`.
  - `bun run check` from the repository root.
  - Report success only when every command exits with status 0, and confirm each service has the same process start time as before.
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP. They are the property-based tests for the Correctness Properties; pure-logic tests need no network, running service, or cloud credential.
- Each task references specific requirements for traceability.
- The intel status route (5.5) is reachable directly in Go after group 3. Its protocol and route-table entry lands in task 9.4.
- Checkpoints ensure incremental validation. The final checkpoint runs the full build and lint set once, not after each task.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.3", "5.1", "5.2", "7.1"] },
    { "id": 1, "tasks": ["1.4", "1.5", "3.1", "3.2", "5.3", "5.6", "5.8", "7.2", "9.1", "13.1"] },
    { "id": 2, "tasks": ["3.3", "3.4", "5.4", "5.7", "5.9", "7.4", "7.5", "7.6", "7.7", "9.2", "9.6", "9.7", "9.9", "13.4"] },
    { "id": 3, "tasks": ["5.5", "9.8", "9.10"] },
    { "id": 4, "tasks": ["7.3"] },
    { "id": 5, "tasks": ["9.3"] },
    { "id": 6, "tasks": ["9.4", "9.5"] },
    { "id": 7, "tasks": ["11.1", "11.2", "13.2"] },
    { "id": 8, "tasks": ["11.3", "11.5"] },
    { "id": 9, "tasks": ["11.4", "11.6", "11.7", "11.8"] },
    { "id": 10, "tasks": ["13.3"] },
    { "id": 11, "tasks": ["13.5"] }
  ]
}
```
