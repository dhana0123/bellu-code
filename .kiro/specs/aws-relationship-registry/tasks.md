# Implementation Plan: AWS Relationship Registry

## Overview

The work follows the phase order in `design.md` and is implemented in Go under `services/bellud`, with generated TypeScript only where the lens and MCP surface changes. The phases are: baseline fixtures on the unmodified tree, per-source registry, edge attributes, retention, reified nodes and exposure, AWS client and collector, lens and MCP, then docs and the final checkpoint. Each phase ends with a checkpoint.

Path convention: `internal/...` means `services/bellud/internal/...`. The design's shorthand maps as follows:

| Design shorthand | Path |
| --- | --- |
| `bge/...` | `internal/bellugraph/internal/bge/...` (`ident`, `codec`, `plan`, `graph`, `engine`, `query`, `gql`, `mcpserver`, `sse`, `debugui`) |
| `facade` | `internal/bellugraph/facade` |
| `schema`, `schemaall`, `batch` | `internal/graph/schema`, `internal/graph/schemaall`, `internal/graph/batch` |
| `connectors/aws`, `collectors`, `redact`, `lens` | `internal/connectors/aws`, `internal/collectors`, `internal/redact`, `internal/lens` |

Rules for every task:

- Run Go commands from `services/bellud` and TypeScript commands from the package directory. Never run tests from the repo root and never run `tsc` directly.
- Before writing any test, read the `unit-tests` skill under `.bellucode/skills`. Property tests use `pgregory.net/rapid` with at least 100 cases and carry the tag `Feature: aws-relationship-registry, Property N: <title>`.
- Do not edit generated client files, add `.changeset` files, or restart any running service. TypeScript changes use no aliased imports and no star imports.
- Tests need no network, no running service, and no cloud credential.

## Tasks

- [x] 1. Phase 0: Baseline fixtures from the unmodified tree
  - These tasks MUST run before any code in phase 1 moves, so the fixtures capture pre-feature behavior.
  - [x] 1.1 Generate golden vectors and add the golden test
    - Create `internal/bellugraph/internal/bge/ident/golden_gen_test.go` (build-tagged or `-update` gated) that writes `testdata/golden.json` from the current `ident.go`: for every existing kind one identity attribute map with its `Hash` output, every kind with its ordered identity list, and every relation type with its direction.
    - Create `golden_test.go` that asserts all three tables against `ident` and fails on any difference. Commit `golden.json` before any other phase 1 change.
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 16.3_

  - [x] 1.2 Generate Legacy_Data fixtures and the replay tests
    - Create a generator test in `internal/bellugraph/internal/bge/engine` that writes `testdata/legacy/log`, `testdata/legacy/snapshot`, and `testdata/legacy/expected.json` (entities, relations, zero attributes) using the unmodified engine.
    - Create `legacy_test.go` that loads both fixtures and compares them with `expected.json`.
    - Add a test that flips one byte in a record of a copy of the log, opens it, asserts the open aborts naming the record, and asserts the original directory is unchanged.
    - _Requirements: 3.5, 3.6, 7.9, 16.5_

  - [x] 1.3 Freeze the legacy relation encoders for byte comparison
    - Create `internal/bellugraph/internal/bge/codec/legacy_encoder_test.go` holding a verbatim copy of the current `RelationAdded` event body encoder and the `RelationRecord` encoder, used later to prove that zero-attribute bytes are identical.
    - _Requirements: 7.2, 16.5_

- [x] 2. Checkpoint - Phase 0
  - From `services/bellud` run `go build ./...`, `go vet ./...`, and `go test ./internal/bellugraph/...`. Ensure all tests pass, ask the user if questions arise.

- [x] 3. Phase 1: Per-source registry
  - [x] 3.1 Implement the `schema` package
    - Create `internal/graph/schema` with `types.go` (`Direction`, `Confidence`, `Status`, `Source`, `KindDeclaration`, `TypeDeclaration`, `RelationDeclaration`, `CategoryDeclaration`, `SourceDeclaration`), `check.go` (all rules in the design's Check table, `CheckError{Failures}`, sorted deterministic output), `builder.go` (`Builder.Add`, `Build`, `Merge`), and `registry.go` (`Registry` with `Kinds`, `Kind`, `Relations`, `Relation`, `Categories`, `Category`, `CategoryOfType`, `SourceOfKind`, `SourceOfRelation`, `RegisteredOnly`, and `Register` that always returns `ErrImmutable`).
    - Move `IsSecretName` into `schema.IsSecretName`. The package imports only the standard library.
    - `Add` validates a declaration alone and against accepted ones, leaves the builder unchanged on error, and sorts inputs so results are order independent.
    - _Requirements: 1.1, 1.2, 1.3, 1.6, 1.7, 1.8, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.13, 12.6, 12.7_

  - [x] 3.2 Write property tests for merge order independence and each conflict class
    - Create `internal/graph/schema/merge_property_test.go` and `check_property_test.go`.
    - Generate valid declarations; assert the merged registry is equal for every ordering. Inject each defect class (bad name pattern, over-long name, empty or duplicate or secret identity attribute, blank description, invalid confidence, duplicate name in one source, direction conflict, identity-list conflict including order, generic confidence conflict, missing prefix) and assert rejection with an error naming the source, name, and reason for every defect, with identical error text for every ordering. Assert identical generic relations from two sources merge to one entry.
    - **Property 1: Merge is order independent and complete**
    - **Property 2: Invalid declarations are rejected with every failure reported**
    - **Validates: Requirements 1.1, 1.7, 1.8, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.13, 16.1**

  - [x] 3.3 Write property test for registry immutability
    - Create `internal/graph/schema/immutable_property_test.go`.
    - **Property 3: Rejected additions and late additions change nothing**
    - **Validates: Requirements 1.6, 1.8**

  - [x] 3.4 Create the leaf declaration packages and `schemaall`
    - Create `internal/graph/schema/coreschema`, `internal/connectors/github/githubschema`, `internal/correlate/corrschema`, and a minimal `internal/connectors/aws/awsschema` (`aws_account`, `aws_resource` with `resource_type` discriminator, the existing relations the AWS collector emits). Each exports `Declaration()` and its name constants and imports only the standard library and `schema`.
    - Copy every identity list and direction from the current `ident.go` character for character and in order, using the migration table in the design (core, github, correlator, aws).
    - Create `internal/graph/schemaall` with `Sources()` and `Default()` (sync.Once merged registry and error). `lens` uses `schemaall.Default()` later, so it never imports `bge/ident`.
    - _Requirements: 1.1, 3.1, 3.2, 3.3, 4.12_

  - [x] 3.5 Delegate `ident` to the registry and gate `facade.Open`
    - Edit `internal/bellugraph/internal/bge/ident/ident.go`: remove `identityAttrs` and `relDirections`; read from `schemaall.Default()`; keep the signatures and byte layout of `Hash`, `Kinds`, `IdentityAttributes`, `RelationTypes`, `DirectionOf`, `Label`, `IsSecretName` (delegating); add `DefaultConfidence`, `Registry`, `Check`, and `Use`.
    - After a failed merge, lookups behave as unregistered and `Hash` returns `errs.Validation`.
    - Edit `internal/bellugraph/facade` `Open` to call `ident.Check()` first and return `*ConfigError` listing every failure before any store opens. Confirm `cmd/bellud/main.go` `openGraph` exits with that message.
    - _Requirements: 1.4, 1.5, 2.12, 3.7, 3.8, 4.10, 4.11_

  - [x] 3.6 Write property tests for lookups and direction/confidence validity
    - Create `internal/bellugraph/internal/bge/ident/lookup_property_test.go`.
    - **Property 4: Lookups are total and well formed**
    - **Validates: Requirements 1.4, 1.5, 4.4, 4.10, 4.11, 16.2**

  - [x] 3.7 Write property test for Entity_ID stability
    - Create `internal/bellugraph/internal/bge/ident/hash_property_test.go`.
    - **Property 5: Entity_ID depends only on kind and identity attributes**
    - **Validates: Requirements 3.4, 3.7, 3.8**

  - [x] 3.8 Extend `describe_schema`
    - Edit `internal/bellugraph/internal/bge/mcpserver/tools.go` (`describeSchema`, `kindInfo`, `relTypeInfo`, `describeSchemaOut`): keep existing JSON fields; add `description`, `source`, `discriminator`, `types[]` to kinds; `confidence`, `description`, `source`, `derived`, `from[]`, `to[]` to relations; and `categories[]` (`id`, `name`, `status`, `read_ops`) to the response.
    - Sort kinds and relations by name with `sort.Strings`, return empty arrays for empty categories, and return `schema could not be read` with no partial result when `ident.Registry()` fails. Make `describeType` list the new kinds through the same lookups.
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 3.9 Write property test for `describe_schema`
    - Extend `internal/bellugraph/internal/bge/mcpserver/prop_test.go`.
    - **Property 27: describe_schema is complete, sorted, and stable**
    - **Validates: Requirements 5.1, 5.2, 5.4**

  - [x] 3.10 Extend the architecture tests
    - Edit `internal/connectors/arch_test.go` and add a sibling test: leaf `...schema` packages import only the standard library and `schema`; `connectors/aws` and `connectors/github` do not import `bellugraph` or `ident`; `lens` does not import `bge/ident`. Keep every existing rule, with no new skips.
    - _Requirements: 11.3, 15.2_

- [x] 4. Checkpoint - Phase 1
  - From `services/bellud` run `go build ./...`, `go vet ./...`, and `go test ./internal/graph/... ./internal/bellugraph/... ./internal/connectors/...`. The golden and legacy tests from phase 0 must pass unchanged. Ensure all tests pass, ask the user if questions arise.

- [x] 5. Phase 2: Edge attributes
  - [x] 5.1 Encode edge attributes in the codec
    - Edit `internal/bellugraph/internal/bge/codec/event.go` and `snapshot.go`: add `EdgeAttrs` (with `Has` bitmask, `Zero`, `Equal`), `AppendEdgeAttrs`, event type `RelationUpdated = 8`, `Event.EdgeAttrs`, and `RelationRecord.Attrs`.
    - Write the optional trailer `0x01 | flags | present strings` only when `Has != 0`; keep `eventVersion` and `snapVersion` at 1.
    - Decoders accept no remaining bytes as zero attributes, parse tag `0x01`, and otherwise fail with `errs.Corrupt` and `codec: unknown trailing field set 0x%02x at byte %d of record (seq %d)`. Reject flags above `0x07`, truncated strings, and bytes after the section. Return the zero value on every failure.
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 5.2 Write property tests for zero-attribute bytes and codec round trip
    - Create `internal/bellugraph/internal/bge/codec/edgeattr_prop_test.go` using the frozen encoder from task 1.3.
    - **Property 8: Zero-attribute encoding is byte identical to the legacy format**
    - **Property 9: Codec round trip with attributes**
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.5, 16.5**

  - [x] 5.3 Write property test for unknown trailing field sets
    - Add to `internal/bellugraph/internal/bge/codec/edgeattr_prop_test.go`.
    - **Property 10: Unknown trailing field sets are decode errors**
    - **Validates: Requirements 7.4**

  - [x] 5.4 Validate and classify relation attributes in `plan`
    - Edit `internal/graph/batch/batch.go` (update the `Relation` doc comment) and `internal/bellugraph/internal/bge/plan/plan.go`: replace the "carries attributes" rejection with `edgeAttrs(r)` applying the validation table (name set, `evidence` string at most 512 bytes, `confidence` exactly `extracted` or `inferred`, `observed_at` RFC 3339, redaction value rule, conflicting duplicate `(type, from, to)`), all as `errs.Validation` rejecting the whole batch.
    - Add `redact.ValueLeak(s string) (string, bool)` in `internal/redact/guard.go`.
    - Implement the classification table: `RelationAdded` for absent, `RelationUpdated` for changed attributes, none for unchanged, with the event order from the design.
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.9, 6.10_

  - [x] 5.5 Scrub and guard relation attributes
    - Edit `internal/redact/guard.go` so `Scrub`, `Leaks`, and `FirstLeak` also run the value rules over `Relation.Attributes` values.
    - Edit `internal/connectors/redactor/redactor.go` (loop over `b.Relations`) to scrub the same values before the guard runs.
    - _Requirements: 6.9_

  - [x] 5.6 Fold edge attributes into the projection and the change feed
    - Edit `internal/bellugraph/internal/bge/graph/graph.go` and `snapshot.go`: add `RelState.Attrs`, set it in `foldRelAdded`, add `foldRelUpdated` (live relations only), and copy it in `Export`, `Import`, and `Clone`.
    - Edit `internal/bellugraph/internal/bge/engine/read.go` (`changeKindSubject` maps `RelationUpdated` to `ChangeChanged`, `SubjectRelation`), the digest and flap counting in `asof.go` so relation updates are never flaps, and the `Reader` interface in `internal/bellugraph/internal/bge/query/find.go` to add `Relation(graph.RelKey)`.
    - Make as-of reads in `engine/asof.go` return the attributes produced by events at or before T.
    - _Requirements: 6.6, 6.11, 7.6, 7.7, 7.8_

  - [x] 5.7 Mirror attributes in the reference model and generators
    - Edit `internal/bellugraph/internal/bge/internal/gen/model/model.go` to mirror validation, classification, and fold for edge attributes, and `gen/gen.go` to add `gen.RelAttrs()` with a negative variant that injects one defect.
    - _Requirements: 6.1, 6.2, 6.7, 7.6_

  - [x] 5.8 Write property test for Edge_Attribute validation
    - Create `internal/bellugraph/internal/bge/plan/edgeattr_prop_test.go`: accept every name in the set, reject every other name, accept `extracted` and `inferred` only, accept 512 bytes of evidence and reject 513, accept and reject timestamps per RFC 3339, reject secret-like values, and assert the stored graph (entities, relations, attributes, last sequence) is unchanged after a rejection.
    - **Property 6: Edge attribute validation is all or nothing**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.9, 16.4**

  - [x] 5.9 Write property test for re-assertion and flaps
    - Create `internal/bellugraph/internal/bge/engine/edgeattr_prop_test.go`.
    - **Property 7: Re-asserting relations replaces attributes and is idempotent**
    - **Validates: Requirements 6.6, 6.7, 6.10, 6.11**

  - [x] 5.10 Write property tests for replay, snapshot restore, and as-of reads
    - Extend `internal/bellugraph/internal/bge/engine/replay_prop_test.go` and `asof_prop_test.go`.
    - **Property 11: Replay, snapshot restore, and as-of reads preserve attributes**
    - **Validates: Requirements 7.6, 7.7, 7.8**

  - [x] 5.11 Expose attributes in views and GraphQL
    - Add `Evidence`, `Confidence`, `ObservedAt` to `engine.EdgeView` (`engine/read.go`), `query.Edge`, and `facade.Edge`.
    - Edit `internal/bellugraph/internal/bge/gql/schema.graphqls` (`Edge`: `evidence`, `confidence`, `observedAt`), `convert.go`, and `resolvers.go`. Read `gqlgen.yml` and the `go:generate` line first and record whether gqlgen needs a pinned version; regenerate with the pinned or existing version.
    - _Requirements: 6.1, 14.5_

  - [x] 5.12 Expose attributes in MCP, SSE, and the debug UI
    - Edit `internal/bellugraph/internal/bge/mcpserver/views.go` (`EdgeOut` gains `evidence`, `confidence`, `observed_at` with `omitempty`; `projectEdge` fills them), `sse/sse.go` (relation frame and `subscribe` matcher unchanged), and `debugui/templates` (three fields, HTML escaped).
    - _Requirements: 14.5, 14.6_

  - [x] 5.13 Update the tests that assert relations take no attributes
    - Rewrite each test to assert "a name outside the fixed set is rejected and valid fixed names are accepted": `internal/bellugraph/internal/bge/plan/plan_test.go`, `reject_prop_test.go`, `logs_metrics_prop_test.go`, `internal/bellugraph/facade/graph_test.go`, `internal/collectors/e2e_test.go`, `internal/connectors/iac_test.go`, `internal/lens/confidence_property_test.go`. Locate each with `file_search` first.
    - _Requirements: 16.6_

  - [x] 5.14 Write tests for the attribute surfaces and flaps
    - Add example tests: GraphQL, MCP `get_neighbors`, SSE, and the debug UI return attributes for one relation that has them and omit them for one that does not; the debug UI output is escaped; an attribute-only change adds no flap to the digest.
    - _Requirements: 6.11, 14.5, 14.6_

- [x] 6. Checkpoint - Phase 2
  - From `services/bellud` run `go build ./...`, `go vet ./...`, and `go test ./internal/graph/... ./internal/bellugraph/... ./internal/redact/... ./internal/collectors/... ./internal/connectors/... ./internal/lens/...`. Ensure all tests pass, ask the user if questions arise.

- [x] 7. Phase 3: Retention, AWS declaration, reified nodes, exposure
  - [x] 7.1 Add `Retain` to the batch and the planner
    - Edit `internal/graph/batch/batch.go` (`Retain{Kind, Attrs}` and `Batch.Retain`), `plan.go` (in full mode skip retirement of entities that match any rule and keep relations whose `From` or `To` entity matches; create no event), `internal/redact/guard.go` (pass `Retain` through `Scrub` unchanged), and `bge/internal/gen/model/model.go` (mirror the retention).
    - _Requirements: 11.8, 11.9, 11.12, 11.13_

  - [x] 7.2 Add truncations to Run_Status
    - Edit `internal/collectors` (`RunStatus.Truncations []Truncation{Scope, Omitted}`, `StatusRecorder.Truncate`, `Reset` clears it, `Status()` copies it) and the connector lifecycle (`internal/connectors/lifecycle`) to store it next to `DeniedScopes`.
    - _Requirements: 8.6, 11.7_

  - [x] 7.3 Write property test for plan retention
    - Create `internal/bellugraph/internal/bge/plan/retain_prop_test.go`.
    - **Property 19: A failed type keeps its entities and a succeeded type retires**
    - **Validates: Requirements 11.8, 11.9, 11.12, 11.13**

  - [x] 7.4 Declare the full AWS kinds, types, and categories
    - Edit `internal/connectors/aws/awsschema`: add `aws_sg_rule`, `aws_cidr`, `aws_policy_statement` (identity lists from design 3.2), the `aws_resource` types of design 3.3 with their categories, the seven `CategoryDeclaration`s with `Status` and the `ReadOps` of design 3.4, and one constant per kind, type, and category.
    - Document in the kind descriptions every scalar attribute a lens reads (`internet_exposed`, `internet_open`, `from_port`, `to_port`, `direction`, `rules_truncated`, `truncated`, `region`, `resource_type`) with value type and permitted values.
    - _Requirements: 8.1, 9.1, 9.2, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.9, 10.10, 12.1, 12.2_

  - [x] 7.5 Declare the 59 AWS relation types and the required-name list
    - Edit `internal/connectors/aws/awsschema`: one `RelationDeclaration` per row of the design 3.1 table (name, from, to, direction, confidence, one-line description of at most 200 characters that applies the Direction_Rule). Set `derived: true` on `aws_allows_ingress_from`, `aws_allows_egress_to`, and `aws_can_access`. State in the descriptions that `aws_attached_policy` does not establish effective access and that Authorization_Analysis produces `aws_can_access`.
    - Add `awsschema.Required` (every name from Requirements 10.1 to 10.7) and the check that rejects the `aws` declaration with one failure per missing name.
    - Keep `attached_to` registered in `core`. Record the two `aws_dns_points_to` target cases in the description.
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.6, 4.7, 4.8, 4.9, 10.8, 10.10, 10.12_

  - [x] 7.6 Write the design-table and declaration tests
    - Create `internal/connectors/aws/awsschema/table_test.go`: parse the 59-row relation table, kind table, and category table from `.kiro/specs/aws-relationship-registry/design.md` and assert row count 59, equality with the declaration (names, directions, confidences, justification length at most 200), and the declaration facts listed in the design testing strategy.
    - _Requirements: 4.5, 4.7, 4.8, 4.9, 10.11_

  - [x] 7.7 Write the required-name rejection test and new-kind golden vectors
    - Create `internal/graph/schema/required_property_test.go`: remove each required AWS name in turn, assert the `aws` declaration is rejected naming that name, and assert previously accepted sources are unchanged.
    - Append one golden vector per new kind to `internal/bellugraph/internal/bge/ident/testdata/golden.json` (written after the change; the pre-feature vectors stay untouched) and extend `golden_test.go`.
    - **Property 2: Invalid declarations are rejected with every failure reported** (missing required AWS name)
    - **Validates: Requirements 3.4, 10.12, 16.1**

  - [x] 7.8 Generate and check the roadmap table
    - Add `schema.RoadmapMarkdown(r *Registry) string` in `internal/graph/schema` and `roadmap_test.go` that compares it with the block between `<!-- roadmap:start -->` and `<!-- roadmap:end -->` in `docs/features/security-graph/README.md`; `go test ./internal/graph/schema -update` rewrites the block.
    - Add the two markers to the README and run `-update` once. Assert one row per category with status `implemented` or `registered-only` and at least one read operation per registered-only row.
    - _Requirements: 12.1, 12.2, 12.6_

  - [x] 7.9 Implement Rule_Node identity and caps
    - Create `internal/connectors/aws/rules.go` with `RuleID(r SGRule) string` (provider id when present, else `"d-" + hex(sha256(canon)[:16])` with the canonical form from the design), the `internet_open` helper (`0.0.0.0/0`, `::/0` only), and a pure `capRules` that sorts by `rule_id`, keeps the first N, and reports the omitted count.
    - Define the `SGRule` projection type in `internal/connectors/aws/client.go` (the one type this function needs; task 9.1 adds the rest).
    - _Requirements: 8.2, 8.4, 8.6, 8.7_

  - [x] 7.10 Write property test for Rule_Node identity
    - Create `internal/connectors/aws/rules_property_test.go`: same id across permutations and repeats, different ids for any rule differing in direction, protocol, ports, or peer, and provider id preferred.
    - **Property 12: Rule identity is deterministic and distinguishing**
    - **Validates: Requirements 8.2, 8.4, 16.7**

  - [x] 7.11 Implement the exposure function
    - Create `internal/connectors/aws/exposure.go` with `Tri`, `OpenRule`, `NACLEntry`, `ExposureInput`, `Exposure`, `Evaluate` (truth table rows 1 to 7 in order), `NACLAllows` (lowest-numbered entry that covers the whole range, `Unknown` on partial overlap, implicit deny), and the evidence and confidence rules. Replace the old two-input `exposed()` and delete the old exposure property test body so the new one replaces it.
    - _Requirements: 9.3, 9.4, 9.5, 9.6, 9.12, 9.13_

  - [x] 7.12 Write property test for the exposure truth table
    - Rewrite `internal/connectors/aws/exposure_property_test.go`: `true` if and only if address, ingress, route, and NACL all hold; `partial` only under unknown facts, unknown route, unknown NACL, or NACL deny; `false` otherwise, including no public address or no open ingress rule; include boundary inputs.
    - **Property 15: Exposure follows the truth table**
    - **Validates: Requirements 9.3, 9.4, 9.6, 9.12, 9.13, 16.8**

  - [x] 7.13 Write property tests for NACL evaluation and exposure evidence
    - Create `internal/connectors/aws/nacl_property_test.go` and extend `exposure_property_test.go`.
    - **Property 16: NACL evaluation uses the first matching entry**
    - **Property 17: Exposure evidence and confidence**
    - **Validates: Requirements 9.3, 9.5, 9.6, 9.13**

- [x] 8. Checkpoint - Phase 3
  - From `services/bellud` run `go build ./...`, `go vet ./...`, and `go test ./internal/graph/... ./internal/bellugraph/... ./internal/connectors/... ./internal/collectors/... ./internal/redact/...`. Ensure all tests pass, ask the user if questions arise.

- [x] 9. Phase 4: AWS client and collector
  - [x] 9.1 Extend the Client interface and decide the Listing shape
    - Edit `internal/connectors/aws/client.go`: add the projection types of design 7.1 (`Subnet`, `ENI`, `Route`, `RouteTable`, `InternetGateway`, `NATGateway`, `NetworkACL`, `VPCEndpoint`, `PeeringConnection`, `ElasticIP`, `TransitGateway`, `TGWAttachment`, `LoadBalancer`, `TargetGroup`, `Listener`, `TargetHealth`), `Listing[T]`, `Instance.ENIIDs`, and the 16 new `Client` methods. Remove `SecurityGroup.OpenToInternet`.
    - Decide and record: before editing, count the existing constructions of `Instances`, `SecurityGroups`, `VPCs` in `client_test.go` and `collector_test.go`. If few, return `Listing` directly. Otherwise add sibling methods that return the flag. Write the decision as a comment above the interface.
    - Update every fake `Client` in existing tests so the package compiles.
    - _Requirements: 11.1, 11.2, 11.3, 11.7_

  - [x] 9.2 Implement the SDK adapter
    - Edit `internal/connectors/aws/client.go` and `go.mod`/`go.sum` (add `github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2`): add `elbv2At(region)` built through the same broker HTTP client, the 16 new calls with SDK paginators, `capped(ctx, 10000, ...)` setting `Truncated`, `maxPages = 100`, `mapErr` on every call, and projections that copy only the listed fields.
    - _Requirements: 11.1, 11.2, 11.3, 11.7, 15.1_

  - [x] 9.3 Add the read operations to the manifest
    - Edit `internal/connectors/aws/manifest.go`: add the 16 operations of Requirement 11.5 as `manifest.ClassRead` with `hostEC2` or a new `hostELB = "elasticloadbalancing.{region}.amazonaws.com"`, and add `hostELB` to `Egress`.
    - _Requirements: 11.4, 11.5, 11.6_

  - [x] 9.4 Write the manifest, template, and read-only tests
    - Extend `manifest_test.go` and `templates_test.go`: the 16 names exist, are `ClassRead`, have a host, use only `Describe`/`List`/`Get` verbs, `hostELB` is in `Egress`, and both managed policy ARNs are in every template.
    - Extend `internal/connectors/arch_test.go` to fail on any `Create`, `Update`, `Delete`, `Put`, `Tag`, `Modify`, `Attach`, `Associate`, or `Run` verb in an `aws` manifest operation.
    - _Requirements: 11.5, 11.6, 15.1, 16.10_

  - [x] 9.5 Restructure the collector into steps
    - Edit `internal/connectors/aws/collector.go` and add `steps.go` and `arn.go`: the `step` struct (`name`, `types`, `global`, `deps`, `run`), the dependency order of design 7.4, `each`/`once` recording failed steps and `<step>@<region>` denied scopes, credential rejection ending the run, the all-types-failed error, a `partition(region)` ARN builder for every resource type, and the second-pass relation emission that skips relations with a missing endpoint.
    - Append `Retain` rules for failed, denied, and truncated steps, and call `StatusRecorder.Truncate` and set `truncated="true"` on the account entity when a `Listing` is truncated. Replace local `kindAccount`/`kindResource` with the `awsschema` constants.
    - Emit `aws_resource` for VPCs and subnets, ENIs with `aws_in_subnet`, `aws_in_vpc`, and `aws_member_of_sg`, each with `canonical_key` from `canonical.Key`.
    - _Requirements: 9.2, 9.7, 9.14, 11.1, 11.7, 11.8, 11.9, 11.10, 11.11, 11.13, 11.14, 11.15_

  - [x] 9.6 Collect routing, gateways, and connectivity resources
    - Create `internal/connectors/aws/network.go` and register the steps: route tables with `ec2:route` entities, `aws_route_of`, `aws_routes_to` (evidence lists destinations), `aws_associated_subnet`; internet gateways with `aws_attached_igw`; NAT gateways with `aws_nat_in_subnet`; network ACLs; Elastic IPs with `aws_assigned_to`; VPC endpoints; peering (`aws_peers_with` in both directions only for status `active`); transit gateways and attachments with `aws_tgw_attached`.
    - _Requirements: 9.7, 9.8, 9.9, 9.10, 11.1, 11.2_

  - [x] 9.7 Collect security groups as Rule_Nodes
    - Create `internal/connectors/aws/sgrules.go` and register the `security-groups` and `sg-rules` steps: one `aws_sg_rule` per distinct rule through `RuleID`, `aws_rule_of`, `aws_rule_peer` to a shared `aws_cidr` node or the collected peer group, `internet_open`, `name` label, caps `maxRulesPerSG = 200` and `maxRuleNodesPerConn = 20000` as collector fields, `rules_truncated` and `rules_omitted` flags, `Truncations` entries, and the per-group and `aws_cidr` retain rules. A peer group or prefix list that was not collected keeps `peer_sg` or `prefix_list` as an attribute with no edge.
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 9.14, 11.1_

  - [x] 9.8 Collect load balancers
    - Create `internal/connectors/aws/lb.go` and register the `lb`, `target-group`, `listener`, and `target-health` steps: `aws_lb_listener_of`, `aws_lb_forwards_to`, `aws_targets`, ENI and subnet links for load balancers, using the ARNs the API returns.
    - _Requirements: 9.11, 11.2_

  - [x] 9.9 Wire exposure and the remaining relation changes
    - Create `internal/connectors/aws/exposure_wire.go`: derive `ExposureInput` for each instance and load balancer (public address across ENIs, union of groups, associated or main route table with `RouteDerived`, subnet ACL), turn failed calls into `Unknown` facts, take the best state across ENIs, set `internet_exposed`, and emit `aws_exposed_via` with sorted, size-limited `evidence`, `confidence`, and `observed_at` only from an API timestamp (never the run time).
    - Emit `aws_has_eni`, stop emitting `attached_to`, keep `owned_by` and `runs_on`, and emit `aws_dns_points_to` or `resolves_to` per the design's target-case table where Route 53 data exists.
    - _Requirements: 9.3, 9.4, 9.5, 9.6, 9.7, 9.13, 10.8, 4.6, 6.10_

  - [x] 9.10 Write the collector test with a fake Client
    - Extend `internal/connectors/aws/collector_test.go` with a fake `Client` and an in-memory engine: the emitted Batch passes `Ingest().Apply`; an entity absent from a later run is retired; a type whose listing fails keeps its entities and relations; a denied scope is recorded as `<type>@<region>`; rejected credentials end the run with no apply; every type failing returns an error and no batch; each cap sets `truncated` or `rules_truncated` and is not set below the cap; `attached_to` is not emitted.
    - _Requirements: 8.6, 11.7, 11.8, 11.9, 11.10, 11.11, 11.12, 11.13, 11.14, 16.9_

  - [x] 9.11 Write property tests for collector output
    - Create `internal/connectors/aws/collector_property_test.go` and `listing_property_test.go`.
    - **Property 13: Rule node emission invariants**
    - **Property 14: Caps set truncation flags exactly when exceeded**
    - **Property 18: Emitted network relations are well formed**
    - **Property 19: A failed type keeps its entities and a succeeded type retires** (collector half)
    - **Validates: Requirements 8.1, 8.3, 8.5, 8.6, 8.7, 9.7, 9.8, 9.9, 9.10, 9.11, 9.14, 11.7, 11.8, 11.9, 11.12, 11.13, 11.14, 11.15**

- [x] 10. Checkpoint - Phase 4
  - From `services/bellud` run `go build ./...`, `go vet ./...`, and `go test ./internal/connectors/... ./internal/collectors/... ./internal/bellugraph/...`. Ensure all tests pass, ask the user if questions arise.

- [x] 11. Phase 5: Lens and MCP
  - [x] 11.1 Read confidence from the registry and carry evidence
    - Edit `internal/lens/` (`slice.go`, `engine.go`): `Confidence(relType)` reads `schemaall.Default()`, add `EdgeConfidence(relType, attr)` (valid stored value wins, otherwise the default), use it in `addEdge` with `facade.Edge.Confidence`, add `SliceEdge.Evidence` and `ObservedAt`, add `truncUTF8(s, 512)`, and keep `PathConfidenceOfEdges` weakest-hop. Update `confidence_property_test.go` for the registry-based default.
    - _Requirements: 6.8, 13.6, 14.1, 14.2, 14.3, 14.4, 14.5, 14.7, 14.9_

  - [x] 11.2 Write property tests for confidence and evidence
    - Create or extend `internal/lens/confidence_property_test.go` and `evidence_property_test.go`.
    - **Property 20: Edge and path confidence**
    - **Property 21: Evidence is cut on a character boundary**
    - **Validates: Requirements 6.8, 13.6, 14.1, 14.2, 14.3, 14.4, 14.7, 14.9**

  - [x] 11.3 Add needs and `missing_data`
    - Edit `internal/lens/catalog.go`, `slice.go`, `engine.go`: `Def.Needs`, `Slice.MissingData` (never nil), `Counts.OmittedRules`, the needs table of design 8.2, `Registry.RegisteredOnly`, and the `no_internet_exposed_entity` sentinel for `attack-path`. Compute `missing_data` only from lens, tool, and parameters.
    - _Requirements: 12.3, 12.4, 12.5, 12.6, 12.7, 13.3, 13.5, 13.9, 13.10_

  - [x] 11.4 Write property test for `missing_data`
    - Create `internal/lens/needs_property_test.go`.
    - **Property 24: missing_data is the registered-only part of the needs**
    - **Validates: Requirements 12.3, 12.4, 12.5, 12.6, 12.7, 13.3, 13.5, 13.10**

  - [x] 11.5 Collapse rule nodes and update the lens definitions
    - Create `internal/lens/collapse.go` implementing design 8.4: replace each `aws_sg_rule` with `aws_allows_ingress_from` or `aws_allows_egress_to` between group and peer, evidence from direction, protocol, and ports, weakest-hop confidence, rebuild paths, and count rules without a peer in `omitted_rules`.
    - Edit `catalog.go`: `Def.CollapseRules` (default true for `cloud` only, overridable by `collapse_rules`), add `aws_sg_rule` and `aws_cidr` to `cloud` and `code-to-cloud` kinds, and set `MaxPathDepth = 6` for attack paths.
    - _Requirements: 8.8, 8.9, 13.2, 13.4, 13.7_

  - [x] 11.6 Order the budget so rule nodes drop first
    - Edit `internal/lens/budget.go`: `nodeLess` gets a leading class (root and path nodes, then other kinds, then `aws_sg_rule`), the existing order within a class, drop from the end, and `Prune` afterwards.
    - _Requirements: 8.10, 13.11_

  - [x] 11.7 Write property tests for collapse and budget
    - Create `internal/lens/collapse_property_test.go` and extend `budget_property_test.go`: collapsing removes every rule node and yields one distinct-evidence edge per distinct rule; rule nodes drop before any other kind; the root and path nodes drop last; after collapse and budget every edge has both endpoints in the node set; output is deterministic.
    - **Property 22: Collapsing rule nodes keeps distinct rules distinct**
    - **Property 23: Budget drops rule nodes first and keeps roots and paths**
    - **Validates: Requirements 8.8, 8.9, 8.10, 13.11, 16.11**

  - [x] 11.8 Implement network reach and the exposure questions
    - Create `internal/lens/netreach.go` (`NetGraph`, `NetworkReach` bounded by depth 6, ordered by `(hops, id)`) and wire it into `blast-radius` for AWS compute entities, tagging network-only results `via: network`.
    - Add `exposed_resources` logic (entities with an attached group that has an ingress rule with `internet_open=true`) and the `target_type` parameter for `attack-path` (paths from `internet_exposed=true` entities to every entity of that type, such as `rds:instance`).
    - _Requirements: 13.1, 13.2, 13.4, 13.8, 13.9_

  - [x] 11.9 Write property tests for impact direction and network reach
    - Extend `internal/bellugraph/internal/bge/query/path_impact_prop_test.go` and create `internal/lens/netreach_property_test.go`.
    - **Property 25: Impact follows registered directions only**
    - **Property 26: Network reach follows the network chain**
    - **Validates: Requirements 13.1, 13.2, 13.8**

  - [x] 11.10 Update the MCP tools
    - Edit `internal/lens/lensmcp` and `internal/bellugraph/facade/mcp.go`: add the read-only `exposed_resources` tool (`ReadOnlyHint: true`) to `MCPTools`, add `target_type` and `collapse_rules`, return `missing_data` from `slice`, `attack_paths`, `blast_radius`, `reachable_vulns`, and `exposed_resources`, and include `evidence` and `observed_at` in every edge and path hop (`omitempty`).
    - _Requirements: 12.3, 12.4, 13.8, 13.9, 14.6_

  - [x] 11.11 Update the HTTP slice route
    - Edit `internal/api/graph/lens.go`: accept `collapse_rules` and `target_type`, validate them with a 400 naming `field`, and return `missing_data`, edge `evidence` and `observed_at`, and `counts.omitted_rules`.
    - _Requirements: 8.8, 13.9, 14.5, 14.8_

  - [x] 11.12 Update protocol and schema, then regenerate
    - Edit `packages/schema/src/graph.ts` (`Graph.LensSlice`, `Graph.LensEdge`, `Graph.LensCounts`: new fields optional) and `packages/protocol/src/groups/experimental-graph.ts` (optional `collapse_rules` and `target_type` query parameters).
    - From the repo root run `bun services/bellud/script/gen-operations.ts`. From `services/bellud` run `go test ./internal/server/routes -run TestGenerate -update -count=1` and confirm `routes.yaml` does not change. From `packages/client` run `bun run generate`. If contract tests report drift, run `bun services/bellud/script/gen-gocontract.ts` from the repo root. Do not edit generated client files.
    - Run `bun typecheck` in `packages/schema`, `packages/protocol`, `packages/client`, and `packages/app`, and run `bun test` in `packages/protocol` for `test/experimental-identifiers.test.ts` (from the package directory).
    - _Requirements: 14.8_

- [x] 12. Checkpoint - Phase 5
  - From `services/bellud` run `go build ./...`, `go vet ./...`, and `go test ./internal/lens/... ./internal/api/... ./internal/bellugraph/... ./internal/server/...`. Run `bun typecheck` in `packages/schema`, `packages/protocol`, `packages/client`, and `packages/app`. Ensure all tests pass, ask the user if questions arise.

- [x] 13. Phase 6: Documentation
  - [x] 13.1 Write the README sections
    - Edit `docs/features/security-graph/README.md`: add sections for the per-source registry, naming convention, Direction_Rule, Edge_Attributes (limits, replace semantics, no-op rule, and the note that downgrade after the first attribute write is unsupported), Reified_Node rule, and Roadmap (keep the generated block between the markers), and the amendment paragraph that supersedes Requirement 2.7 for the three attributes only. Remove the statement that relations have no attributes.
    - _Requirements: 6.1, 7.2, 12.1, 15.3, 15.5, 15.6_

  - [x] 13.2 Update "Add a new Collector" and the experimental-routes note
    - Edit `docs/features/security-graph/README.md`: replace the `ident.go` registration step with the four ordered registry sub-steps (declare in the leaf `...schema` package, add to `schemaall.Sources()`, run `go test ./internal/graph/schema/... ./internal/bellugraph/...`, justify each direction with the Direction_Rule), point the "Relation types" section at the registry, state that routes under `/api/experimental/graph/` may change or be removed without compatibility guarantees or deprecation notice, and document the protocol regeneration sequence from task 11.12.
    - _Requirements: 15.4, 15.8_

  - [x] 13.3 Add the amendment notes to the unified-security-graph spec
    - Edit `.kiro/specs/unified-security-graph/requirements.md` and `design.md`: under the first heading of each add the note "Requirement 2.7 (relations carry no attributes) is amended by `.kiro/specs/aws-relationship-registry`. Relations may carry `evidence`, `confidence`, and `observed_at`; every other relation attribute is still rejected."
    - _Requirements: 15.6, 15.7_

  - [x] 13.4 Write a test for the README sections
    - Add to `internal/graph/schema/roadmap_test.go` a check that each required README section heading exists and the roadmap block equals `RoadmapMarkdown`.
    - _Requirements: 15.3_

- [x] 14. Final checkpoint - Ensure all tests pass
  - From `services/bellud` run `go build ./...`, `go vet ./...`, and `go test ./...`.
  - Run `bun typecheck` from each touched package directory: `packages/schema`, `packages/protocol`, `packages/client`, `packages/app`.
  - Run `bun run check` from the repository root.
  - Report success only when every command exits with status 0. If any command exits non-zero, name each failing command with its exit status and do not report success. Do not restart any service.
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 16.12, 16.13, 16.14_

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP. Tests that the requirements name explicitly (Requirement 16) are required and are not marked.
- Phase 0 runs on the unmodified tree so the golden vectors and Legacy_Data fixtures describe pre-feature behavior.
- The `Listing` shape decision is made in task 9.1 and the gqlgen pin decision in task 5.11, where each is first needed. Both are recorded in code comments or the task's commit message.
- `lens` reads the registry through `schemaall.Default()`; the design's `schema.Default()` is placed in `schemaall` to avoid an import cycle with the leaf packages.
- Every correctness property from the design maps to a task: P1, P2 (3.2, 7.7), P3 (3.3), P4 (3.6), P5 (3.7), P6 (5.8), P7 (5.9), P8, P9 (5.2), P10 (5.3), P11 (5.10), P12 (7.10), P13, P14, P18 (9.11), P15 (7.12), P16, P17 (7.13), P19 (7.3, 9.11), P20, P21 (11.2), P22, P23 (11.7), P24 (11.4), P25, P26 (11.9), P27 (3.9).
- No `.changeset` files are added. Generated client files are regenerated, never edited by hand.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.3"] },
    { "id": 1, "tasks": ["3.1"] },
    { "id": 2, "tasks": ["3.2", "3.3", "3.4"] },
    { "id": 3, "tasks": ["3.5", "3.10"] },
    { "id": 4, "tasks": ["3.6", "3.7", "3.8", "5.1"] },
    { "id": 5, "tasks": ["3.9", "5.2", "5.3", "5.4"] },
    { "id": 6, "tasks": ["5.5", "5.6"] },
    { "id": 7, "tasks": ["5.7", "5.11"] },
    { "id": 8, "tasks": ["5.8", "5.9", "5.10", "5.12", "5.13"] },
    { "id": 9, "tasks": ["5.14", "7.1", "7.2", "7.4", "7.9", "7.11"] },
    { "id": 10, "tasks": ["7.3", "7.5", "7.10", "7.12", "7.13"] },
    { "id": 11, "tasks": ["7.6", "7.7", "7.8"] },
    { "id": 12, "tasks": ["9.1", "9.3"] },
    { "id": 13, "tasks": ["9.2", "9.4", "9.5"] },
    { "id": 14, "tasks": ["9.6"] },
    { "id": 15, "tasks": ["9.7"] },
    { "id": 16, "tasks": ["9.8"] },
    { "id": 17, "tasks": ["9.9"] },
    { "id": 18, "tasks": ["9.10", "9.11"] },
    { "id": 19, "tasks": ["11.1"] },
    { "id": 20, "tasks": ["11.2", "11.3"] },
    { "id": 21, "tasks": ["11.4", "11.5"] },
    { "id": 22, "tasks": ["11.6"] },
    { "id": 23, "tasks": ["11.7", "11.8"] },
    { "id": 24, "tasks": ["11.9", "11.10", "11.11"] },
    { "id": 25, "tasks": ["11.12"] },
    { "id": 26, "tasks": ["13.1", "13.3"] },
    { "id": 27, "tasks": ["13.2"] },
    { "id": 28, "tasks": ["13.4"] }
  ]
}
```
