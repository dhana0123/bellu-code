# Requirements Document

## Introduction

The Unified Security Graph connects sources to one read-only graph and presents it through lenses. The pipeline is: sources → connectors → collectors → one graph engine (Bellud) → lenses (graph types) → UI and AI context over MCP. Every stage is read-only with respect to the customer's systems.

The first release ships a GitHub collector and an AWS collector. Bellud downloads signed threat intelligence from Bellu Cyber Global Intel (a separate server) in one direction only, and sends no customer data back. A correlator matches intel against package entities and creates vulnerability entities only for matches (match-then-materialize). A risk score, ported from Bellu Cyber `internal/risk`, ranks each finding. A lens engine in Bellud returns one output format to both the UI and MCP. The app renders lenses on a Sigma canvas, and an agent overlay animates what an AI is doing on that canvas.

The Bellu Cyber code in `global-intel` (canonical model, release bundle, correlation matching) and `internal/risk` is a reference to port to Go in Bellud. Bellud does not import it. Bellu Cyber publishes the feed outside this scope; this feature only documents the `latest.json` pointer contract.

## Glossary

- **Bellud**: The Go service at `services/bellud` that hosts connectors, collectors, the graph engine, the intel store, the lens engine, and the HTTP API.
- **Graph_Engine**: The existing graph engine in `services/bellud/internal/bellugraph` that stores entities and relations and provides `Path` and `Impact`.
- **Entity_ID**: The existing connection-scoped identity hash of an entity, computed from its kind and registered identity attributes.
- **Canonical_Key**: An entity attribute derived from a provider stable identifier (ARN, purl, CVE or GHSA identifier, image digest, or normalized git URL) and shared across connections.
- **Relation_Type**: A registered relation name in the Graph_Engine registry that has an impact direction.
- **Extracted_Relation**: A relation established by an exact match of Canonical_Key values or by a provider-reported fact.
- **Inferred_Relation**: A relation established by a heuristic.
- **Path_Confidence**: The confidence of a path, equal to the confidence of its weakest hop.
- **Connection**: One authorized link between a user and a source, such as one GitHub organization or one AWS account.
- **Collector**: A Bellud component that reads one Connection and emits entities and relations.
- **GitHub_Collector**: The Collector for GitHub repositories, workflows, alerts, and dependencies (packages).
- **AWS_Collector**: The Collector for an AWS account and its resources.
- **Batch**: The full snapshot of one Connection emitted by one Collector run.
- **Run_Status**: The recorded outcome of a Collector run, including counts, rate-limit waits, authorization errors, and denied scopes.
- **Global_Intel**: The Bellu Cyber server that publishes signed intel release bundles.
- **Latest_Pointer**: The `latest.json` file at a configured URL that names the current release bundle.
- **Release_Bundle**: A `.tar.zst` archive that contains `intel.jsonl`, `manifest.json`, and an ed25519 signature.
- **Pinned_Key**: The ed25519 public key compiled into or configured in Bellud for verifying Release_Bundle signatures.
- **Intel_Store**: The local Pebble store in Bellud that holds the imported intel corpus keyed by CVE identifier and purl.
- **Intel_Syncer**: The Bellud component that downloads, verifies, and imports Release_Bundles.
- **Correlator**: The Bellud component that matches Intel_Store records against package entities and materializes vulnerability entities.
- **Risk_Scorer**: The Bellud component that computes the risk score and severity of a finding.
- **Lens**: A definition-driven view of the graph that selects entities, relations, groups, and confidence for one purpose.
- **Lens_Engine**: The Bellud component that evaluates Lens definitions against the Graph_Engine.
- **Lens_Slice**: The Lens_Engine output format, made of nodes, edges, groups, and confidence tags, shared by the HTTP API and MCP.
- **Default_Lens**: The Lens used when a request names none; this is the `code-to-cloud` Lens.
- **Lens_Switcher**: The control in the page header of the app that selects the active Lens.
- **Security_Graph_View**: The SolidJS and Sigma 4 view in `packages/app/src/security-graph`.
- **MCP_Server**: The existing Bellud MCP server that exposes graph tools to agents.
- **Overlay_Event**: A short-lived event that names an entity, an action (focus node, walk path, or proposed change), and an explanation.
- **Overlay_Stream**: The ordered sequence of Overlay_Events delivered to the Security_Graph_View.
- **Follow_Mode**: The canvas state in which the camera follows Overlay_Events.
- **Graph_README**: The document at `docs/features/security-graph/README.md`.
- **Final_Checkpoint**: The set of commands run once at the end of implementation to verify the build, types, and lint state.
- **Pure_Logic**: Functions with no network, service, or cloud-credential dependency, such as identity hashing, version matching, scoring, lens projection, pointer parsing, and bundle verification.

## Requirements

### Requirement 1: Read-only pipeline

**User Story:** As a security engineer, I want one read-only pipeline from sources to lenses, so that I can trust that observing my environment changes nothing in it.

#### Acceptance Criteria

1. THE Bellud SHALL process data in the order connector, collector, Graph_Engine, Lens_Engine, then UI and MCP_Server.
2. THE Bellud SHALL perform only read operations against each connected source.
3. THE MCP_Server SHALL expose the new graph tools with the read-only hint set.
4. THE Bellud SHALL send no customer data to Global_Intel.
5. WHEN the Bellud serves a Lens_Slice, THE Bellud SHALL build the Lens_Slice from the Graph_Engine without modifying graph content.

### Requirement 2: Cross-source identity

**User Story:** As a security engineer, I want stable cross-source identity, so that the same asset seen by different sources joins into one picture.

#### Acceptance Criteria

1. THE Graph_Engine SHALL keep the connection-scoped Entity_ID for every existing entity kind.
2. WHEN a Collector emits an entity that has a provider stable identifier, THE Collector SHALL set a Canonical_Key attribute derived from an ARN, purl, CVE or GHSA identifier, image digest, or normalized git URL.
3. THE Graph_Engine SHALL register the entity kinds `package` and `vulnerability`.
4. THE Graph_Engine SHALL register the Relation_Types `affected_by`, `same_as`, and `likely_same_as`, each with a declared impact direction.
5. WHEN two entities from different Connections have equal Canonical_Key values, THE Correlator SHALL create an Extracted_Relation of type `same_as` between the entities.
6. WHEN two entities from different Connections have no equal Canonical_Key and match by a heuristic, THE Correlator SHALL create an Inferred_Relation of type `likely_same_as` between the entities.
7. THE Graph_Engine SHALL encode relation confidence in the Relation_Type, with no attribute on the relation and no change to the Graph_Engine storage model.
8. WHEN the Lens_Engine reports a path, THE Lens_Engine SHALL set the Path_Confidence to the confidence of the weakest hop of the path.

### Requirement 3: GitHub and AWS collection

**User Story:** As a security engineer, I want GitHub and AWS collected into the graph, so that I can follow risk from code to cloud.

#### Acceptance Criteria

1. WHEN a Collector run starts for an authorized GitHub Connection, THE GitHub_Collector SHALL emit entities for repositories, workflows, alerts, and dependencies as `package` entities.
2. WHEN a Collector run starts for an authorized AWS Connection, THE AWS_Collector SHALL emit entities for the account and its resources.
3. WHEN the AWS_Collector emits a resource that is reachable from the internet, THE AWS_Collector SHALL set an internet-exposed attribute on the resource entity.
4. WHEN a Collector run finishes, THE Graph_Engine SHALL replace the entities of that Connection with the Batch of that run.
5. WHEN a Connection is disconnected, THE Graph_Engine SHALL remove the entities of that Connection and keep the entities of every other Connection.
6. IF a source API returns a rate-limit response, THEN THE Collector SHALL wait until the reset time reported by the source and record the wait in the Run_Status.
7. IF a source rejects the Connection credentials, THEN THE Collector SHALL end the run and record an authorization error in the Run_Status.
8. IF a source returns an access-denied error for one scope, THEN THE Collector SHALL record the denied scope in the Run_Status and continue with the remaining scopes.

### Requirement 4: Verified intel sync

**User Story:** As a security engineer, I want verified threat intelligence downloaded from Bellu Cyber, so that correlation uses trusted data, including in air-gapped environments.

#### Acceptance Criteria

1. WHEN the Intel_Syncer runs, THE Intel_Syncer SHALL fetch the Latest_Pointer from the configured URL and download the Release_Bundle that the Latest_Pointer names.
2. WHEN the Intel_Syncer receives a Release_Bundle, THE Intel_Syncer SHALL verify the ed25519 signature against the Pinned_Key and verify the sha256 of each file against `manifest.json`.
3. WHEN verification succeeds, THE Intel_Syncer SHALL import `intel.jsonl` into the Intel_Store keyed by CVE identifier and purl.
4. THE Intel_Syncer SHALL run once every 24 hours.
5. WHERE a local Release_Bundle file path is provided, THE Intel_Syncer SHALL verify and import that file without network access.
6. IF the download fails, THEN THE Intel_Syncer SHALL keep the previous Intel_Store corpus and record the error.
7. IF signature or sha256 verification fails, THEN THE Intel_Syncer SHALL discard the Release_Bundle, keep the previous Intel_Store corpus, and record the error.
8. IF the Latest_Pointer is unreachable or cannot be parsed, THEN THE Intel_Syncer SHALL keep the previous Intel_Store corpus and record the error.
9. WHEN a client requests the intel status route, THE Bellud SHALL return the corpus version, record count, last synced time, and last error.

### Requirement 5: Match-then-materialize vulnerabilities

**User Story:** As a security engineer, I want vulnerabilities to appear in the graph only when they affect my packages, so that the graph stays small and relevant.

#### Acceptance Criteria

1. WHEN a `package` entity is added or changed, THE Correlator SHALL look up Intel_Store vulnerabilities by the purl name of the entity.
2. WHEN the purl name and version of a `package` entity match an affected package of a vulnerability, THE Correlator SHALL create a `vulnerability` entity and an `affected_by` relation from the package, with the version range semantics of the Bellu Cyber `SplitPurl` and `MatchPackage` functions.
3. WHEN the Correlator creates a `vulnerability` entity, THE Correlator SHALL set its CVSS, EPSS, and KEV attributes from the Intel_Store record.
4. WHEN a vulnerability record has no version ranges for the matching purl name, THE Correlator SHALL treat every version of the package as affected.
5. WHEN a version of a package lies outside every declared range, THE Correlator SHALL create no `vulnerability` entity for that match.
6. WHEN the Intel_Store corpus changes or a `package` entity is removed or changed, THE Correlator SHALL remove the `vulnerability` entities and `affected_by` relations that no longer match.
7. THE Correlator SHALL read Intel_Store records on demand and load no full corpus into the Graph_Engine.

### Requirement 6: Risk scoring

**User Story:** As a security engineer, I want a transparent risk score, so that I can rank findings and explain the ranking.

#### Acceptance Criteria

1. THE Risk_Scorer SHALL compute base as CVSS divided by 10 and multiplied by 100.
2. THE Risk_Scorer SHALL compute exploit as the larger of EPSS and 0.95 when KEV is set, or EPSS when KEV is not set.
3. THE Risk_Scorer SHALL compute exposure as 1.0 for a reachable asset and 0.4 for an asset that is not reachable.
4. THE Risk_Scorer SHALL compute aiBoost as 1 plus 0.25 multiplied by the AI criticality of the asset.
5. THE Risk_Scorer SHALL compute the score as base × (0.5 + 0.5 × exploit) × exposure × aiBoost, clamped to the range 0 to 100.
6. THE Risk_Scorer SHALL map a score of at least 90 to critical, at least 70 to high, at least 40 to medium, at least 10 to low, and any lower score to info.
7. WHERE KEV is set for a finding, THE Risk_Scorer SHALL raise a severity below high to high.
8. WHEN an input is outside its valid range, THE Risk_Scorer SHALL clamp the input to the range before computing the score.

### Requirement 7: Lens engine and MCP tools

**User Story:** As a security engineer, I want purpose-built lenses served by Bellud, so that the UI and AI see the same answers.

#### Acceptance Criteria

1. THE Lens_Engine SHALL provide the lenses `code-to-cloud`, `cloud`, `blast-radius`, `attack-path`, and `vulnerability-reachability`, each defined by a definition in Go in Bellud.
2. THE Lens_Engine SHALL return every Lens result as a Lens_Slice with nodes, edges, groups, and confidence tags.
3. WHEN the `blast-radius` Lens is requested for an entity, THE Lens_Engine SHALL build the Lens_Slice from the Graph_Engine `Impact` result.
4. WHEN the `attack-path` Lens is requested with a target high-value node, THE Lens_Engine SHALL build the Lens_Slice from the Graph_Engine `Path` results from each internet-exposed entity to the target.
5. WHEN a client requests the lens list, THE Bellud SHALL return the identifier, display name, and description of each Lens at a route under `/api/experimental/graph/`.
6. WHEN a client requests a Lens_Slice with a valid Lens identifier, THE Bellud SHALL return the slice of that Lens at a route under `/api/experimental/graph/`.
7. WHEN a client requests a Lens_Slice with no Lens identifier, THE Bellud SHALL return the Lens_Slice of the Default_Lens.
8. IF a client requests an unknown Lens identifier, THEN THE Bellud SHALL return a 404 response that names the unknown identifier.
9. WHEN a Lens excludes an entity, THE Lens_Engine SHALL exclude every relation attached to that entity from the Lens_Slice.
10. THE MCP_Server SHALL provide the tools `slice`, `attack_paths`, `blast_radius`, and `reachable_vulns`.
11. WHEN an MCP tool builds an answer, THE MCP_Server SHALL limit the answer to a bounded size and tag each edge and path with Extracted or Inferred confidence.

### Requirement 8: Lens switching on the canvas

**User Story:** As an app user, I want to switch lenses on a graph canvas, so that I can view the graph for one concern at a time.

#### Acceptance Criteria

1. WHEN the Security_Graph_View opens, THE Lens_Switcher SHALL display the Lenses returned by the Bellud in the page header.
2. WHEN the user selects a Lens, THE Security_Graph_View SHALL request the Lens_Slice of that Lens and render the response.
3. WHILE the `blast-radius` Lens is active, THE Security_Graph_View SHALL use a radial layout.
4. WHILE the `attack-path` Lens is active, THE Security_Graph_View SHALL use a left-to-right chain layout.
5. WHILE the `code-to-cloud` Lens is active, THE Security_Graph_View SHALL use the existing layout.
6. WHEN the user selects a vulnerability node, THE Security_Graph_View SHALL show its severity, KEV flag, and EPSS value in the node details.
7. WHILE no Connection exists, THE Security_Graph_View SHALL render the existing dummy graph as the empty state.
8. WHEN the user reopens the Security_Graph_View, THE Lens_Switcher SHALL select the Lens that the user selected last, or the Default_Lens when the stored identifier is not in the lens list.
9. IF a Lens_Slice request fails, THEN THE Security_Graph_View SHALL display an error message and keep the previously rendered graph.
10. THE Security_Graph_View SHALL color nodes and edges with theme tokens and SHALL define user-visible text as English i18n keys only.

### Requirement 9: Agent overlay

**User Story:** As an app user, I want to watch what an AI is doing on the graph, so that I can follow and review its work.

#### Acceptance Criteria

1. THE Bellud SHALL define an Overlay_Event format with an entity identifier, an action of focus node, walk path, or proposed change, and an explanation text.
2. THE Overlay_Stream SHALL deliver Overlay_Events to the Security_Graph_View in order.
3. WHILE Follow_Mode is on, WHEN an Overlay_Event arrives, THE Security_Graph_View SHALL zoom to the entity of the event, highlight the entity, and show a tooltip card with the explanation.
4. WHEN the user pans the canvas manually, THE Security_Graph_View SHALL turn Follow_Mode off.
5. WHEN an Overlay_Event names an entity identifier that is absent from the rendered Lens_Slice, THE Security_Graph_View SHALL skip the event and continue with the next event.
6. THE first release SHALL produce the Overlay_Stream from a scripted replay.
7. THE Bellud SHALL discard each Overlay_Event after delivery and SHALL store no Overlay_Event as a graph fact.

### Requirement 10: Feature documentation

**User Story:** As a developer, I want feature documentation, so that I can operate and extend the Unified Security Graph.

#### Acceptance Criteria

1. THE Graph_README SHALL exist at `docs/features/security-graph/README.md`.
2. THE Graph_README SHALL describe the architecture, the naming contract, the lens catalog, and the intel flow.
3. THE Graph_README SHALL define the Latest_Pointer fields, state that the Latest_Pointer is a mutable object, state the cache lifetime that Bellud applies, and describe the Bellud behavior for each failure case in Requirement 4.
4. THE Graph_README SHALL describe how to add a new Collector.
5. THE Graph_README SHALL credit Graphify (Apache-2.0, Python) as the source of the ideas of extracted versus inferred edges, weakest-hop confidence, and bounded subgraph answers, and SHALL state that no Graphify code is copied.
6. THE Graph_README SHALL state that the protocol, client, and route table are regenerated with `bun run generate` from `packages/client` after the experimental routes change.

### Requirement 11: Offline tests and final checks

**User Story:** As a maintainer, I want fast offline tests of the core logic and a clean final check, so that regressions are caught without live services.

#### Acceptance Criteria

1. THE test suite SHALL include automated tests for Entity_ID and Canonical_Key derivation, purl version matching, the risk score and buckets, Lens_Slice output, Latest_Pointer parsing, and Release_Bundle verification.
2. THE test suite SHALL run the Pure_Logic tests without network access, running services, or cloud credentials.
3. WHEN the Pure_Logic tests run, THE test suite SHALL leave every running service untouched.
4. WHEN the Final_Checkpoint runs, THE Final_Checkpoint SHALL execute `go build` and `go vet` for Bellud, `bun typecheck`, the app build, and `bun run check`, and report success only when every command exits with status 0.
5. WHEN the Final_Checkpoint completes, THE Final_Checkpoint SHALL leave every running service with the same process start time that the service had before the Final_Checkpoint began.
