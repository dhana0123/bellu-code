# Requirements Document

## Introduction

`bellud` embeds a graph engine under `services/bellud/internal/bellugraph`. That engine is currently a vendored, renamed copy of an upstream project, kept in sync by a rename tool and shipped with attribution files. This feature replaces it with an original, clean-room Go implementation, the Bellu Graph Engine. The new engine keeps today's features: an append-only event log, bi-temporal timestamps, identity and canonicalization, search and traversal, MCP tools, embedded persistence and observability. It also adds richer tools, MCP resources and prompts, verbosity tiers, short local IDs, endpoint resolution, snapshots, subscriptions, token roles, a GraphQL API and a debug page.

The engine is written from behavior, not from upstream source. The allowed inputs are:

- the Facade package and its tests;
- the Facade's callers (`internal/graph`, `internal/api/graph`, `internal/collectors`, `internal/mcptoken`, `internal/agentcfg`, `internal/server`, `internal/contract`, `cmd/bellud`);
- the spec `go-server-bellu-graph` (`requirements.md`, `design.md`);
- this document;
- general knowledge of event sourcing, Pebble, MCP, GraphQL and OTLP.

After the swap, the vendored tree, sync tooling and attribution files are removed, and the repository contains no Upstream_Name.

Existing graph data may be dropped. Collectors rebuild it.

### Out of scope

The following are explicitly excluded: multi-tenancy, TLS (on any listener, including OTLP), Docker and release images, a producer SDK, a conformance kit for third-party engines, and federation between graph instances.

## Glossary

- **Engine**: The Bellu Graph Engine, the Go packages under `internal/bellugraph/internal/bge/*` that implement the Facade.
- **Facade**: The Go package `internal/bellugraph/facade`, with its exported `Engine`, `Ingest`, `Query`, `Config`, `Batch` and error types. Its import path does not change and its exported API only grows.
- **Vendored_Tree**: Everything under `internal/bellugraph` except `facade/` and `internal/bge/`, plus the sync tooling and attribution files listed in Requirement 23.
- **Upstream_Name**: The name of the project the previous engine was derived from, matched case-insensitively. The documents refer to it only by this term or as "the previous engine".
- **Event**: One immutable record in the Event_Log.
- **Change_Event**: An Event that changes the Projection: entity created, updated or removed, relation added or removed, or annotation changed.
- **Event_Log**: The append-only, ordered sequence of Events held in the Store.
- **Log_Sequence**: The 64-bit position of an Event in the Event_Log.
- **Store**: The embedded Pebble database (already in `go.mod`) that holds the Event_Log, its indexes and Snapshots.
- **Projection**: The in-memory graph state derived by folding Events in log order.
- **Snapshot**: A persisted copy of the Projection as of a Log_Sequence, with the maximum Valid_Time of the Events folded into it.
- **Retention_Horizon**: The earliest instant for which As_Of_Queries are exact after retention has trimmed the Event_Log.
- **Valid_Time**: `observed_at`, when the observation was true in the world. Supplied by the collector.
- **Recorded_Time**: `recorded_at`, when the Engine appended the Event. Assigned by the Engine.
- **As_Of_Query**: A read that returns state folded from Events whose Valid_Time is at or before a given instant.
- **Entity_ID**: `<kind>:<32 lowercase hex>`, the first 128 bits of SHA-256 over the Canonical_Encoding of the kind and the registered identity attributes. Exposed as `identity_fingerprint`.
- **Local_ID**: A short, human-friendly entity alias of the form `@` followed by 6 characters, minted by the Engine and re-minted after 15 minutes without a lookup.
- **Entity_Ref**: Any accepted way to name an entity: an Entity_ID, a live Local_ID, or an entity URI.
- **Canonical_Encoding**: The Engine's deterministic byte encoding of a value: keys sorted bytewise, each value type-tagged and length-prefixed.
- **Collector_Scope**: The set of entities and relations a collector has asserted. A Batch is a full observation of its scope.
- **Batch**: `facade.Batch` (`internal/graph/batch`), one collector run's observations.
- **Endpoint**: An entity of kind `endpoint` that names a network address, port and protocol.
- **Endpoint_Resolution**: The read-time join from an Endpoint to the live `listening_port` entities that serve it, and to their owning processes.
- **Impact_Direction**: The direction in which failure propagates along a relation type: `forward` (from → to) or `reverse` (to → from).
- **Verbosity**: The response detail tier of an MCP tool: `brief`, `normal` or `full`.
- **Subscriber**: A consumer of Change_Events pushed after commit.
- **Role**: The rights of a graph token: `read`, `ingest` or `write`. `write` includes `read` and `ingest`.
- **MCP_Handler**: The HTTP handler returned by `Engine.MCPHandler()`, serving MCP over Streamable HTTP.
- **GraphQL_Handler**: The handler served at `/api/experimental/graph/graphql`.
- **SSE_Handler**: The handler served at `/api/experimental/graph/subscribe`.
- **Debug_UI**: The HTML page served at `/api/experimental/graph/debug`.
- **OTLP_Receiver**: The listener started when `BELLU_GRAPH_OTLP_LISTEN` is set.
- **Metrics_Registry**: The Engine's Prometheus-format metric set, with every name prefixed `bellu_graph_`.
- **Leftover_Check**: A case-insensitive recursive search for the Upstream_Name over the repository paths and contents. It excludes `.git`, `node_modules`, built `dist` directories, and the unrelated Finnish i18n words in `fi.ts`.

## Requirements

### Requirement 1: Clean-room provenance

**User Story:** As a maintainer, I want the Engine to be our own original code, so that no third-party attribution or license obligation applies.

#### Acceptance Criteria

1. THE Engine SHALL be implemented only from the allowed inputs listed in the Introduction.
2. THE Engine source SHALL contain no file copied, translated or ported from the Vendored_Tree.
3. THE Engine source SHALL carry no upstream copyright header, modification marker or attribution comment.
4. THE Engine SHALL use only the Go standard library and modules already present in `go.mod`, plus any new module recorded in the design with its license.

### Requirement 2: Facade compatibility

**User Story:** As a developer of collectors, the Graph API, the MCP endpoint and agentcfg, I want the Facade to stay stable, so that none of those callers change.

#### Acceptance Criteria

1. THE Facade SHALL keep the import path `github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade`.
2. THE Facade SHALL keep every exported identifier it has today with an unchanged signature, including `Open`, `LoadConfig`, `Hash`, `Kinds`, `IdentityAttributes`, `MCPTools`, `TokenIdentity`, `StateOf`, the `Page`, `Entity`, `Edge`, `Change` and `Diff` types, and the error values `ErrUnavailable`, `ErrNotFound`, `ErrValidation`, `ErrLocked`, `ErrCorrupt` and `ErrInsecurePermissions`.
3. WHERE a new feature needs Facade surface, THE Facade SHALL add it as new identifiers, new struct fields or optional interfaces discovered at run time, and SHALL keep the `Engine`, `Ingest` and `Query` interface method sets unchanged.
4. WHEN the swap is complete, THE existing tests of `internal/bellugraph/facade`, `internal/graph`, `internal/api/graph`, `internal/server`, `internal/collectors`, `internal/mcptoken`, `internal/agentcfg` and `internal/contract` SHALL pass without modification, with two exceptions: removal of references to the Vendored_Tree, and the expected values in `TestIdentityHashGolden`, which SHALL be replaced with vectors computed from the Engine's Canonical_Encoding.
5. THE Facade SHALL import no package outside `internal/bellugraph/internal/bge/*`, the standard library and `go.mod` modules, except `internal/graph/batch`.

### Requirement 3: Append-only event log with atomic batches

**User Story:** As a collector author, I want each batch appended all-or-nothing to a durable log, so that the graph never shows half a run.

#### Acceptance Criteria

1. THE Engine SHALL assign each appended Event a Log_Sequence one greater than the previous Event and a ULID event ID.
2. THE Engine SHALL keep every appended Event unmodified until retention deletes it (Requirement 13).
3. WHEN `Apply` receives a valid Batch, THE Engine SHALL write all resulting Events and index entries in one atomic Store write that is synced to disk before `Apply` returns.
4. IF `Apply` returns an error, THEN THE Engine SHALL leave the Event_Log and the Projection unchanged.
5. IF a Batch has an empty collector, an unknown entity kind, a missing or empty identity attribute, a duplicate entity, a relation without a type, or a relation carrying attributes, THEN THE Engine SHALL reject the whole Batch with an error wrapping `ErrValidation` and append nothing.
6. IF a relation endpoint names an entity that is neither in the Batch nor live in the Projection, or names an entity the same Batch retires, THEN THE Engine SHALL reject the Batch with an error wrapping `ErrValidation`.
7. THE Engine SHALL apply a Batch to the Projection only after the Store write succeeds.
8. WHEN two `Apply` calls run concurrently, THE Engine SHALL serialize them so that each plans against the Projection left by the previous one.
9. WHEN the Engine reopens a Store, THE Engine SHALL rebuild a Projection equal to the one it held before close.
10. WHEN `Apply` receives a Batch that changes neither the Projection nor any Collector_Scope, THE Engine SHALL append no Event and still return a Receipt with a fresh ULID.

### Requirement 4: Bi-temporal timestamps and as-of queries

**User Story:** As an analyst, I want to ask what was true at a past instant and when we learned it, so that I can investigate incidents accurately.

#### Acceptance Criteria

1. THE Engine SHALL store the Batch's `ObservedAt` as Valid_Time exactly as supplied, or the current UTC time when it is zero.
2. THE Engine SHALL stamp Recorded_Time with the current UTC time at append, and SHALL ignore any caller-supplied Recorded_Time.
3. THE Engine SHALL keep Recorded_Time non-decreasing along the Event_Log.
4. WHEN `Query.Entity` is called with an `at` instant, THE Engine SHALL return the state produced by folding, in log order, all Events with Valid_Time at or before `at`.
5. WHEN `Query.Diff` is called with `from` and `to`, THE Engine SHALL compute added, changed and removed entities by comparing the as-of states at both instants, so that an entity created and deleted between them appears in none of those three lists.
6. IF a time range has `To` before `From`, or a diff has `to` before `from`, THEN THE Engine SHALL return an error wrapping `ErrValidation`.
7. THE Engine SHALL report in `Entity` and `Change` the Valid_Time and Recorded_Time of the latest Event folded into the reported state.

### Requirement 5: Entities, relations, identity, scopes and annotations

**User Story:** As a collector author, I want stable, deterministic entity identity, so that repeated observations update the same entity.

#### Acceptance Criteria

1. THE Engine SHALL register identity attributes per entity kind for the 15 kinds the Facade registers today (`host`, `process`, `listening_port`, `container`, `image`, `network`, `volume`, `repository`, `dependency`, `workflow`, `secret_ref`, `iac_resource`, `k8s_object`, `secret_finding`, `collector_status`) and for the kind `endpoint` with identity attributes `protocol`, `address` and `port`.
2. WHEN `Hash` is called with a kind and attributes, THE Engine SHALL return an Entity_ID computed over the kind and the Canonical_Encoding of the registered identity attributes only.
3. THE Engine SHALL produce the same Entity_ID for the same kind and identity attributes regardless of map iteration order, process, operating system and CPU architecture.
4. WHEN two entities of the same kind differ in any registered identity attribute, THE Engine SHALL assign them different Entity_IDs.
5. WHEN an entity differs only in descriptive attributes, THE Engine SHALL keep its Entity_ID.
6. IF `Hash` is called with an unknown kind or a missing or empty identity attribute, THEN THE Engine SHALL return an error wrapping `ErrValidation` that names the kind or the attribute.
7. THE Engine SHALL classify each entity observation as created, attribute-updated, state-changed or unchanged by comparing the observation with the Projection, and SHALL append a Change_Event for the first three only.
8. THE Engine SHALL identify a relation by the triple of type, from Entity_ID and to Entity_ID.
9. THE Engine SHALL record, per Collector_Scope, which entities and relations each collector currently asserts.
10. WHEN a Batch omits an entity or relation that the Batch's Collector_Scope asserted before, THE Engine SHALL remove that assertion, and SHALL append a removal Change_Event only when no other Collector_Scope still asserts the entity or relation.
11. WHEN a removed entity is observed again, THE Engine SHALL revive the entity under the same Entity_ID and record a created change.
12. THE Engine SHALL accept descriptive attribute values of string, boolean, integer, finite float and list-of-string type, and SHALL reject other types with an error wrapping `ErrValidation`.
13. THE Engine SHALL store annotations as operator-owned key-value pairs per Entity_ID that Batches cannot overwrite or remove, and SHALL include them in entity reads.

### Requirement 6: Search and traversal queries

**User Story:** As a Graph API client, I want to find entities and walk relations with stable pagination, so that I can explore the graph.

#### Acceptance Criteria

1. WHEN `Find` is called, THE Engine SHALL return the live entities matching the optional kind and every given attribute (logical AND over identity and descriptive attributes), ordered by Entity_ID.
2. THE Engine SHALL paginate `Find`, `Neighbors`, `History` and `Changes` with an opaque cursor, a default page size of 100 and a maximum of 1000.
3. IF a page size is negative or above 1000, or a cursor is malformed, THEN THE Engine SHALL return an error wrapping `ErrValidation`.
4. WHEN `Neighbors` is called with depth 1 to 10 and direction `out`, `in` or `both`, THE Engine SHALL return each reachable relation once, at its fewest hops, ordered by hops, relation type, from and to.
5. IF `Neighbors`, `Entity` or `History` names an unknown entity, THEN THE Engine SHALL return an error wrapping `ErrNotFound`.
6. WHEN `History` is called, THE Engine SHALL return the entity's own Change_Events and the Change_Events of relations touching the entity within the time range, oldest first.
7. WHEN `Changes` is called, THE Engine SHALL return Change_Events within the time range filtered by kind, subject and entity, ordered by Valid_Time and then Log_Sequence.
8. THE Engine SHALL report in `Find`, `Neighbors`, `History` and `Changes` a Total equal to the size of the full matching set.

### Requirement 7: MCP tools

**User Story:** As an agent user, I want the 12 MCP tools to behave as the security skill describes, so that agents can query the graph.

#### Acceptance Criteria

1. THE MCP_Handler SHALL serve MCP over Streamable HTTP with exactly the tools in `facade.MCPTools`: `describe_schema`, `describe_type`, `find_entities`, `get_entity`, `annotate_entity`, `get_neighbors`, `find_path`, `impact_of`, `entity_history`, `recent_changes`, `graph_diff` and `telemetry_keys`.
2. WHEN `tools/list` is called, THE MCP_Handler SHALL return each tool with a description and a JSON input schema.
3. WHEN `find_entities`, `get_entity`, `get_neighbors` or `entity_history` is called, THE MCP_Handler SHALL return the same entities, relations or changes as the corresponding `Query` method.
4. WHERE the Facade verifies tokens, THE MCP_Handler SHALL compare the bearer token in constant time and respond `401` with a `WWW-Authenticate` header on mismatch.
5. WHEN `annotate_entity` is called, THE MCP_Handler SHALL write an audit record (time, token identity, action, Entity_ID) to `audit.jsonl` in the data directory with mode 0600 and sync the record before applying the annotation.
6. IF the audit write fails, THEN THE MCP_Handler SHALL return an error result and apply no annotation.
7. IF a POST body exceeds 4 MiB, THEN THE MCP_Handler SHALL respond `413`.
8. WHILE the Engine state is not `ready`, THE MCP_Handler SHALL respond `503` with code `graph_unavailable`.
9. WHEN `telemetry_keys` is called, THE MCP_Handler SHALL return the identity attribute names and values that locate the entity's metrics and logs, and SHALL omit attribute values whose names mark them as secret.
10. THE MCP_Handler SHALL report a server title and instructions that name the Bellu Graph Engine.

### Requirement 8: Richer tool behavior

**User Story:** As an agent, I want tools that summarize, detect churn and explain negative results, so that I can answer questions in few calls.

#### Acceptance Criteria

1. WHEN `recent_changes` is called, THE MCP_Handler SHALL return change items newest first until the serialized items reach the response byte budget (default 16 KiB, maximum 256 KiB), and SHALL set `truncated` and a cursor when items remain.
2. WHEN `recent_changes` is called, THE MCP_Handler SHALL return a digest over the full matching set with counts by change kind, subject and entity kind, and the 10 entities with the most changes.
3. WHEN `graph_diff` is called with a window, THE Engine SHALL report as flapping every entity with two or more Change_Events in the window whose state at the window end equals its state at the window start, with its change count.
4. WHEN `find_path` finds a path, THE Engine SHALL return a shortest path by hop count between the two entities.
5. IF `find_path` finds no path, THEN THE Engine SHALL return `connected: false`, state whether the search exhausted the connected component or stopped at the depth bound, and list the neighbor entities and the non-secret attribute key-value pairs both ends share.
6. WHEN `impact_of` is called, THE Engine SHALL return the entities reachable from the given entity within the depth bound by following each relation type in the type's declared Impact_Direction, with the hop count and relation path of each entity.
7. THE Engine SHALL declare an Impact_Direction for each known relation type, SHALL apply `reverse` to undeclared types, and SHALL report each type's Impact_Direction in `describe_schema`.

### Requirement 9: MCP resources and prompts

**User Story:** As an agent user, I want the schema and entities as pinnable resources and ready-made prompts, so that I can start investigations quickly.

#### Acceptance Criteria

1. THE MCP_Handler SHALL serve a resource `bellugraph://schema` with the live schema: kinds, identity attributes, relation types with Impact_Direction, and live counts.
2. THE MCP_Handler SHALL serve a resource template `bellugraph://{kind}/{hex}` that returns the entity view: the entity, the entity's annotations, the entity's 1-hop relations and the entity's 10 most recent changes.
3. IF a resource URI names an unknown or removed entity, THEN THE MCP_Handler SHALL return a resource-not-found error.
4. THE MCP_Handler SHALL serve the prompts `investigate_incident`, `blast_radius` and `explain_entity`, each with declared arguments.
5. WHEN a prompt is requested, THE MCP_Handler SHALL return messages that name the tools to call and embed the referenced entity view as a resource, and that contain no secret attribute values.

### Requirement 10: Response verbosity tiers

**User Story:** As an agent, I want to choose how much detail a tool returns, so that I stay within my context budget.

#### Acceptance Criteria

1. THE MCP_Handler SHALL accept an optional `verbosity` argument of `brief`, `normal` or `full` on every read tool, defaulting to `normal`.
2. WHEN `verbosity` is `brief`, THE MCP_Handler SHALL return for each entity only the Local_ID, the Entity_ID, the kind and the label.
3. WHEN `verbosity` is `normal`, THE MCP_Handler SHALL also return attributes and annotations, with at most 32 attributes and each value cut to 256 bytes, marking cut values.
4. WHEN `verbosity` is `full`, THE MCP_Handler SHALL return all attributes uncut, both timestamps and the entity URI.
5. IF `verbosity` has another value, THEN THE MCP_Handler SHALL return an invalid-arguments error.

### Requirement 11: Stable and local identifiers

**User Story:** As an agent, I want short IDs to type and stable IDs to keep, so that conversations are compact and references stay valid.

#### Acceptance Criteria

1. THE Engine SHALL expose each entity's Entity_ID as `identity_fingerprint` in MCP and GraphQL responses.
2. WHEN the Engine returns an entity in an MCP, GraphQL or Debug_UI response, THE Engine SHALL include the entity's Local_ID, minting one when the entity has none.
3. WHEN a Local_ID has not been looked up or returned for 15 minutes, THE Engine SHALL retire the Local_ID, and the next response SHALL carry a newly minted Local_ID.
4. THE Engine SHALL never map a retired Local_ID to a different entity within 24 hours of retirement.
5. THE Engine SHALL accept an Entity_ID, a live Local_ID or an entity URI wherever a query, tool, resource, GraphQL argument, HTTP path or annotation takes an entity identifier.
6. IF a retired or unknown Local_ID is supplied, THEN THE Engine SHALL return an error wrapping `ErrNotFound` that tells the caller to use the `identity_fingerprint`.
7. THE Engine SHALL accept only Entity_IDs as relation endpoints in Batches.

### Requirement 12: Endpoint resolution for `depends_on`

**User Story:** As an analyst, I want service dependencies on network endpoints joined to the live listeners, so that I can answer both "what does this depend on" and "who connects to this".

#### Acceptance Criteria

1. THE Engine SHALL accept durable `depends_on` relations from any entity to an Endpoint.
2. WHEN a read resolves endpoints, THE Engine SHALL resolve each Endpoint to every live `listening_port` with the same protocol and port whose address equals the Endpoint address, or whose address is a wildcard and whose host matches the Endpoint address, and to the processes those ports are `owned_by`.
3. THE Engine SHALL compute Endpoint_Resolution at read time and SHALL append no Event for the join.
4. WHEN `get_neighbors`, `impact_of` or the GraphQL `neighbors` and `impact` fields traverse an Endpoint, THE Engine SHALL include the resolved listeners as derived relations of type `resolves_to`, marked as derived.
5. WHEN neighbors of a `listening_port` or process are requested with endpoint resolution, THE Engine SHALL include the entities whose `depends_on` Endpoints resolve to that port or process.
6. WHEN the Facade `Neighbors` method is called without the resolution option, THE Engine SHALL return stored relations only.

### Requirement 13: Snapshots and retention

**User Story:** As an operator, I want fast startup and bounded storage, so that the graph stays responsive as history grows.

#### Acceptance Criteria

1. THE Engine SHALL write a Snapshot every 5 minutes when Events were appended since the last Snapshot, after every 10,000 Events, and on `Close`.
2. WHEN the Engine opens a Store, THE Engine SHALL load the newest valid Snapshot and fold only the Events after the Snapshot's Log_Sequence.
3. IF a Snapshot fails validation, THEN THE Engine SHALL ignore that Snapshot and use the next older one or the full Event_Log.
4. WHERE `BELLU_GRAPH_RETENTION` is greater than zero, THE Engine SHALL delete Events whose Recorded_Time is older than the retention window, only after writing a Snapshot at the deletion boundary.
5. WHEN retention has deleted Events, THE Engine SHALL answer every As_Of_Query at or after the Retention_Horizon with the same result as before the deletion.
6. IF an As_Of_Query or diff bound is before the Retention_Horizon, THEN THE Engine SHALL return an error wrapping `ErrValidation` that states the horizon.

### Requirement 14: Real-time subscriptions

**User Story:** As a client developer, I want change events pushed as they commit, so that views update without polling.

#### Acceptance Criteria

1. THE Engine SHALL offer a subscriber API that delivers Change_Events on a Go channel, filtered by change kind, subject, entity kind and entity.
2. THE Engine SHALL publish each Change_Event to Subscribers only after the Store write and the Projection update succeed, in Log_Sequence order.
3. WHEN a subscription starts from a Log_Sequence, THE Engine SHALL first replay the stored Change_Events after that Log_Sequence and then deliver live Change_Events without gap or duplicate.
4. IF a Subscriber's buffer is full, THEN THE Engine SHALL close that subscription with an overflow error and continue serving other Subscribers and `Apply` without blocking.
5. THE SSE_Handler SHALL stream Change_Events as server-sent events whose IDs are Log_Sequences, honor `Last-Event-ID` for resume, and send a keep-alive comment every 15 seconds.
6. IF a resume Log_Sequence is older than the retained Event_Log, THEN THE SSE_Handler SHALL send an error event naming the oldest retained Log_Sequence and close the stream.
7. THE GraphQL_Handler SHALL offer a `changes` subscription backed by the same subscriber API.

### Requirement 15: Token roles

**User Story:** As an operator, I want read-only and ingest-only graph tokens, so that clients get only the rights they need.

#### Acceptance Criteria

1. WHEN `bellud` starts, THE bellud process SHALL mint one per-start token for each Role, keeping the existing MCP token as the `write` token.
2. WHEN `bellud` starts with the graph enabled, THE bellud process SHALL write the `read` and `ingest` tokens to `graph-tokens.json` with mode 0600 in the bellucode data directory, replacing earlier contents.
3. THE bellud front door SHALL accept a graph token only on `/api/experimental/graph/*` routes other than the Debug_UI and metrics routes, and SHALL treat requests authenticated by bellud credentials as `write`.
4. WHEN a request carries a `read` token, THE bellud process SHALL allow MCP read tools, GraphQL queries and subscriptions, the SSE_Handler and the HTTP graph read routes.
5. WHEN a request carries an `ingest` token, THE bellud process SHALL allow only `POST /api/experimental/graph/batches` and the OTLP_Receiver.
6. THE bellud process SHALL require the `write` Role for `annotate_entity` and the GraphQL `annotateEntity` mutation.
7. IF a valid token lacks the Role a request needs, THEN THE bellud process SHALL respond `403` with code `graph_forbidden`, or return an error tool result naming the needed Role for an MCP tool call.
8. WHEN `POST /api/experimental/graph/batches` receives a JSON Batch of at most 4 MiB, THE Graph API SHALL apply the Batch and return the Receipt.
9. THE token Roles SHALL reuse the `internal/mcptoken` patterns: 32 random bytes, in-memory only apart from Requirement 15.2, constant-time comparison and a non-reversible audit identity.

### Requirement 16: GraphQL API

**User Story:** As a client developer, I want a typed query API, so that I can fetch exactly the graph data I need in one request.

#### Acceptance Criteria

1. THE GraphQL_Handler SHALL serve a GraphQL schema at `/api/experimental/graph/graphql` over HTTP POST.
2. THE GraphQL schema SHALL offer the queries `entity`, `find`, `neighbors`, `history`, `recentChanges`, `diff`, `path` and `impact`.
3. WHERE a query takes an `asOf` argument, THE GraphQL_Handler SHALL answer from the as-of state at that instant.
4. THE GraphQL schema SHALL offer exactly one mutation, `annotateEntity`, audited as in Requirement 7.5 and 7.6.
5. THE GraphQL schema SHALL offer exactly one subscription, `changes`.
6. WHEN a GraphQL query resolves, THE GraphQL_Handler SHALL return the same entities, relations and changes as the corresponding `Query` method.
7. IF a query exceeds a depth of 12 or a complexity of 5,000, THEN THE GraphQL_Handler SHALL reject the query with an error before execution.
8. WHEN a GraphQL resolver fails, THE GraphQL_Handler SHALL return an error with an `extensions.code` of `VALIDATION`, `NOT_FOUND`, `FORBIDDEN` or `UNAVAILABLE`.

### Requirement 17: Debug UI

**User Story:** As a developer, I want a built-in page to inspect the graph, so that I can debug collectors without extra tools.

#### Acceptance Criteria

1. THE Debug_UI SHALL serve server-rendered HTML at `/api/experimental/graph/debug` that uses no JavaScript and no external resources.
2. THE Debug_UI SHALL show, for an entered Entity_Ref and optional as-of instant, the entity's attributes, annotations, neighbors to a chosen depth of 1 to 3, and history.
3. THE Debug_UI SHALL offer only read operations, served through GET requests.
4. THE Debug_UI SHALL require bellud credentials and SHALL reject graph tokens.
5. THE Debug_UI SHALL escape every rendered value and send `Content-Security-Policy: default-src 'none'; style-src 'self'` and `X-Content-Type-Options: nosniff`.

### Requirement 18: Persistence

**User Story:** As an operator, I want the log stored in an embedded database with safe file handling, so that the graph survives restarts and corruption is detected.

#### Acceptance Criteria

1. THE Engine SHALL persist the Event_Log, indexes and Snapshots in a Pebble database at `Config.Dir/default`.
2. THE Store SHALL index Events by Log_Sequence, by entity, by relation endpoint and by Valid_Time, written in the same atomic write as the Event.
3. THE Engine SHALL create `Config.Dir` with mode 0700 and SHALL leave every file below it with mode 0600 and every directory with mode 0700.
4. IF `Config.Dir` exists with group or world permission bits, THEN `Open` SHALL fail with an error wrapping `ErrInsecurePermissions` and leave the directory unchanged.
5. IF another process holds the Store, THEN `Open` SHALL fail with an error wrapping `ErrLocked` and log one error entry naming the lock file.
6. IF the Store cannot be opened or fails validation, THEN `Open` SHALL return an error wrapping `ErrCorrupt` and leave every file byte- and mode-identical.
7. WHEN `Open` fails, THE Facade SHALL return an engine in state `failed` whose Ingest, Query and handlers respond with `ErrUnavailable`.
8. WHEN `Close` is called, THE Engine SHALL refuse new `Apply` calls, wait for in-flight `Apply` calls or the context deadline, stop background work, write a final Snapshot, and close the Store.
9. THE Engine SHALL store a format version in the Store, and IF the Engine finds a missing or unknown version in an existing Store, THEN `Open` SHALL fail with an error wrapping `ErrCorrupt` that states the version found.
10. WHEN a process dies during `Apply`, THE Engine SHALL on reopen contain either all or none of that Batch's Events.

### Requirement 19: OTLP ingest

**User Story:** As a producer outside bellud, I want to send entity events over OTLP, so that I can feed the graph with standard tooling.

#### Acceptance Criteria

1. WHERE `BELLU_GRAPH_OTLP_LISTEN` is set, THE Engine SHALL start an OTLP/HTTP receiver on that address accepting the logs signal at `/v1/logs` in protobuf and JSON encodings; otherwise THE Engine SHALL start no listener.
2. WHEN the OTLP_Receiver receives a resource's log records, THE Engine SHALL convert the records to one Batch whose collector is the resource attribute `bellugraph.collector` and apply the Batch atomically.
3. THE OTLP_Receiver SHALL treat a converted Batch as a partial observation that adds and updates only, unless the resource attribute `bellugraph.full_observation` is `true`.
4. IF a record lacks a required attribute or fails validation, THEN THE OTLP_Receiver SHALL reject that resource's Batch and report the rejected record count and the reason in a partial-success response.
5. WHERE the Facade verifies tokens, THE OTLP_Receiver SHALL require a bearer token with the `ingest` or `write` Role.

### Requirement 20: Metrics and observability

**User Story:** As an operator, I want Engine metrics and logs under one prefix, so that I can monitor the graph.

#### Acceptance Criteria

1. THE Metrics_Registry SHALL name every metric with the prefix `bellu_graph_`.
2. THE Engine SHALL expose counters for batches applied, batches rejected, events appended and queries served; gauges for entities, relations, the last Log_Sequence and Subscribers; and histograms for `Apply` and query latency.
3. THE Engine SHALL expose the Metrics_Registry in Prometheus text format through a handler that bellud serves at `/api/experimental/graph/metrics` behind bellud credentials.
4. THE Engine SHALL log through `Config.Logger` (or `slog.Default()` when nil) at the level set by `BELLU_GRAPH_LOG_LEVEL`.
5. THE Engine SHALL write no attribute or annotation value to logs or metric labels.
6. WHEN the Engine state changes, THE Engine SHALL log the transition with its reason.

### Requirement 21: Configuration, URIs and naming

**User Story:** As an operator, I want one consistent naming scheme, so that configuration and identifiers are predictable.

#### Acceptance Criteria

1. THE Engine SHALL read configuration only from `BELLU_GRAPH_ENABLED`, `BELLU_GRAPH_DIR`, `BELLU_GRAPH_OTLP_LISTEN`, `BELLU_GRAPH_RETENTION` and `BELLU_GRAPH_LOG_LEVEL`, through `facade.LoadConfig`.
2. IF a `BELLU_GRAPH_*` value is unparsable, THEN `LoadConfig` SHALL return an error naming each offending variable.
3. THE Engine SHALL name entities, relations and events with URIs of the form `bellugraph://<kind>/<hex>`, `bellugraph://relation/<type>/<from-kind>/<from-hex>/<to-kind>/<to-hex>` and `bellugraph://event/<ulid>`.
4. FOR ALL references the Engine formats as `bellugraph://` URIs, parsing the URI SHALL return the original reference (round-trip property).
5. IF a URI has another scheme or is malformed, THEN the URI parser SHALL return an error wrapping `ErrValidation`.
6. THE Engine SHALL name Go packages, identifiers, user-visible strings, MCP and GraphQL server metadata and documentation with `bellugraph`, `bge` or `Bellu Graph Engine`.

### Requirement 22: Verification of the new Engine

**User Story:** As a maintainer, I want automated tests to establish behavior, so that the swap is safe.

#### Acceptance Criteria

1. THE Engine SHALL have property-based tests, each running at least 100 iterations, for the properties in the design document.
2. THE Engine SHALL have crash-recovery tests that kill a writer process during `Apply` and verify that reopening yields all or none of the Batch.
3. THE Engine SHALL pass the existing Facade tests, run unchanged apart from Requirement 2.4, as its conformance suite.
4. WHEN `go build ./...`, `go vet ./...` and `go test ./...` run in `services/bellud`, THE Engine SHALL pass all three.

### Requirement 23: Removal of the vendored engine and sync tooling

**User Story:** As a maintainer, I want all vendored code and sync machinery gone, so that nothing derived from upstream remains.

#### Acceptance Criteria

1. WHEN the Engine passes the conformance suite, THE repository SHALL delete the Vendored_Tree: every path under `services/bellud/internal/bellugraph` except `facade/` and `internal/bge/`.
2. THE repository SHALL delete `services/bellud/internal/syncgraph`, `services/bellud/internal/rename`, `services/bellud/cmd/sync-bellu-graph`, `services/bellud/script/rename.map.yaml`, `services/bellud/script/bellu-graph.sum` and `script/sync-bellu-graph`.
3. THE repository SHALL delete `NOTICE`, `UPSTREAM.md` and the copied upstream `LICENSE` inside `internal/bellugraph`.
4. THE repository SHALL remove the `sync-graph` target and the `TestFixtureV1` invocation from the root `Makefile`.
5. THE CI workflow `.github/workflows/bellud.yml` SHALL drop the step that runs `./internal/syncgraph`, the `script/sync-bellu-graph/**` path filter, and every other reference to sync, rename or the Vendored_Tree.
6. THE repository SHALL remove the `go.mod` and `go.sum` entries that only the Vendored_Tree required, as computed by `go mod tidy`.
7. THE `go-server-bellu-graph` spec (`requirements.md`, `design.md`, `tasks.md`, `tasks.meta.json`) SHALL drop the sync tool, rename map, Allow_List, NOTICE and upstream references, and SHALL describe the Engine as the Bellu Graph Engine implemented in-tree.
8. THE `bellud` README SHALL replace the "Sync the Bellu Graph engine" section with a description of the in-tree Engine.

### Requirement 24: Migration

**User Story:** As an operator, I want clear upgrade steps, so that I know what happens to existing graph data.

#### Acceptance Criteria

1. THE Engine SHALL use a new Store format version and SHALL read no data written by the previous engine.
2. IF `Config.Dir/default` holds a store written by the previous engine, THEN `Open` SHALL fail with an error wrapping `ErrCorrupt` that tells the operator to delete the directory.
3. THE `bellud` README SHALL document that the graph in `~/.local/share/bellucode/graph` may be deleted before the first start of the new version and that collectors rebuild the graph on their next run.
4. WHEN a collector runs against an empty Store, THE Engine SHALL rebuild the collector's part of the graph from that Batch with no manual step.

### Requirement 25: Zero upstream-name check

**User Story:** As a maintainer, I want proof that no upstream name remains, so that attribution is truly unnecessary.

#### Acceptance Criteria

1. WHEN the Leftover_Check runs after Requirement 23 is complete, THE repository SHALL return zero matches.
2. THE Leftover_Check SHALL match file paths as well as file contents.
3. THE repository SHALL provide a script `script/check-no-upstream-name` that runs the Leftover_Check and exits non-zero on any match, and THE CI workflow SHALL run the script.
4. THE script SHALL build its search term from concatenated fragments, so that the script does not match its own check.
5. THE documentation SHALL describe the Engine as original work and SHALL mention no third-party origin.
