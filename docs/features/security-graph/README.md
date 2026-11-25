# Unified Security Graph

The Unified Security Graph connects sources to one read-only graph and presents it through lenses. Every stage only reads from the customer's systems.

The first release ships a GitHub collector and an AWS collector. Bellud downloads signed threat intelligence from Bellu Cyber Global Intel in one direction and sends no customer data back.

Routes under `/api/experimental/graph/` are experimental and may change without compatibility guarantees.

## Architecture

### Pipeline

```
sources -> connectors -> collectors -> graph engine (Bellud) -> lenses -> UI and MCP
```

| Stage | Where it lives |
| --- | --- |
| Connections, vault, broker (read-only operation allowlist) | `services/bellud/internal/connectors/{lifecycle,broker,store,vault}` |
| Collectors (GitHub, AWS) | `internal/connectors/github`, `internal/connectors/aws`, scheduled by `collectors.Runner` |
| Graph engine | `internal/bellugraph/facade`, fed only through `Ingest().Apply` |
| Intel sync and store | `internal/intel/*` |
| Correlator and risk score | `internal/correlate`, `internal/risk` |
| Lens engine | `internal/lens` |
| Agent overlay | `internal/overlay` |
| HTTP routes | `internal/api/graph` (`lens.go`) |
| MCP tools | `internal/lens/lensmcp`, registered through `facade.Config.MCPExtras` |
| UI | `packages/app/src/security-graph` (SolidJS, Sigma 4) |

Rules that hold for the whole pipeline:

- Collectors perform read operations only.
- Bellud sends nothing about the customer to Global Intel. It issues `GET` requests for the pointer and the bundle, with no cookies, identifiers, body, or query string.
- A lens builds its slice from the engine without modifying graph content.
- Overlay events are discarded after delivery. They are never stored as graph facts, and `internal/overlay` does not import the facade.
- The Bellu Cyber code in `global-intel` and `internal/risk` is a reference that was ported to Go. Bellud imports nothing from `github.com/bellu/bellu-ai-cyber`.

### Package layout

```
services/bellud/internal/
  canonical/        key normalization (pure)
  intel/model/      Vuln, AffectedPackage, SplitPurl, MatchPackage (port)
  intel/bundle/     pointer parsing, bundle Verify, pinned key
  intel/store/      Pebble intel store
  intel/sync/       Syncer: schedule, fetch, import, status
  risk/             Compute, Bucket
  correlate/        Plan (pure) and Correlator (a collectors.Collector)
  lens/             lens definitions, engine, slice, prune, budget, confidence
  lens/lensmcp/     slice, attack_paths, blast_radius, reachable_vulns
  overlay/          Event, Hub, scripted replay
  api/graph/        read API plus lens, intel status, and overlay handlers
```

Wiring is in `cmd/bellud/main.go` (`openGraph`). Shutdown order is Syncer, Runner, engine, intel store.

## Naming contract

### Canonical_Key

`canonical_key` is a descriptive entity attribute shared across connections. It is never an identity attribute, so it cannot change an Entity_ID. Collectors set it only when the provider gives a stable identifier.

| Source identifier | Key | Normalization |
| --- | --- | --- |
| ARN | `arn:<partition>:<service>:<region>:<account>:<resource>` | Trim. Lowercase the first five segments. Keep the resource part as is. Reject fewer than six segments. |
| purl | `pkg:<type>/<namespace>/<name>@<version>` | Trim. Drop qualifiers and subpath. Lowercase everything before the final `@`. |
| CVE or GHSA id | `vuln:<ID>` | Trim and uppercase. |
| Image digest | `sha256:<64 hex>` | Trim and lowercase. Anything else has no key. |
| Git URL | `git:<host>/<owner>/<repo>` | Accept https, http, ssh, git, and `git@host:owner/repo`. Drop user info, port, `.git`, trailing slash, query, and fragment. Lowercase. |

`Key(kind, raw)` returns false when no key can be derived, and `Key(Key(x)) == Key(x)`.

Which collector sets which key:

- GitHub: `github_repo` gets `git:`, `package` gets `pkg:`.
- AWS: `aws_resource` gets `arn:`.
- Correlator: `vulnerability` gets `vuln:`.
- Docker: `image` gets `sha256:` when its `id` is a digest.

### Entity kinds

Existing Entity_IDs do not change. This feature adds two kinds.

| Kind | Identity attributes | Notes |
| --- | --- | --- |
| `package` | `connection`, `scope`, `purl` | Connection-scoped, so disconnecting removes it. `scope` is the repo full name for GitHub. `purl` is the versioned purl. |
| `vulnerability` | `id` | Global. One node per canonical id, shared by every package it affects. Owned by the correlator. |

### Relation types

Every relation type, its direction, and its default confidence are declared in the per-source registry (see "Per-source registry"). `describe_schema` lists them all. A relation may also carry its own `confidence` edge attribute (see "Edge_Attributes"); a valid stored value wins over the default. The correlator types are:

| Type | Direction | Meaning | Confidence |
| --- | --- | --- | --- |
| `affected_by` | Reverse | package to vulnerability | extracted |
| `same_as` | Reverse | group member to group anchor (smallest Entity_ID) | extracted |
| `likely_same_as` | Reverse | same shape, found by heuristic | inferred |

An extracted relation comes from an exact Canonical_Key match or a provider-reported fact. An inferred relation comes from a heuristic. The confidence of a path equals the confidence of its weakest hop, so one inferred hop makes the whole path inferred.

`same_as` groups are stars around the anchor, so n members cost n-1 relations. The existing `depends_on` links a `github_repo` to its `package` entities.

### Attribute names to avoid

The redaction guard and `ident.IsSecretName` reject attribute names that contain these fragments: `secret`, `token`, `password`, `credential`, `private`, `apikey`, `hash`. An attribute must also not be named `data`. Use names such as `canonical_key`, `internet_exposed`, `purl`, `cvss`, `epss`, `kev`, `severity`, `summary`, `fixed_in`.

## Per-source registry

Every entity kind, resource type, relation type, and collection category is declared by exactly one source in a leaf `...schema` package that imports only the standard library and `internal/graph/schema`:

| Source | Package |
| --- | --- |
| `core` | `internal/graph/schema/coreschema` |
| `github` | `internal/connectors/github/githubschema` |
| `aws` | `internal/connectors/aws/awsschema` |
| `correlator` | `internal/correlate/corrschema` |

`internal/graph/schemaall` lists the declarations (`Sources()`) and merges them once (`Default()`). The merge checks every rule (name pattern and length, identity lists, descriptions, confidences, duplicate names, direction and identity conflicts between sources, source prefixes, endpoint and category references, and the required AWS names) and reports every failure, sorted, with the source, name, and reason. The result is the same for any order of declarations. The merged registry is immutable: `Register` always returns `ErrImmutable`. `facade.Open` checks the registry before any store opens and fails with a configuration error that lists every failure. `ident` reads kinds, identity lists, and directions from the registry, so Entity_IDs and directions of existing kinds are unchanged (golden vectors in `bge/ident/testdata`). The MCP tool `describe_schema` returns the registry: kinds with description, source, discriminator, and types; relations with direction, confidence, description, source, `derived`, and endpoints; and categories with status and read operations.

### Naming convention

- Names match `[a-z][a-z0-9_]*` and are at most 64 characters.
- A source with a prefix starts every kind and relation name with it: `aws_` for AWS (`aws_sg_rule`, `aws_routes_to`). Core has no prefix.
- A relation name is `<prefix>_<verb phrase>` and reads "from <verb phrase> to", for example `aws_member_of_sg` (ENI member of security group).
- Generic relations keep one meaning in every source and may be declared by several sources with the same direction and confidence: `owned_by`, `runs_on`, `on`, `uses`, `attached_to`, `depends_on`, `mounts`, `resolves_to`, `found_in`, `affected_by`, `same_as`, `likely_same_as`.
- AWS resources share the kind `aws_resource` and are told apart by the `resource_type` discriminator (`ec2:subnet`, `elbv2:load-balancer`).

### Direction_Rule

An edge reads "from <type> to". Its direction says which way impact flows.

- `Forward`: compromise or failure of `from` gives an attacker or fault a capability over `to` (routing, forwarding, credentials, permission to act, protection removed). Example: `aws_routes_to` (route table routes to internet gateway).
- `Reverse`: `from` depends on, is contained in, or is owned by `to`, so failure of `to` impacts `from`. Example: `aws_in_subnet` (ENI in subnet).
- When both criteria match, the edge is `Forward` and its description says "both matched". Example: `aws_rule_of` (rule defines the group's filtering).

Every relation declaration justifies its direction in its description (at most 200 characters).

### Edge_Attributes

A relation may carry three optional attributes. Every other relation attribute is rejected.

| Name | Value |
| --- | --- |
| `evidence` | String, at most 512 bytes. Lens slices cut it at 512 bytes on a character boundary. |
| `confidence` | `extracted` or `inferred`. |
| `observed_at` | RFC 3339 time. Collectors set it only from a provider timestamp, never from the run time. |

An invalid name or value, a secret-like value, or two assertions of the same `(type, from, to)` with different attributes in one batch rejects the whole batch and leaves the graph unchanged. Re-asserting a relation replaces its attributes (a `RelationUpdated` event). Re-asserting it with the same attributes writes nothing, and an attribute-only change is never counted as a flap. A relation without attributes is stored byte for byte as before. After the first attribute write, downgrading to a build that does not know the attribute trailer is unsupported: the old build refuses to open the log.

This feature supersedes `unified-security-graph` Requirement 2.7 (relations carry no attributes) for `evidence`, `confidence`, and `observed_at` only. Requirement 2.7 still applies to every other relation attribute.

### Reified_Node rule

Reify a fact as its own node when it is multi-valued or carries attributes that an edge cannot hold, for example one security group with many rules, each with a direction, protocol, ports, and peer. A security group rule is an `aws_sg_rule` node (identity `connection`, `sg`, `rule_id`) with `aws_rule_of` to its group and `aws_rule_peer` to its peer: a shared `aws_cidr` node per distinct CIDR, or the peer group when it was collected. `rule_id` is the provider id, or a hash of the rule's own fields, so it is stable across runs. Caps: 200 rules per group and 20,000 rule nodes per connection; a cut sets `rules_truncated`. The `cloud` lens collapses rule nodes by default into `aws_allows_ingress_from` or `aws_allows_egress_to` edges between group and peer, with the rule's direction, protocol, and ports as evidence (`collapse_rules=false` keeps the nodes). The budget drops rule nodes before any other node.

## Lens catalog

A lens is a definition in Go that selects entities, relations, groups, and confidence for one purpose. Every lens returns a Lens_Slice (nodes, edges, groups, confidence tags) to both the HTTP API and MCP.

| ID | Layout | Selection |
| --- | --- | --- |
| `code-to-cloud` (default) | force | GitHub, package, vulnerability, AWS, and image entities with the relations among them. Grouped by `connection`. |
| `cloud` | force | `aws_account`, `aws_resource`, `aws_sg_rule`, and `aws_cidr`, grouped by `region`. Rule nodes are collapsed by default. |
| `blast-radius` | radial | Requires `entity`. Built from the engine `Impact` result (depth default 3, maximum 6). For an AWS compute entity it adds network reach (ENI, security group, ingress rule peers, members, subnet context); those nodes carry `via: network`. |
| `attack-path` | chain | Requires `target` or `target_type` (for example `rds:instance`). Built from `Path` results (at most 6 hops) from each `internet_exposed=true` entity (at most 50) to the target or to every entity of the type. It shows connectivity, not a directed exploit route. With no exposed entity, `missing_data` contains `no_internet_exposed_entity`. |
| `vulnerability-reachability` | force | Vulnerabilities whose impacted set contains an internet-exposed entity, the packages they affect, and the chain to the exposed entity. |

When a lens excludes an entity, it also excludes every relation attached to that entity.

Every slice and MCP answer has `missing_data`: the registered-only collection categories (see "Roadmap") that the answer depends on, plus sentinel entries. It is never absent, and it depends only on the lens, tool, and parameters. Edges carry `evidence` and `observed_at` when the relation has them, and `counts.omitted_rules` counts collapsed rules whose peer was not in the slice.

Budgets: 500 nodes and 1,000 edges over HTTP, 100 nodes (maximum 200) over MCP. When anything is dropped, `truncated` is true and `counts.omitted_nodes` says how many nodes were dropped.

Risk score (ported from Bellu Cyber `internal/risk`), computed by the lens when it serves a slice:

```
base     = clamp(cvss,0,10)/10 * 100
exploit  = max(clamp(epss,0,1), kev ? 0.95 : 0)
exposure = reachable ? 1.0 : 0.4
aiBoost  = 1 + 0.25 * clamp(aiCriticality,0,1)
score    = clamp(base * (0.5 + 0.5*exploit) * exposure * aiBoost, 0, 100)
severity = >=90 critical, >=70 high, >=40 medium, >=10 low, else info; KEV raises below-high to high
```

Routes:

| Route | Purpose |
| --- | --- |
| `GET /api/experimental/graph/lenses` | List lens id, name, description, layout, and params. |
| `GET /api/experimental/graph/slice` | Return a Lens_Slice. Query: `lens` (default `code-to-cloud`), `entity`, `target`, `target_type`, `collapse_rules` (`true` or `false`), `depth`, `limit`. An unknown lens returns 404 that names the id; an invalid parameter returns 400 that names the field. |
| `GET /api/experimental/graph/intel/status` | Return state, version, record count, last synced time, and last error. |
| `GET /api/experimental/graph/overlay` | Server-sent overlay events. `?replay=demo` plays a scripted replay. |

Routes under `/api/experimental/graph/` may change or be removed in any release without compatibility guarantees or deprecation notice.

MCP tools (read-only hint set, answers bounded, every edge and path tagged `extracted` or `inferred`, and `missing_data` in every answer): `slice`, `attack_paths` (`target` or `target_type`), `blast_radius`, `reachable_vulns`, and `exposed_resources` (entities with an attached security group that has an ingress rule open to `0.0.0.0/0` or `::/0`).

## Intel flow

```
Global Intel latest.json -> Syncer -> bundle.Verify -> intel store (Pebble) -> Correlator -> graph
```

1. The Syncer fetches the Latest_Pointer and, if the version is new, downloads the Release_Bundle it names.
2. `Verify` checks the ed25519 signature against the Pinned_Key and the size and sha256 of each file against `manifest.json`.
3. On success, `intel.jsonl` is imported into the intel store, keyed by CVE id and purl.
4. The Correlator reads records on demand by purl name. It never loads the full corpus into the engine.
5. When a package's purl name and version match an affected package, the Correlator creates a `vulnerability` entity and an `affected_by` relation (match-then-materialize). A record with no version ranges for the matching purl name affects every version. A version outside every range creates nothing.
6. The Correlator applies its result as a full observation, so vulnerabilities and relations that no longer match are retired when the corpus or the packages change.

The Syncer runs every 24 hours with up to 10 percent random jitter, and the first run starts 30 seconds after boot. If a local bundle path is configured, it is verified and imported without network access, which supports air-gapped installs.

Configuration:

| Setting | Effect |
| --- | --- |
| `BELLU_INTEL_URL` | Latest_Pointer URL. Unset means sync stays idle and reports `not_configured`. |
| `BELLU_INTEL_PUBKEY` | Base64 ed25519 Pinned_Key. It overrides the embedded `intel/bundle/pinned_key.txt`. With no key, sync is disabled and the status says so. |
| `BELLU_INTEL_DIR` | Intel store location. Default is `<dir of BELLU_GRAPH_DIR>/intel`. |

### Latest_Pointer

`latest.json` is a mutable object at the configured URL. Bellu Cyber publishes it. This repository only documents the contract.

```json
{
  "schema": 1,
  "version": "2026.11.15-0",
  "created_at": "2026-11-15T03:00:00Z",
  "bundle_url": "https://intel.example/releases/intel-2026.11.15-0.tar.zst",
  "bundle_sha256": "9f2c...64 hex...",
  "bundle_size": 48211904
}
```

| Field | Rule |
| --- | --- |
| `schema` | Integer. Bellud accepts `1`. Any other value is a parse failure. |
| `version` | Non-empty string, at most 64 characters. A value equal to the current corpus version means nothing to do. |
| `created_at` | RFC 3339. Informational. |
| `bundle_url` | Absolute `https` URL, or a path relative to the pointer URL. The object at this URL is immutable. |
| `bundle_sha256` | 64 lowercase hex. Early integrity check on the download. The ed25519 signature is the trust anchor. |
| `bundle_size` | Positive integer, at most 1 GiB. The download stops at this size. |

Unknown extra fields are ignored. HTTP is accepted only for loopback hosts, for tests.

The pointer is a mutable object, so Bellud applies a cache lifetime of 0. It keeps no pointer cache between runs. Each run makes one conditional GET with `If-None-Match` when it holds an ETag, and a 304 ends the run as up to date. Bundle URLs are immutable, are fetched at most once per `version`, and are never revalidated. Bellu Cyber should serve the pointer with `Cache-Control: max-age=300`.

### Failure behavior

In every case the previous corpus stays active and Bellud records the error as `last_error`, which the intel status route returns.

| Failure | Bellud behavior |
| --- | --- |
| Pointer unreachable (DNS, TLS, 15 s timeout, non-2xx other than 304) | Records `pointer_unreachable: <status or error>`. Retries at the next scheduled run, or after 1 hour when the previous run failed. |
| Pointer not JSON, wrong schema, or a bad field | Records `pointer_invalid: <field>`. No download. |
| Bundle download fails or is shorter than `bundle_size` (10 minute timeout) | Records `download_failed` and deletes the partial file. |
| Download sha256 differs from `bundle_sha256` | Records `download_corrupt` and discards the bundle. |
| Signature, manifest, member sha256, or archive limit check fails | Records `verification_failed: <reason>`, discards the bundle, and imports nothing. Archive limits: at most 8 members, 1 GiB decompressed in total, 512 MiB per member. |
| Import fails midway | Records `import_failed`. The old generation stays active. |

The store writes each import to a new generation and flips the active generation in one batch, so a failed import never changes what readers see.

## Roadmap

Collection categories and their status. Generated from the registry; do not edit by hand.

<!-- roadmap:start -->
| Category | Status | Read operations a collector needs |
| --- | --- | --- |
| `azure_ai` | implemented | none |
| `azure_compute` | implemented | none |
| `azure_data` | implemented | none |
| `azure_identity` | implemented | none |
| `azure_network` | implemented | none |
| `azure_ownership` | implemented | none |
| `compute` | registered-only | `autoscaling:DescribeAutoScalingGroups`, `ec2:DescribeImages`, `ec2:DescribeLaunchTemplates`, `ecs:DescribeServices`, `ecs:DescribeTasks`, `ecs:ListClusters`, `ecs:ListTasks`, `eks:DescribeCluster`, `eks:ListClusters`, `eks:ListNodegroups`, `iam:ListInstanceProfiles`, `lambda:ListLayers` |
| `controls` | registered-only | `cloudtrail:DescribeTrails`, `config:DescribeConfigRules`, `config:DescribeConfigurationRecorders`, `guardduty:GetFindings`, `guardduty:ListDetectors`, `guardduty:ListFindings`, `inspector2:ListFindings`, `securityhub:GetFindings`, `wafv2:ListWebACLs` |
| `data` | registered-only | `dynamodb:DescribeTable`, `dynamodb:ListTables`, `ec2:DescribeSnapshots`, `ec2:DescribeVolumes`, `elasticfilesystem:DescribeFileSystems`, `kms:DescribeKey`, `kms:ListAliases`, `kms:ListKeys`, `rds:DescribeDBClusters`, `s3:GetBucketEncryption`, `s3:GetBucketPolicy`, `secretsmanager:ListSecrets`, `ssm:DescribeParameters` |
| `dns` | registered-only | `route53:ListHostedZones`, `route53:ListResourceRecordSets` |
| `gcp_compute` | registered-only | `compute.instances.list`, `container.clusters.list` |
| `gcp_data` | registered-only | `sql.instances.list`, `storage.buckets.list` |
| `gcp_identity` | registered-only | `cloudresourcemanager.projects.getIamPolicy`, `iam.serviceAccounts.list` |
| `gcp_network` | registered-only | `compute.firewalls.list`, `compute.networks.list`, `compute.subnetworks.list` |
| `gcp_ownership` | registered-only | `cloudresourcemanager.projects.get` |
| `identity` | registered-only | `iam:GetAccountAuthorizationDetails`, `iam:GetPolicyVersion`, `iam:GetRole`, `iam:ListGroups`, `iam:ListPolicies`, `iam:ListUsers` |
| `network` | implemented | none |
| `ownership` | registered-only | `organizations:DescribeOrganization`, `organizations:ListAccountsForParent`, `organizations:ListOrganizationalUnitsForParent`, `organizations:ListPolicies`, `organizations:ListRoots`, `organizations:ListTargetsForPolicy` |
| `workloads` | implemented | none |
<!-- roadmap:end -->

## Add a new Collector

A Collector reads one Connection and emits a Batch of entities and relations. Scheduling, timeouts, redaction, and retirement come from the existing runner.

1. Implement the connector under `internal/connectors/<name>`. Declare read operations only in its manifest. The broker enforces the read-only allowlist.
2. Implement a `collectors.Collector`. The supervisor runs one per Connection, named `connector:<id>:<connection>`. Emit the full snapshot of the Connection on each run.
3. Register any new entity kind and relation type in the registry, in this order:
   1. Declare the kinds, resource types, and relation types in the source's leaf `...schema` package (for example `internal/connectors/aws/awsschema`). Do not change the identity list of an existing kind.
   2. Add the declaration to `schemaall.Sources()`.
   3. Run `go test ./internal/graph/schema/... ./internal/bellugraph/...` from `services/bellud` and confirm the registry check and golden-vector tests pass.
   4. Justify each relation direction with the Direction_Rule in the declaration description and in the source's design table.
4. Connection-scoped kinds include `connection` in their identity attributes, so disconnecting removes them without touching other connections.
5. Set `canonical_key` through `canonical.Key` whenever the provider has an ARN, purl, CVE or GHSA id, image digest, or git URL, so the entity can join across connections.
6. Use attribute names that avoid the fragments listed under "Attribute names to avoid".
7. Implement the optional `collectors.StatusReporter` so the Run_Status is recorded:
   - On a rate-limit response, wait until the reset time the source reports and report the wait (`RateLimitWaits`).
   - On rejected credentials, end the run and report `AuthError`.
   - On access denied for one scope, add it to `DeniedScopes` and continue with the other scopes.
8. Add the entity kinds to the `code-to-cloud` lens definition if they belong in it, and add offline tests for the pure logic (identity, key derivation, any exposure or mapping function).

A finished run replaces the entities of its Connection with the new Batch.

## Credits

The ideas of extracted versus inferred edges, weakest-hop confidence, and bounded subgraph answers come from Graphify (Apache-2.0, Python). This repository includes a modified copy of Graphify, licensed under Apache-2.0, in `third_party/bellu-graphify/`. See its `LICENSE`, `NOTICE`, `PROVENANCE.md`, and `CHANGES.md`.

## Regenerating protocol, client, and routes

After the experimental routes change, regenerate the protocol, client, and route table with `bun run generate` from `packages/client`. Do not edit generated client files directly.

The route table (`routes.yaml`) is rewritten first so the new paths are `owner: go`, and the overlay path needs `stream: true`:

1. `bun services/bellud/script/gen-operations.ts` (repository root).
2. `go test ./internal/server/routes -run TestGenerate -update -count=1` (from `services/bellud`).
3. `bun run generate` (from `packages/client`).
4. If the contract tests report drift, run `bun services/bellud/script/gen-gocontract.ts`.
5. Run `bun typecheck` in `packages/schema`, `packages/protocol`, `packages/client`, and `packages/app`, and `bun test test/experimental-identifiers.test.ts` in `packages/protocol`.

Schema and protocol changes go first: edit `packages/schema/src/graph.ts` and `packages/protocol/src/groups/experimental-graph.ts`, keeping new fields optional so older clients stay valid.
