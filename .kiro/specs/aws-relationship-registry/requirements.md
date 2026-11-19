# Requirements Document

## Introduction

This feature extends the Unified Security Graph (`.kiro/specs/unified-security-graph`, `docs/features/security-graph/README.md`) in two ways.

1. **Per-source registry.** Today `ident.identityAttrs` and `ident.relDirections` are two global maps. Each source (core, GitHub, AWS, correlator, and later sources) instead declares its own entity kinds and relation types in its own package. A central check merges the declarations, rejects conflicts, and produces the maps the engine already consumes.
2. **AWS security-graph taxonomy.** The registry holds the complete AWS taxonomy across six dimensions: ownership and hierarchy, network connectivity and exposure, compute and workload, identity and permissions, data access and storage, and security controls and monitoring. The first collector increment implements the **network slice**. Every other category is registered and listed on a roadmap, and nothing in the design is network-only.

The goal is to answer questions such as: if an EC2 instance is compromised, what can an attacker reach; which S3 buckets can an IAM role access; can an internet-facing resource reach an RDS database; which Lambda functions can access production secrets; which resources are exposed through a misconfigured security group; what is the blast radius of compromising an AWS account or identity. The first release answers the questions that need only network data and reports plainly which questions need data that is not yet collected.

### Decisions fixed by the request

- **Edge evidence is hybrid.** The engine accepts a small fixed set of optional relation attributes (`evidence`, `confidence`, `observed_at`). Complex or multi-valued facts, such as a security group rule, are reified as entity nodes, because a relation is keyed by `(type, from, to)` and two rules between the same pair would otherwise collapse.
- **Relation names are hybrid.** Generic names are kept where meaning is identical across sources (`owned_by`, `runs_on`, `uses`, `depends_on`, `mounts`, `resolves_to`, `found_in`). Source-specific meanings use a source prefix written with underscores, for example `aws_allows_ingress_from`, `aws_routes_to`, `aws_has_eni`, `aws_can_pass_role`. Relation type names match `[a-z][a-z0-9_]*`, so dots are never used.
- **Effective access is derived.** `attached_policy` is not effective access. `aws_can_access` is a derived relation produced by a future authorization analysis engine. This release registers it and does not evaluate it.

### Amendment to an earlier requirement

This feature supersedes Requirement 2.7 of `unified-security-graph` ("no attribute on the relation and no change to the Graph_Engine storage model") for the fixed optional edge attribute set only. Relation confidence for relations that carry no `confidence` attribute is still carried by the Relation_Type default. Every other attribute name on a relation is still rejected.

### Out of scope for this release

- The authorization analysis engine that evaluates IAM identity policies, resource policies, trust policies, permission boundaries, SCPs, session policies, explicit denies, and conditions.
- Collectors for categories other than the network slice (see the roadmap in Requirement 12).
- Any write operation against an AWS account.
- Changes to entity identity hashing of existing kinds.

## Glossary

- **Bellud**: The Go service at `services/bellud`.
- **Graph_Engine**: The graph engine in `services/bellud/internal/bellugraph` that stores entities and relations.
- **Source**: A producer of graph facts that owns a namespace of kinds and relation types. Sources in this release are `core`, `github`, `aws`, and `correlator`.
- **Source_Declaration**: The set of Kind_Declarations and Relation_Declarations that one Source registers from its own package.
- **Kind_Declaration**: A declaration of an entity kind with its identity attributes and a description.
- **Relation_Declaration**: A declaration of a relation type with its name, Impact_Direction, default confidence, and description.
- **Registry**: The merged, read-only result of all Source_Declarations, which supplies the identity attribute lookup, `DirectionOf`, `RelationTypes`, and `Kinds`.
- **Registry_Check**: The central validation that runs when Source_Declarations are merged.
- **Impact_Direction**: `Forward` means failure or compromise of `from` impacts `to`. `Reverse` means failure or compromise of `to` impacts `from`.
- **Direction_Rule**: The rule used to assign an Impact_Direction, defined in Requirement 4.
- **Source_Prefix**: The lowercase prefix that a Source puts before its source-specific relation type names and kind names, followed by an underscore, for example `aws_`.
- **Generic_Relation**: One of `owned_by`, `runs_on`, `on`, `uses`, `attached_to`, `depends_on`, `mounts`, `resolves_to`, `found_in`, `affected_by`, `same_as`, `likely_same_as`, which keep one meaning in every Source.
- **Edge_Attributes**: The fixed optional relation attributes `evidence`, `confidence`, and `observed_at`.
- **Evidence**: A short string attribute of a relation that names the fact that established it, for example `sg-0abc rule sgr-0123 tcp/443 from 0.0.0.0/0`.
- **Confidence**: `extracted` (provider-reported fact or exact join) or `inferred` (heuristic or partial evidence).
- **Observed_At**: The valid time of the observation, as RFC 3339 text with second precision in UTC.
- **Reified_Node**: An entity node that represents a fact that would otherwise be a multi-valued or attributed relation, such as a security group rule.
- **Rule_Node**: The Reified_Node of kind `aws_sg_rule` that represents one security group rule entry.
- **Network_Slice**: The AWS resources and relations of the network dimension: VPC, subnet, ENI, route table, internet gateway, NAT gateway, security group and rules, network ACL, VPC endpoint, VPC peering connection, Elastic IP, load balancer, target group, listener, and transit gateway.
- **AWS_Collector**: The collector at `services/bellud/internal/connectors/aws`.
- **AWS_Client**: The `Client` interface in `connectors/aws/client.go` that the AWS_Collector depends on.
- **Manifest_Allowlist**: The list of read operations in `connectors/aws/manifest.go` that the broker permits.
- **Internet_Reachable**: The derived state of a resource that satisfies the exposure rule in Requirement 9.
- **Lens_Engine**: The Bellud component in `internal/lens` that builds Lens_Slices.
- **Lens_Slice**: The Lens_Engine output of nodes, edges, groups, and confidence tags.
- **Authorization_Analysis**: The future component that derives `aws_can_access` from policies. Not built in this release.
- **Log_Codec**: The binary encoding of events and snapshots in `internal/bellugraph/internal/bge/codec`.
- **Legacy_Data**: Event logs and snapshots written by a Bellud build that predates this feature.
- **Roadmap**: The table in the Graph_README that lists every registered AWS category with the status `implemented` or `registered-only`.
- **Run_Status**: The per-run record of rate-limit waits, authorization error, denied scopes, and truncations.
- **Final_Checkpoint**: The last task, which runs the build, vet, test, and check commands.
- **Graph_README**: The document at `docs/features/security-graph/README.md`.

## Requirements

### Requirement 1: Per-source declarations

**User Story:** As a developer adding a source, I want to declare that source's kinds and relation types in its own package, so that I never edit a global map.

#### Acceptance Criteria

1. WHEN a Source supplies a Source_Declaration from its own package during startup, THE Registry SHALL accept the Source_Declaration and associate it with that Source.
2. THE Kind_Declaration SHALL contain a kind name of 1 to 64 characters, an ordered list of 1 to 16 identity attributes with no duplicate attribute names, and a description of 1 to 500 characters.
3. THE Relation_Declaration SHALL contain a relation type name of 1 to 64 characters, an Impact_Direction, a default confidence of exactly `extracted` or `inferred`, and a description of 1 to 500 characters.
4. WHEN a caller invokes the kind identity attribute lookup, `DirectionOf`, `RelationTypes`, or `Kinds` after startup merging completes, THE Registry SHALL return results computed from the merged declarations, with the same signatures and return semantics as the current `ident` package.
5. WHEN `DirectionOf` is called with a relation type that is not registered, THE Registry SHALL return the `Reverse` direction and report that the default was applied, as `DirectionOf` does today.
6. WHEN startup merging completes, THE Registry SHALL reject any later attempt to add or modify a declaration, leave the merged contents unchanged, and return an error to the caller indicating the Registry is immutable.
7. WHEN startup merging completes, THE Registry SHALL provide, for each registered kind and relation type, the name of exactly one Source that declared it.
8. IF a Source_Declaration contains a Kind_Declaration or Relation_Declaration that violates the constraints in criterion 2 or 3, or declares a kind name or relation type name already declared by any Source in a conflicting way, THEN THE Registry SHALL reject the entire Source_Declaration, return an error identifying the Source and the offending name and the reason, and leave previously accepted declarations unchanged. (A Generic_Relation declared identically by two Sources is not a conflict, see Requirement 2.)

### Requirement 2: Registry validation and conflict detection

**User Story:** As a maintainer, I want conflicting or malformed declarations rejected at startup, so that two sources cannot silently disagree about a name.

#### Acceptance Criteria

1. WHEN two declarations from different Sources register the same relation type name with different Impact_Directions, THE Registry_Check SHALL fail the merge and report an error that names both Sources, the relation type name, and both Impact_Directions.
2. WHEN two declarations from different Sources register the same kind name with different identity attribute lists, THE Registry_Check SHALL fail the merge and report an error that names both Sources, the kind name, and both identity attribute lists. Lists that contain the same attributes in a different order SHALL count as different.
3. WHEN one Source declares the same relation type name or the same kind name more than once, THE Registry_Check SHALL fail the merge and report an error that names the Source, the name, and whether it is a relation type or a kind.
4. WHEN two Sources declare the same Generic_Relation name with the same Impact_Direction and the same default confidence, THE Registry_Check SHALL accept the merge and keep exactly one entry for that name.
5. IF two Sources declare the same Generic_Relation name with the same Impact_Direction and different default confidence, THEN THE Registry_Check SHALL fail the merge and report an error that names both Sources, the relation type name, and both default confidence values.
6. IF a relation type name does not match `[a-z][a-z0-9_]*` or is longer than 64 characters, THEN THE Registry_Check SHALL fail the merge and report an error that names the offending relation type and its Source.
7. IF a kind name does not match `[a-z][a-z0-9_]*` or is longer than 64 characters, THEN THE Registry_Check SHALL fail the merge and report an error that names the offending kind and its Source.
8. IF a Source other than `core` declares a source-specific relation type or kind whose name does not begin with that Source's Source_Prefix, and the name is neither a Generic_Relation nor an existing migrated kind listed in Requirement 3, THEN THE Registry_Check SHALL fail the merge and report an error that names the Source, the name, and the expected Source_Prefix.
9. IF a kind declares zero identity attributes, or declares an identity attribute whose name is empty, THEN THE Registry_Check SHALL fail the merge and report an error that names the Source and the kind.
10. IF a relation type or kind declaration has a description that is empty or contains only whitespace, THEN THE Registry_Check SHALL fail the merge and report an error that names the Source and the declared name.
11. IF a declared attribute name satisfies `ident.IsSecretName` or equals `data`, THEN THE Registry_Check SHALL fail the merge and report an error that names the Source, the kind or relation type, and the attribute name.
12. IF the Registry_Check fails at Bellud startup, THEN THE Bellud SHALL NOT open the Graph_Engine, SHALL report every failure found in a single error, and SHALL exit without partially applying any declaration.
13. THE Registry_Check SHALL produce the same set of failures, and the same accept or fail result, for every ordering of the same declarations.

### Requirement 3: Migration of existing kinds and relation types

**User Story:** As an operator, I want the existing graph to behave exactly as before, so that upgrading changes no entity ID and no impact answer.

#### Acceptance Criteria

1. WHEN the Registry finishes loading, THE Registry SHALL contain every kind and every relation type present in the `ident` maps before this feature, with each one declared by exactly one owning Source (`core`, `github`, `aws`, or `correlator`) and no kind or relation type declared by more than one Source, except Generic_Relations declared identically as allowed by Requirement 2.
2. WHEN the Registry finishes loading, THE Registry SHALL hold, for every existing kind, an identity attribute list that is identical to the pre-feature list in both content and order.
3. WHEN the Registry finishes loading, THE Registry SHALL hold, for every existing relation type, an Impact_Direction that is identical to the pre-feature value.
4. WHEN the Graph_Engine computes an Entity_ID for an existing kind, THE Graph_Engine SHALL return a value byte-for-byte identical to the value produced before this feature, verified by a golden-vector test containing at least one vector per existing kind, where each vector is generated from the pre-feature code.
5. WHEN the Graph_Engine is replayed from Legacy_Data, THE Graph_Engine SHALL load 100% of the entities and relations, keep every stored Entity_ID unchanged, and report zero load errors.
6. IF the Graph_Engine fails to load a record during replay from Legacy_Data, THEN THE Graph_Engine SHALL abort the replay, report an error identifying the failing record, and leave the previously persisted graph data unmodified.
7. IF `ident.Hash` is called with a kind that is not registered, THEN THE `ident.Hash` function SHALL return an error indicating an unregistered kind and produce no Entity_ID.
8. IF `ident.Hash` is called with an identity attribute that is missing or is an empty string, THEN THE `ident.Hash` function SHALL return an error identifying the offending attribute and produce no Entity_ID.

### Requirement 4: Naming convention and Impact_Direction rule

**User Story:** As an analyst, I want one consistent meaning for relation direction, so that blast-radius and attack-path answers are correct across sources.

#### Acceptance Criteria

1. THE Direction_Rule SHALL assign `Forward` to a relation type when compromise or failure of `from` gives an attacker or fault a capability over `to`, such as network reachability, permission to act, or the ability to assume.
2. THE Direction_Rule SHALL assign `Reverse` to a relation type when `from` depends on, is contained in, or is owned by `to`, so that failure of `to` impacts `from`.
3. IF a relation type fits both criterion 1 and criterion 2, THEN THE Direction_Rule SHALL assign `Forward`, and THE design document SHALL state in the one-line justification for that type that both criteria matched.
4. THE Registry SHALL declare each source-specific relation type with a name of the form `<source prefix>_<verb phrase>` that reads as the sentence `from <type> to`, for example `subnet aws_in_vpc vpc`, and each AWS relation type name SHALL start with `aws_`.
5. THE design document SHALL contain a table that lists every registered AWS relation type with its `from` kind, `to` kind, Impact_Direction, default confidence, and a justification of at most 200 characters that applies the Direction_Rule, and the number of table rows SHALL equal the number of AWS relation types in the Registry.
6. THE Registry SHALL declare a distinct source-specific relation type for each meaning that the taxonomy draft expressed with the single name `attached_to`, and SHALL declare no AWS relation type that has two meanings.
7. THE Registry SHALL declare the network reachability relation of a security group rule as `aws_allows_ingress_from`, with its `from` and `to` kinds and its Impact_Direction assigned by the Direction_Rule, and the design table SHALL justify the direction chosen for `aws_allows_ingress_from`.
8. THE Registry SHALL declare `aws_attached_policy` as a relation that states only that a policy is attached to an identity, and SHALL give it a description that says it does not establish effective access.
9. THE Registry SHALL declare `aws_can_access` as a derived relation with a description that states Authorization_Analysis produces it and that it carries Evidence and Confidence.
10. FOR ALL registered relation types, WHEN the Registry is queried for a relation type, THE Registry SHALL return a direction that is exactly `Forward` or `Reverse` and a default confidence that is exactly `extracted` or `inferred`.
11. WHEN the Registry is queried for a relation type name that is not registered, THE Registry SHALL return the `Reverse` direction, report that the default was applied, and report the default confidence `extracted`, consistent with Requirement 1.
12. THE Registry SHALL declare each Generic_Relation with the same Impact_Direction that the Generic_Relation has in the current codebase before this change.

### Requirement 5: Discoverability through MCP

**User Story:** As an AI agent, I want to read the schema, so that I know which kinds and relation types exist and what direction each has.

#### Acceptance Criteria

1. WHEN a client calls the MCP `describe_schema` tool, THE MCP_Server SHALL return one entry for every registered kind, and each entry SHALL contain the kind name, its identity attributes (attribute names in declared order), its description, and the name of the declaring Source.
2. WHEN a client calls the MCP `describe_schema` tool, THE MCP_Server SHALL return one entry for every registered relation type, and each entry SHALL contain the relation type name, its Impact_Direction, its default confidence (`extracted` or `inferred`), its description, and the name of the declaring Source.
3. WHEN a client calls the MCP `describe_schema` tool, THE MCP_Server SHALL include in the response every field that the tool returned before this change, with the same field name, value type, and value semantics.
4. WHEN a client calls the MCP `describe_schema` tool, THE MCP_Server SHALL order kind entries and relation type entries each in ascending order by name (case-sensitive, code-point order), so that two calls against an unchanged registry return identical output.
5. IF the registry contains no kinds or no relation types, THEN THE MCP_Server SHALL return an empty list for the missing category, and the call SHALL complete without an error.
6. IF the MCP_Server fails to read the registry while handling a `describe_schema` call, THEN THE MCP_Server SHALL return an error response indicating that the schema could not be read and SHALL NOT return a partial schema.

### Requirement 6: Fixed optional edge attributes

**User Story:** As an analyst, I want a relation to say how it was established and how sure Bellud is, so that I can trust an attack path.

#### Acceptance Criteria

1. THE Graph_Engine SHALL accept on a relation only the Edge_Attributes `evidence`, `confidence`, and `observed_at`, each optional.
2. IF a relation carries an attribute name other than an Edge_Attribute, THEN THE Graph_Engine SHALL reject the whole Batch with a validation error that names the attribute, and SHALL leave the stored graph unchanged.
3. IF `confidence` is a value other than the exact, case-sensitive strings `extracted` or `inferred`, THEN THE Graph_Engine SHALL reject the whole Batch with a validation error that names the attribute `confidence`, and SHALL leave the stored graph unchanged.
4. IF `evidence` is not a string or is longer than 512 bytes when encoded as UTF-8, THEN THE Graph_Engine SHALL reject the whole Batch with a validation error that names the attribute `evidence`, and SHALL leave the stored graph unchanged. An `evidence` string of 0 to 512 bytes SHALL be accepted.
5. IF `observed_at` is not a string that is a valid RFC 3339 timestamp, THEN THE Graph_Engine SHALL reject the whole Batch with a validation error that names the attribute `observed_at`, and SHALL leave the stored graph unchanged.
6. THE Graph_Engine SHALL keep the relation identity as `(type, from, to)`, with the Edge_Attributes excluded from the identity.
7. WHEN a Batch asserts a relation that already exists with different Edge_Attributes, THE Graph_Engine SHALL replace the stored Edge_Attributes with the new values and keep one relation. An Edge_Attribute that the asserted relation omits SHALL be removed from the stored relation.
8. WHEN a relation carries no `confidence`, THE Lens_Engine SHALL use the default confidence of the Relation_Declaration.
9. IF the value of an Edge_Attribute looks like a secret according to the existing redaction guard, THEN THE Graph_Engine SHALL reject the whole Batch with a validation error that names the attribute, and SHALL leave the stored graph unchanged.
10. WHEN a Batch asserts an unchanged relation with unchanged Edge_Attributes, THE Graph_Engine SHALL record no new event.
11. WHEN a Batch changes only the Edge_Attributes of an existing relation, THE Graph_Engine SHALL record one update event that is not a state-changed event and SHALL NOT count it as a flap.

### Requirement 7: Backward-compatible persistence of edge attributes

**User Story:** As an operator, I want upgrades and downgrades-in-place to keep my graph, so that adding edge attributes never invalidates stored data.

#### Acceptance Criteria

1. THE Log_Codec SHALL encode Edge_Attributes in `RelationRecord` and in the `RelationAdded` event such that a record written by the previous format (Legacy_Data) decodes without error and every field absent from the record decodes to the empty value (an empty map with zero entries).
2. WHEN a relation has zero Edge_Attributes, THE Log_Codec SHALL write bytes identical to the bytes the previous format writes for the same relation, so that a log containing no Edge_Attributes is byte-for-byte identical to a log written by the previous format.
3. WHEN the Log_Codec reads a `RelationRecord` or `RelationAdded` event written by the previous format, THE Log_Codec SHALL decode it with zero Edge_Attributes and with all other fields equal to the values stored in the record.
4. IF the Log_Codec reads a record that contains a trailing field set it does not recognize (written by a newer version), THEN THE Log_Codec SHALL return a decode error that identifies the record position and states that an unknown trailing field set was found, SHALL NOT return a partially decoded or truncated record, and SHALL leave previously decoded records and the stored log bytes unchanged.
5. FOR ALL relations with 0 to 3 Edge_Attributes, encoding then decoding SHALL produce a relation equal to the original, including every attribute key and value (round-trip property).
6. FOR ALL event logs, WHEN the log is replayed from the start, THE Graph_Engine SHALL produce a graph whose entities, relations and Edge_Attributes are equal to those of the live engine that wrote the log.
7. WHEN a snapshot is taken and then restored, THE Graph_Engine SHALL restore every relation with Edge_Attributes equal to those it had at snapshot time, and SHALL restore a snapshot written by the previous format with zero Edge_Attributes on every relation.
8. WHEN a client reads the graph as of a past time T, THE Graph_Engine SHALL return for each relation the Edge_Attributes produced by all events with timestamps less than or equal to T, and a relation whose first event is later than T SHALL NOT be returned.
9. THE test suite SHALL include a fixture containing a Legacy_Data log and a Legacy_Data snapshot, and a test that loads each fixture and asserts that the resulting entities and relations equal an expected set recorded with the fixture, with zero Edge_Attributes on every relation.

### Requirement 8: Reified nodes for multi-valued facts

**User Story:** As a security engineer, I want each security group rule to be its own node, so that two rules between the same resources do not collapse and each keeps its protocol, port range, and source.

#### Acceptance Criteria

1. THE Registry SHALL declare the kind `aws_sg_rule` with the identity attributes `connection`, `sg`, `rule_id`, and with the attributes `direction` (one of `ingress` or `egress`), `protocol`, `from_port` (integer 0 to 65535, or absent when the protocol has no ports), `to_port` (integer 0 to 65535, greater than or equal to `from_port`, or absent when the protocol has no ports), `cidr`, `peer_sg`, `prefix_list`, and `description` (maximum 1,024 characters) stored as descriptive attributes.
2. WHEN the AWS_Collector sees a security group rule, THE AWS_Collector SHALL emit exactly one Rule_Node, and the `rule_id` SHALL be the provider rule identifier when present, else a value derived only from direction, protocol, port range, and peer.
3. WHEN the AWS_Collector emits a Rule_Node, THE AWS_Collector SHALL link it to its security group with one `aws_rule_of` edge and to its peer (a CIDR node, a security group, or a prefix list) with one `aws_rule_peer` edge.
4. WHEN the same input describes the same rules in two separate collection runs, THE AWS_Collector SHALL produce identical `rule_id` values and identical Entity_IDs, regardless of the order in which the rules are received.
5. WHEN the AWS_Collector sees a CIDR peer, THE AWS_Collector SHALL emit it as an `aws_cidr` node with the identity attributes `connection` and `cidr`, one node per distinct CIDR value in a Connection, and two rules with the same CIDR in one Connection SHALL link to the same `aws_cidr` node.
6. IF a security group has more than 200 rules or a Connection has more than 20,000 Rule_Nodes, THEN THE AWS_Collector SHALL stop emitting further Rule_Nodes for that security group or Connection, retain the Rule_Nodes already emitted, set `rules_truncated` to `true` on the affected security group or account entity, and record the truncation in the Run_Status with the affected security group or Connection and the number of rules omitted.
7. WHEN the AWS_Collector emits a Rule_Node, THE AWS_Collector SHALL set `internet_open` to `true` on the Rule_Node if the peer CIDR is `0.0.0.0/0` or `::/0`, and SHALL set it to `false` otherwise.
8. WHERE the rule-node collapse option is enabled, THE Lens_Engine SHALL replace each Rule_Node with one edge between the security group and the peer. The option SHALL default to on for the `cloud` lens and off for all other lenses, so that Rule_Nodes do not count against the lens budget.
9. WHEN a Lens_Slice collapses Rule_Nodes, THE Lens_Engine SHALL include the direction, protocol, and port range (`from_port` to `to_port`) of each collapsed rule in the `evidence` text of the resulting edge, so that two rules between the same security group and peer produce two distinct edges.
10. WHEN the Lens_Engine applies a budget and the Lens_Slice exceeds it, THE Lens_Engine SHALL drop all Rule_Nodes, with their incident edges, before it drops any node of another kind.

### Requirement 9: Network slice taxonomy and exposure semantics

**User Story:** As a security engineer, I want exposure derived from real configuration, so that "internet-exposed" means a resource that traffic from the internet can actually reach.

#### Acceptance Criteria

1. THE Registry SHALL declare AWS kinds and relation types for every resource in the Network_Slice, including subnet, ENI, route table, route, internet gateway, NAT gateway, security group, Rule_Node, network ACL, VPC endpoint, VPC peering connection, Elastic IP, load balancer, target group, listener, and transit gateway with its attachments.
2. THE AWS_Collector SHALL continue to emit `aws_account` and `aws_resource` with the existing identity attributes, and SHALL emit each new Network_Slice resource as an `aws_resource` entity distinguished by `resource_type`, except where Requirement 8 or the design defines a dedicated kind for that `resource_type`, in which case THE AWS_Collector SHALL emit that dedicated kind.
3. WHEN the AWS_Collector evaluates exposure for a resource, THE AWS_Collector SHALL set `internet_exposed` to `true` if and only if all of the following hold: (a) the resource has a public address, meaning a public IP, an Elastic IP association, or a load balancer with the internet-facing scheme; (b) at least one attached security group has an ingress Rule_Node whose source is `0.0.0.0/0` or `::/0`; (c) the route table associated with the resource's subnet has a route whose target is an internet gateway; and (d) no network ACL of the subnet denies inbound traffic from `0.0.0.0/0` for the Rule_Node port.
4. IF a resource satisfies conditions (a) and (b) of criterion 3 and the route table association or routes of its subnet could not be determined, THEN THE AWS_Collector SHALL set `internet_exposed` to `partial` and SHALL NOT set it to `true`.
5. WHEN the AWS_Collector derives an exposure relation, THE AWS_Collector SHALL set the Edge_Attributes `evidence` to the list of identifiers of the facts used (for example the security group rule, route, and address) and SHALL set `confidence` to `extracted` when every fact is reported directly by the AWS API, and to `inferred` when at least one fact is derived.
6. IF a network ACL of the subnet denies inbound traffic from `0.0.0.0/0` for the Rule_Node port, THEN THE AWS_Collector SHALL set `internet_exposed` to `partial` for a resource that satisfies conditions (a), (b), and (c) of criterion 3.
7. WHEN the AWS_Collector collects the Network_Slice, THE AWS_Collector SHALL emit `aws_in_vpc` from each subnet to its VPC, `aws_in_subnet` from each ENI to its subnet, `aws_has_eni` from each compute resource to each of its ENIs, `aws_member_of_sg` from each ENI to each of its security groups, `aws_routes_to` from each route table to the target of each of its routes, and `aws_associated_subnet` from each route table to each of its associated subnets.
8. WHEN the AWS_Collector collects an internet gateway or NAT gateway, THE AWS_Collector SHALL emit `aws_attached_igw` from the internet gateway to its VPC, and `aws_nat_in_subnet` from the NAT gateway to its subnet.
9. WHEN the AWS_Collector collects a VPC peering connection whose status is `active`, THE AWS_Collector SHALL emit `aws_peers_with` between the requester VPC and the accepter VPC, and SHALL NOT emit `aws_peers_with` for a peering connection in any other status.
10. WHERE a transit gateway attachment is collected, THE AWS_Collector SHALL emit `aws_tgw_attached` from the attachment to its transit gateway and, for a VPC attachment, from the attachment to the attached VPC.
11. WHERE a load balancer is collected, THE AWS_Collector SHALL emit `aws_lb_forwards_to` from each listener to each target group it forwards to, `aws_lb_listener_of` from each listener to its load balancer, and `aws_targets` from each target group to each registered target.
12. FOR ALL combinations of security group rules, network ACLs, route tables, and addresses of a resource, THE exposure function SHALL return exactly one of `true`, `partial`, or `false`, SHALL return `true` if and only if the four conditions of criterion 3 hold, SHALL return `partial` only under criterion 4, criterion 6, or criterion 13, and SHALL return `false` otherwise, including when the resource has no public address or no ingress Rule_Node open to `0.0.0.0/0` or `::/0`.
13. IF an AWS API call needed to evaluate a Network_Slice resource fails or is denied by permissions, THEN THE AWS_Collector SHALL continue collecting the remaining resources, SHALL set `internet_exposed` to `partial` (never `true`) for each resource whose evaluation depended on the failed call, SHALL set `confidence` to `inferred` on its exposure relations, and SHALL report the failed call and affected resource identifiers in the collection result.
14. IF a relation endpoint named in criteria 7 to 11 was not collected, THEN THE AWS_Collector SHALL NOT emit that relation and SHALL NOT remove or alter other collected entities or relations.

### Requirement 10: Complete AWS taxonomy across six dimensions

**User Story:** As an architect, I want the whole AWS security graph registered now, so that later collectors need no registry or engine change.

#### Acceptance Criteria

1. THE Registry SHALL declare in the Source_Declaration of the `aws` Source the following AWS kinds and relation types for ownership and hierarchy: kinds organization, organizational unit, account, service control policy, and region; and relation types for membership (a child belongs to an organization, organizational unit, or account) and parent (a child points to its parent organization or organizational unit), with each relation type named with the `aws_` prefix.
2. THE Registry SHALL declare in the Source_Declaration of the `aws` Source every AWS kind and relation type for network connectivity and exposure that Requirement 9 lists, with no kind or relation type from Requirement 9 omitted.
3. THE Registry SHALL declare in the Source_Declaration of the `aws` Source the following AWS kinds for compute and workload: EC2 instance, Auto Scaling group, launch template, AMI, ECS cluster, ECS service, ECS task, EKS cluster, EKS node group, Lambda function, and Lambda layer; and relation types, each named with the `aws_` prefix, connecting each of these kinds to its role, network, and image kinds where the AWS resource has such a reference.
4. THE Registry SHALL declare in the Source_Declaration of the `aws` Source the following AWS kinds for identity and permissions: user, group, role, instance profile, managed policy, inline policy, policy statement, trust relationship, and permission boundary; and the relation types `aws_member_of_group`, `aws_attached_policy`, `aws_trusts`, `aws_can_assume`, `aws_can_pass_role`, `aws_has_instance_profile`, `aws_task_role`, `aws_exec_role`, and the derived relation type `aws_can_access`.
5. THE Registry SHALL declare in the Source_Declaration of the `aws` Source the following AWS kinds for data access and storage: S3 bucket, RDS instance, RDS cluster, DynamoDB table, EBS volume, EBS snapshot, EFS file system, KMS key, KMS alias, Secrets Manager secret, and SSM parameter; and the relation types `aws_encrypted_by`, `aws_stores_in`, `aws_reads_from`, `aws_writes_to`, `aws_attached_volume`, and `aws_mounts_fs`.
6. THE Registry SHALL declare in the Source_Declaration of the `aws` Source the following AWS kinds for security controls and monitoring: GuardDuty detector, GuardDuty finding, AWS Config recorder, AWS Config rule, CloudTrail trail, WAF web ACL, Security Hub finding, and Inspector finding; and the relation types `aws_monitors`, `aws_logs_to`, `aws_protects`, and `aws_finding_affects`.
7. THE Registry SHALL declare in the Source_Declaration of the `aws` Source the kinds Route 53 hosted zone and Route 53 record, and the relation types `aws_record_in_zone` and `aws_dns_points_to`.
8. WHERE a target of `aws_dns_points_to` is a resolvable name, THE Registry SHALL map that case to the Generic_Relation `resolves_to` meaning, and WHERE a target is a resource identifier (such as an AWS resource ARN), THE Registry SHALL NOT apply the `resolves_to` meaning; the design table SHALL state, for each target kind of `aws_dns_points_to`, which of the two cases applies.
9. WHEN a resource kind has a scalar attribute that Authorization_Analysis or the Lens_Engine reads, THE Registry SHALL document the attribute name, its value type, and its permitted values or unit in the description of that kind's Kind_Declaration.
10. THE Registry SHALL declare every kind and relation type of this requirement in the Source_Declaration of the `aws` Source, so that zero kind names and zero relation type names of this requirement appear in any global map.
11. FOR ALL AWS relation types declared by this requirement, THE design SHALL include in the table of Requirement 4 one row containing the relation type name, its source kind, its target kind, and a Direction_Rule justification.
12. IF an AWS kind or relation type listed in criteria 1 to 7 is absent from the `aws` Source_Declaration, THEN THE Registry SHALL reject registration of the `aws` Source with an error that names each missing kind or relation type, and SHALL leave previously registered Sources unchanged.

### Requirement 11: Network slice collection

**User Story:** As a security engineer, I want the network slice collected from a read-only AWS connection, so that the graph shows how traffic can reach my resources.

#### Acceptance Criteria

1. WHEN a Collector run starts for an authorized AWS Connection, THE AWS_Collector SHALL collect, for each selected region, VPCs, subnets, ENIs, route tables with routes and associations, internet gateways, NAT gateways, security groups with Rule_Nodes, and Elastic IP addresses.
2. WHERE the AWS_Client supports the call, THE AWS_Collector SHALL also collect network ACLs, VPC endpoints, VPC peering connections, transit gateways with attachments, and load balancers with target groups, listeners, and target health.
3. THE AWS_Collector SHALL depend only on the AWS_Client interface and SHALL import no SDK package and no `net/http`, as it does today.
4. THE AWS_Collector SHALL issue read operations only, and WHEN a new call is added, THE Manifest_Allowlist SHALL list it as a read operation with its host before the AWS_Client issues it.
5. THE Manifest_Allowlist SHALL include `ec2:DescribeSubnets`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeRouteTables`, `ec2:DescribeInternetGateways`, `ec2:DescribeNatGateways`, `ec2:DescribeSecurityGroupRules`, `ec2:DescribeNetworkAcls`, `ec2:DescribeVpcEndpoints`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeAddresses`, `ec2:DescribeTransitGateways`, `ec2:DescribeTransitGatewayAttachments`, `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeListeners`, and `elasticloadbalancing:DescribeTargetHealth`, each classed as read, and the egress host list SHALL include the `elasticloadbalancing.{region}.amazonaws.com` host pattern.
6. THE Manifest_Allowlist and the existing role templates SHALL keep working without a permission change, because the templates attach `ReadOnlyAccess` and `SecurityAudit`, and the manifest and template tests SHALL fail if any of the 16 operations in criterion 5 is missing, is not classed as read, or is not covered by the attached policies.
7. WHEN the AWS_Collector reads a paginated API, THE AWS_Client SHALL read every page until it has read 10,000 items for that resource type in that region, and WHEN the cap is reached, THE AWS_Collector SHALL set `truncated` to `true` on the account entity, record the resource type in the Run_Status, and SHALL NOT retire entities of that type.
8. IF one resource type fails in one region, THEN THE AWS_Collector SHALL continue with the other types and regions, report the failed types through `collectors.PartialError`, and keep previously stored entities and relations of the failed types unchanged.
9. IF AWS returns access denied for one resource type in one region, THEN THE AWS_Collector SHALL record `<type>@<region>` as a denied scope in the Run_Status, continue with the other types and regions, and keep previously stored entities and relations of that type in that region unchanged.
10. IF AWS rejects the Connection credentials, THEN THE AWS_Collector SHALL end the run without collecting further resource types, record an authorization error in the Run_Status, and keep all previously stored entities and relations unchanged, as it does today.
11. IF every resource type fails in every selected region, THEN THE AWS_Collector SHALL return an error and SHALL NOT emit an observation.
12. WHEN a Collector run completes without a failure for a resource type, THE Graph_Engine SHALL retire the entities and relations of that type that the run no longer observes.
13. WHEN a Collector run completes with a failure for a resource type, THE Graph_Engine SHALL keep the entities and relations of that type.
14. THE AWS_Collector SHALL emit a Batch in which every relation endpoint names an entity in the same Batch or an entity already in the graph, so that `Ingest().Apply` accepts the Batch.
15. THE AWS_Collector SHALL set `canonical_key` through `canonical.Key` on every `aws_resource` that has an ARN, and SHALL construct an ARN for each resource type that the API returns without one.

### Requirement 12: Roadmap for registered-only categories

**User Story:** As a project owner, I want to see what is built and what is only registered, so that I can plan the next collectors.

#### Acceptance Criteria

1. THE Graph_README SHALL contain a Roadmap table with exactly one row for each category of Requirement 10, and each row SHALL show a status of exactly `implemented` or `registered-only`.
2. THE Roadmap SHALL mark each collected Network_Slice resource category as `implemented` and every other category of Requirement 10 as `registered-only`, and each `registered-only` row SHALL list at least one AWS read operation that the future collector for that category needs.
3. WHEN a requested Lens_Slice or MCP answer depends on one or more categories marked `registered-only`, THE Bellud SHALL include in the answer a `missing_data` list containing the name of each such category exactly once.
4. WHEN a requested Lens_Slice or MCP answer depends only on categories marked `implemented`, THE Bellud SHALL return the answer with a `missing_data` list that is present and empty.
5. THE Lens_Engine SHALL determine the contents of `missing_data` only from the Roadmap status held in the Registry, and SHALL produce the same `missing_data` for two questions that depend on the same categories regardless of question wording.
6. THE Registry SHALL hold exactly one collected-or-not status per AWS category, and THE Roadmap table and `missing_data` SHALL both read that status from the Registry, so that a status change in the Registry changes both outputs.
7. IF the Registry has no status for a category that a Lens_Slice or MCP answer depends on, THEN THE Lens_Engine SHALL treat the category as `registered-only`, include it in `missing_data`, and return the rest of the answer unchanged.

### Requirement 13: Attack-path and blast-radius across services

**User Story:** As a security engineer, I want path and blast-radius answers to follow the new network edges, so that I can see what an attacker reaches from a compromised resource.

#### Acceptance Criteria

1. WHEN the Graph_Engine computes `Impact` for a relation type added by the Network_Slice, THE Graph_Engine SHALL traverse that relation in the direction given by its registered Impact_Direction and SHALL NOT traverse it in the opposite direction.
2. WHEN the `blast-radius` Lens is requested for an EC2 instance, THE Lens_Engine SHALL return every resource reachable from the instance through ENI, security group, subnet, route table, and rule relations present in the graph, within the traversal depth limit of 6 hops.
3. WHEN the `blast-radius` Lens is requested while Authorization_Analysis is not built, THE Lens_Engine SHALL list each category that depends on `aws_can_access` in `missing_data`.
4. WHEN the `attack-path` Lens is requested, THE Lens_Engine SHALL start from each entity with `internet_exposed` equal to `true`, follow Network_Slice relations, and return each path from a start entity to a target entity, with a maximum path length of 6 hops.
5. IF no entity has `internet_exposed` equal to `true`, THEN THE Lens_Engine SHALL return an empty path list and SHALL include in `missing_data` an entry stating that no internet-exposed entity was found.
6. WHEN a path contains at least one hop whose relation has `confidence` equal to `inferred` or whose relation type is `likely_same_as`, THE Lens_Engine SHALL tag that hop `inferred` and SHALL tag the whole path `inferred`.
7. THE Lens_Engine SHALL include every AWS kind that the Network_Slice adds in the `cloud` Lens kind list.
8. WHEN the question "which resources are exposed through a misconfigured security group" is asked, THE Lens_Engine SHALL return the entities that have an attached security group with at least one ingress Rule_Node whose `internet_open` equals `true`.
9. WHEN the question "can an internet-facing resource reach an RDS database" is asked, THE Lens_Engine SHALL return the paths from entities with `internet_exposed` equal to `true` to RDS instances, and SHALL list in `missing_data` each of the following that is not collected: RDS instances, ENIs, security groups, and network path elements.
10. WHEN a question requires IAM access (for example "which S3 buckets can an IAM role access", "which Lambda functions can access production secrets", or "blast radius of compromising an identity"), THE Lens_Engine SHALL return the graph structure that exists and SHALL list each missing category in `missing_data`, so that the result is never an empty result without a `missing_data` entry.
11. WHILE the Lens_Engine budgets a slice that exceeds the node budget, THE Lens_Engine SHALL retain the lens root and all entities on each reported path before any other node, and SHALL drop only other nodes.

### Requirement 14: Edge confidence in lenses and MCP

**User Story:** As an AI agent, I want each edge tagged with its true confidence, so that I can say how sure an answer is.

#### Acceptance Criteria

1. WHEN a relation has the `confidence` Edge_Attribute with the value `extracted` or `inferred`, THE Lens_Engine SHALL set the confidence of the corresponding Lens_Slice edge to that value.
2. WHEN a relation of a registered relation type has no `confidence` Edge_Attribute, THE Lens_Engine SHALL set the confidence of the corresponding Lens_Slice edge to the default confidence of its Relation_Declaration.
3. WHEN a relation has a relation type that is not registered, THE Lens_Engine SHALL set the confidence of the corresponding Lens_Slice edge to `extracted`, as it does today.
4. IF a relation read from stored data has a `confidence` Edge_Attribute whose value is neither `extracted` nor `inferred`, THEN THE Lens_Engine SHALL treat the attribute as absent, apply the default confidence of criterion 2 or 3, and still return the Lens_Slice without error.
5. WHERE a relation has the `evidence` Edge_Attribute, THE Lens_Engine SHALL carry its text in the corresponding Lens_Slice edge as `evidence`.
6. WHERE a Lens_Slice edge or path hop has `evidence`, THE MCP_Server SHALL include `evidence` in every edge and every path hop that an MCP tool returns for it.
7. WHEN the `evidence` text of a relation is longer than 512 bytes, THE Lens_Engine SHALL truncate the text in the Lens_Slice edge to at most 512 bytes, without splitting a multi-byte UTF-8 character, and SHALL leave text of 512 bytes or fewer unchanged.
8. WHEN the Lens_Slice edge schema gains `evidence` and `observed_at`, THE Bellud SHALL expose both as optional fields, so that a Lens_Slice edge without either field remains valid, AND THE protocol and schema definitions SHALL be regenerated with the steps in the Graph_README.
9. FOR ALL paths returned by the Lens_Engine or an MCP tool, THE path confidence SHALL equal the weakest confidence among the hop confidences, using the order `inferred` < `extracted` (weakest to strongest).

### Requirement 15: Read-only guarantees and documentation

**User Story:** As a developer, I want the docs to describe the registry and the new collector steps, so that I can add a source without reading the engine.

#### Acceptance Criteria

1. THE AWS_Collector SHALL perform read operations only against AWS, and SHALL issue zero create, update, delete, or tag-modification calls.
2. WHEN the arch test suite runs against the AWS_Collector, THE arch test SHALL pass with zero failures and zero newly skipped tests.
3. THE Graph_README SHALL contain one dedicated section for each of the following topics: the per-source registry, the naming convention, the Direction_Rule, the Edge_Attributes, the Reified_Node rule, and the Roadmap.
4. THE Graph_README "Add a new Collector" section SHALL contain a registry step with four ordered sub-steps: (1) declare kinds and relation types in the Source package, (2) register the Source_Declaration, (3) run the Registry_Check tests and confirm they pass, (4) justify each declared relation direction with the Direction_Rule.
5. THE Graph_README SHALL remove its statement that relations have no attributes, and SHALL state the Edge_Attributes rules in its place.
6. THE Graph_README SHALL state that the Edge_Attributes rules supersede Requirement 2.7 of `unified-security-graph` for the fixed set of attributes only, and that Requirement 2.7 continues to apply to all other relation attributes.
7. THE `unified-security-graph` requirements document and design document SHALL each contain one note that names this spec and states that Requirement 2.7 is amended by it.
8. THE Graph_README SHALL state that routes under `/api/experimental/graph/` may change or be removed in any release without compatibility guarantees or deprecation notice.

### Requirement 16: Tests

**User Story:** As a maintainer, I want automated tests of the registry, codec, directions, and collector output, so that regressions are caught without live AWS.

#### Acceptance Criteria

1. THE test suite SHALL include property tests, each run with at least 100 generated cases, that assert the merged registry is identical for every ordering of the same inputs and that each conflict class of Requirement 2 produces its specified rejection.
2. THE test suite SHALL include a property test, run with at least 100 generated cases, that asserts the merged registry returns a valid direction and a default confidence of `extracted` or `inferred` for every registered relation type.
3. THE test suite SHALL include a golden-vector test that asserts the exact encoded Entity_ID of one sample entity for every existing kind and the pinned direction of every existing relation type, and the test SHALL fail if any value differs from the stored vector.
4. THE test suite SHALL include property tests, each run with at least 100 generated cases, for Edge_Attribute validation that assert acceptance of every name in the accepted set, rejection of every name outside it, acceptance of `extracted` and `inferred` and rejection of any other confidence value, acceptance of evidence at 512 bytes and rejection at 513 bytes, and acceptance and rejection of timestamps according to RFC 3339.
5. THE test suite SHALL include a codec round-trip property test, run with at least 100 generated cases, that asserts decode(encode(x)) equals x both with and without Edge_Attributes, a test that asserts previous-format bytes decode with empty Edge_Attributes, and the Legacy_Data fixture test.
6. THE test suite SHALL update each of the existing tests that assert relations take no attributes (`plan_test.go`, `reject_prop_test.go`, `logs_metrics_prop_test.go`, `facade/graph_test.go`, `collectors/e2e_test.go`, `iac_test.go`, `lens/confidence_property_test.go`) so that it asserts the new attribute rule and passes.
7. THE test suite SHALL include a property test, run with at least 100 generated cases, that asserts Rule_Node identity is identical across repeated derivations of the same rule and differs for any two distinct rules of one security group.
8. THE test suite SHALL include a property test, run with at least 100 generated cases, that asserts the exposure function of Requirement 9 criterion 12 returns the specified result for every generated input, including the boundary inputs that criterion defines.
9. THE test suite SHALL include a collector test with a fake AWS_Client that asserts the emitted Batch passes `Ingest().Apply` without error, that an entity absent from a later collection is retired, that a type whose listing fails keeps its previously collected entities and is not retired, and that reaching each cap sets `truncated` and does not set it when the count is below the cap.
10. THE test suite SHALL include a test of the manifest and role templates that fails if any new operation is not classed read-only or is not covered by the `ReadOnlyAccess` and `SecurityAudit` policies that the role templates attach.
11. THE test suite SHALL include a lens test that asserts, after Rule_Node collapsing and after budgeting, every edge in the output has both endpoints present in the output node set.
12. THE test suite SHALL pass when run with no network access, no running services, and no cloud credentials, and every running service SHALL have the same state and configuration after the run as before it.
13. WHEN implementation finishes, THE Final_Checkpoint SHALL run `go build ./...`, `go vet ./...`, and `go test ./...` for Bellud, `bun typecheck` in each touched package, and `bun run check` from the repository root, and SHALL report success only when every command exits with status 0.
14. IF any Final_Checkpoint command exits with a non-zero status, THEN THE Final_Checkpoint SHALL report failure, name each failing command with its exit status, and SHALL NOT report success.
