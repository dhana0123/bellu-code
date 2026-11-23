# Requirements Document

## Introduction

This feature reproduces the online retrieval stage of SEEK (Gadey et al., arXiv 2610.14968, "SEEK: Agentic Knowledge Graph Retrieval for Secure Code Generation") inside bellucode. It adds a new subagent type, `seek`, to bellucode core. The `seek` subagent runs on the parent session's LLM, predicts likely CWEs for a task, calls a deterministic `bellu-graph` MCP tool served by bellud to scope and rank CVE evidence from the BSKG (Bellu security knowledge graph), selects the sound evidence, and returns a compact security context to the main agent.

Scope decisions: no embeddings, no curated fix examples, no language restriction. Ranking uses existing BSKG signals. The LLM never writes queries. The BSKG API key stays inside bellud. This feature may depend on the BSKG client, `/v1/schema`, and weakness parents/children tasks (5.30-5.36) of the `bellu-three-graph-security-intelligence` spec, or include the minimal parts it needs.

## Glossary

- **Core**: The bellucode core package (`packages/core`) that registers agents and tools.
- **Seek_Agent**: The `seek` subagent type registered in Core, which acts as both planner and selector.
- **Main_Agent**: The `build` primary agent that spawns subagents with the `subagent` tool.
- **Bellud**: The Go daemon in `services/bellud`.
- **Seek_Tool**: The `bellu-graph` MCP tool `seek_retrieve`, implemented in Bellud.
- **BSKG**: The Bellu security knowledge graph REST API, reached with a Bearer key.
- **BSKG_Client**: The Bellud component that calls the BSKG.
- **Plan**: The JSON object `{language, reasoning, weaknesses:[{cwe_id, root_cause, code_snippet}]}` produced by the Seek_Agent.
- **Retrieval_Unit**: One element of `weaknesses` in a Plan.
- **Scope**: The set of CWEs consisting of a predicted CWE and its graph neighbors selected by the scoping rules.
- **Candidate**: A vulnerability (CVE) attached by an `EXAMPLE_OF` edge to a CWE in the Scope.
- **Top_K**: The total Candidate budget across all Retrieval_Units. The default is 4.
- **Relevance_Score**: The deterministic ranking score of a Candidate.
- **Security_Context**: The compact output returned to the Main_Agent.
- **Seek_Flag**: Removed. The `seek_planner` feature flag no longer exists; the `seek` agent is always registered (see Requirements 11 and 13).
- **Seek_Usage_Rule**: The `PROMPT_SEEK_USAGE` text added to the Build agent's context as a separate system part (via a `ctx.session.hook("context", ...)`) that tells the Main_Agent when and how to call `seek`.
- **Round**: One planner-then-selection pass.
- **Protocol**: The public bellucode protocol package (`packages/protocol`).
- **Server**: The bellucode server package that serves the Protocol `HttpApi`.

## Requirements

### Requirement 1: Seek subagent registration

**User Story:** As a developer, I want a `seek` subagent available to the main agent, so that security retrieval runs through the existing subagent mechanism.

#### Acceptance Criteria

1. THE Core SHALL always register an agent with id `seek`, mode `subagent`, and a description of 1 to 200 characters that states that the agent retrieves CVE-grounded security context for a task.
2. ~~WHERE the Seek_Flag is disabled, THE Core SHALL omit the `seek` agent from the agent registry and from the agent list returned to clients.~~ Removed: the `seek_planner` flag was removed, so `seek` is registered unconditionally (see criterion 1).
3. THE Core SHALL register the `seek` agent in `packages/core/src/plugin/agent.ts` with `ctx.agent.transform` and `Agent.ID.make("seek")`.
4. THE Seek_Agent SHALL use permission rules that deny `*`, allow only the Seek_Tool, and deny `subagent`, so that every other tool call by the Seek_Agent is denied without prompting the user.
5. WHEN the Main_Agent invokes the `subagent` tool with agent `seek` and no model, THE Core SHALL run the child session with the same provider and model as the parent session.
6. THE Core SHALL include `seek` and its description in the `subagent` tool description shown to the Main_Agent, so that the Main_Agent can choose it for security-sensitive coding or review tasks.
7. ~~IF the Main_Agent invokes the `subagent` tool with agent `seek` while the Seek_Flag is disabled, THEN THE Core SHALL return an error indicating that the agent does not exist and SHALL NOT create a child session.~~ Removed: no flag exists, so `seek` is always available.

### Requirement 2: Planner prompt contract

**User Story:** As a developer, I want the planner to produce a strict, structured prediction, so that downstream retrieval is deterministic.

#### Acceptance Criteria

1. THE Seek_Agent system prompt SHALL instruct the model to state the programming language of the task as a non-empty string, using `unknown` when the language cannot be determined, and to predict CWEs that are distinct from one another (no repeated `cwe_id`), identified by a specific weakness identifier (not a CWE Category or View), and not marked Deprecated in the BSKG.
2. THE Seek_Agent system prompt SHALL instruct the model to return `"weaknesses": []` when it cannot predict any CWE with confidence, and SHALL instruct the model to predict only distinct risks, meaning no CWE that is a broader or narrower variant of an already predicted CWE, and to predict at most 20 CWEs as a safety cap.
3. THE Seek_Agent system prompt SHALL require, for each Retrieval_Unit, a `cwe_id` matching `^CWE-[0-9]{1,5}$`, a `root_cause` of 1 to 1000 characters that describes the weakness in the specific task rather than the generic CWE definition, and a `code_snippet` of 1 to 2000 characters that shows the vulnerable code shape.
4. THE Seek_Agent system prompt SHALL require the model to output a single JSON object with exactly the fields `language`, `reasoning`, and `weaknesses`, and no text outside that object.
5. THE Seek_Agent system prompt SHALL NOT contain a language allowlist or any instruction that refuses or skips a task because of its programming language.
6. WHERE the agent configuration exposes a temperature setting, THE Core SHALL run the `seek` agent with the lowest temperature value that setting accepts. The bellucode `Agent.Info` currently has no temperature setting, so this criterion has no effect until such a setting exists.
7. WHEN the Seek_Agent model response is not a JSON object that satisfies criterion 4, THE Seek_Agent SHALL NOT call the Seek_Tool with it and SHALL request a corrected Plan within the Round limit of Requirement 7.
8. WHEN the Seek_Agent produces a Plan whose `weaknesses` list is empty, THE Seek_Agent SHALL NOT call the Seek_Tool and SHALL return a result stating that no augmentation applies.

### Requirement 3: Input validation

**User Story:** As a security engineer, I want every Plan validated before use, so that malformed or hostile model output cannot reach the graph.

#### Acceptance Criteria

1. WHEN the Seek_Tool receives a Plan, THE Seek_Tool SHALL validate it against a JSON schema before making any BSKG_Client call, and SHALL make no BSKG_Client call for a Plan that fails validation.
2. IF a Plan is not a JSON object, contains a field outside `language`, `reasoning`, and `weaknesses`, lacks a required field, or has a field of the wrong type (`language`, `reasoning`, `cwe_id`, `root_cause`, and `code_snippet` must be strings; `weaknesses` must be an array of objects with exactly the fields `cwe_id`, `root_cause`, and `code_snippet`), THEN THE Seek_Tool SHALL return an `invalid_plan` error that names the offending field path, return no Candidates, and leave graph data unchanged.
3. IF `language` is empty or exceeds 64 characters, `reasoning` exceeds 4000 characters, `root_cause` is empty or exceeds 1000 characters, `code_snippet` is empty or exceeds 2000 characters, or `weaknesses` has more than 20 submitted items (counted before any per-unit rejection under criteria 4 and 5), THEN THE Seek_Tool SHALL return an `invalid_plan` error that names the offending field path, where length is counted in Unicode code points.
4. IF a `cwe_id` does not match `^CWE-[0-9]{1,5}$`, THEN THE Seek_Tool SHALL reject that Retrieval_Unit, report its position in `weaknesses` and the reason in the result, and continue processing the remaining valid Retrieval_Units.
5. IF a Plan contains duplicate `cwe_id` values (compared as exact strings), THEN THE Seek_Tool SHALL keep the first occurrence in Plan order and report the position of each dropped duplicate in the result.
6. WHEN a Plan passes validation with an empty `weaknesses` list, THE Seek_Tool SHALL return a result with zero Retrieval_Units and zero Candidates, SHALL make no BSKG_Client call, and SHALL NOT return an error.
7. THE Seek_Tool SHALL pass validated values to the BSKG_Client only as typed parameters and SHALL NOT interpolate model text into URLs, queries, or shell commands.
8. FOR ALL valid Plans, serializing then parsing then serializing SHALL produce a Plan with identical field values and identical `weaknesses` order (round-trip property).

### Requirement 4: MCP tool contract

**User Story:** As a developer, I want a single, well-defined tool for retrieval, so that the subagent has one narrow capability.

#### Acceptance Criteria

1. THE Bellud built-in `bellu-graph` MCP server SHALL expose a tool named `seek_retrieve`.
2. THE Seek_Tool SHALL accept `plan` (a Plan, required) and `top_k` (optional integer from 1 to 10 inclusive, default 4) and SHALL accept no other input parameters.
3. WHEN validation succeeds and the BSKG is available, THE Seek_Tool SHALL return an overall status `ok` and, for each accepted Retrieval_Unit in Plan order, the following: the predicted CWE id, the Scope CWE ids, a unit status, and the Candidates in descending Relevance_Score order. Each Candidate SHALL carry its CVE id and numeric Relevance_Score. The unit status SHALL be one of `ok`, `no_candidates`, `unknown_cwe`, or `unavailable`.
4. WHEN validation succeeds and a Plan has an empty `weaknesses` list, THE Seek_Tool SHALL return overall status `ok` with no Retrieval_Unit results and SHALL make no BSKG call.
5. IF `top_k` is not an integer or is outside 1 to 10, THEN THE Seek_Tool SHALL return an `invalid_plan` error that names `top_k`, SHALL make no BSKG call, and SHALL return no Candidates.
6. THE Seek_Tool SHALL be read-only: it SHALL issue only read requests to the BSKG and SHALL NOT create, update, or delete BSKG data or Bellud data.
7. WHEN Bellud registers its tools, THE Bellud SHALL register the Seek_Tool only if both the BSKG base URL and the BSKG API key are configured with non-empty values, and SHALL otherwise omit `seek_retrieve` from the `bellu-graph` tool list.

### Requirement 5: Graph scoping

**User Story:** As a developer, I want scoping to follow fixed hierarchy rules, so that retrieved evidence stays on topic.

#### Acceptance Criteria

1. WHEN a Retrieval_Unit names a CWE that exists in the BSKG, THE Seek_Tool SHALL set the Scope to that CWE plus its direct children, where a child is a CWE that has a `CHILD_OF` edge pointing to the predicted CWE.
2. IF no CWE in the Scope has an attached Candidate after the direct-children Scope is built, THEN THE Seek_Tool SHALL expand the Scope exactly once to include the grandchildren of the predicted CWE, where a grandchild is a CWE that has a `CHILD_OF` edge to a direct child.
3. THE Seek_Tool SHALL exclude the parents, grandparents, and siblings of the predicted CWE from the Scope, except where a CWE also qualifies as a child or grandchild of the predicted CWE under criteria 1 and 2.
4. IF the BSKG reports that a predicted CWE does not exist, THEN THE Seek_Tool SHALL mark that Retrieval_Unit `unknown_cwe`, return an empty Scope and no Candidates for it, and continue processing the other Retrieval_Units. A BSKG failure, as opposed to a not-found response, is handled under Requirement 10.
5. THE Seek_Tool SHALL perform scoping without any LLM call.
6. THE Seek_Tool SHALL include each CWE at most once in a Scope and SHALL limit a Scope to a maximum of 50 CWEs, keeping the predicted CWE first and then the remaining CWEs in ascending numeric CWE id order.
7. WHEN the Seek_Tool returns a Retrieval_Unit result, THE Seek_Tool SHALL include the Scope CWE ids and an indication of whether the grandchild expansion was applied.
8. FOR ALL Retrieval_Units, THE Seek_Tool SHALL return a Scope whose deepest CWE is at most 1 level below the predicted CWE when no expansion occurred, and at most 2 levels below it when the expansion occurred.

### Requirement 6: Retrieval and ranking without embeddings

**User Story:** As a developer, I want ranking from signals already in the BSKG, so that retrieval works without embeddings or curated fixes.

#### Acceptance Criteria

1. WHEN a Retrieval_Unit has a Scope, THE Seek_Tool SHALL select Candidates from vulnerabilities attached by `EXAMPLE_OF` to Scope CWEs, fetching at most 50 vulnerabilities per Scope CWE and counting a vulnerability attached to several Retrieval_Units only in the first unit in Plan order.
2. WHEN the Seek_Tool scores a Candidate, THE Seek_Tool SHALL compute the Relevance_Score as a value from 0.0 to 1.0 using these normalized signals: identifier match (1 if at least one code identifier token of 3 or more characters appears in both the CVE description and the `code_snippet` or `root_cause`, otherwise 0), lexical overlap (Jaccard similarity of the lowercase alphanumeric token sets of 3 or more characters from `root_cause` and the CVE description), CISA KEV membership (1 or 0), EPSS (0.0 to 1.0), CVSS base score divided by 10, and presence of a fix commit (1 or 0).
3. THE Seek_Tool SHALL weight the signals as identifier match 0.30, lexical overlap 0.25, CISA KEV 0.15, EPSS 0.10, CVSS 0.10, and fix commit 0.10, SHALL treat a signal missing from the BSKG as 0, and SHALL use no randomness, so that identical inputs and identical BSKG data produce identical scores and output order.
4. WHEN two Candidates in the same Retrieval_Unit have Relevance_Scores equal when rounded to 6 decimal places, THE Seek_Tool SHALL order them by ascending CVE id.
5. WHEN the Seek_Tool allocates the Top_K budget, THE Seek_Tool SHALL give each Retrieval_Unit with Candidates floor(Top_K / unit count) slots, assign remaining slots one each in Plan order, give 1 slot each to the first Top_K units in Plan order when the unit count exceeds Top_K, and reassign slots a unit cannot fill to units that still have Candidates in Plan order.
6. THE Seek_Tool SHALL drop Candidates whose Relevance_Score is below the minimum-relevance cutoff, which is configured in Bellud with a default of 0.20 and an allowed range of 0.0 to 1.0.
7. IF every Candidate of a Retrieval_Unit is dropped by the cutoff or the unit has no Candidates, THEN THE Seek_Tool SHALL return an empty Candidate list and the status `no_candidates` for that unit while still returning the other units' results.
8. WHERE a Candidate has a fix commit and repository in the BSKG, THE Seek_Tool SHALL include both fields in that Candidate and otherwise SHALL omit them.
9. THE Seek_Tool SHALL return at most Top_K Candidates in total.
10. THE Seek_Tool SHALL NOT use embeddings or curated fix examples.
11. FOR ALL inputs, THE Seek_Tool SHALL return identical Candidates in identical order when the same Retrieval_Units are processed in the same order against identical BSKG data (determinism property).
12. THE Seek_Tool SHALL fetch `/v1/vulnerabilities/{id}` details for at most 120 vulnerabilities per Seek_Tool run, selecting them by ordering all Candidate references by CVSS v3 base score descending and then by CVE id ascending, and taking the first 120.

### Requirement 7: Selection loop

**User Story:** As a developer, I want the model to validate predictions and candidates, so that weak evidence does not reach the answer.

#### Acceptance Criteria

1. WHEN the Seek_Tool returns a result for a Round, THE Seek_Agent SHALL record, for each Retrieval_Unit that has at least one Candidate, a verdict of `sound` or `unsound` with a reason of 1 to 200 characters, where a prediction is `sound` only if its `root_cause` describes a weakness present in the task and matches the definition of its CWE.
2. WHEN a Retrieval_Unit is judged `sound`, THE Seek_Agent SHALL record, for each Candidate of that unit, a decision of `keep` or `drop` with a reason of 1 to 200 characters, and SHALL record `keep` only if the CVE description shows the same weakness pattern as the `root_cause`.
3. IF the Seek_Agent judges a Retrieval_Unit `unsound`, or the Seek_Tool marks it `unknown_cwe` or returns no Candidates for it, AND fewer than 2 Rounds have run, THEN THE Seek_Agent SHALL produce feedback naming a replacement CWE id that matches `^CWE-[0-9]{1,5}$` and was not predicted earlier in the invocation, and SHALL run exactly one re-planning Round whose Plan replaces only the affected units and keeps the Candidates already retained.
4. THE Seek_Agent system prompt SHALL limit the Seek_Agent to at most 2 Rounds per invocation, and THE Core SHALL configure the `seek` agent with a step limit of 4 as a backstop to that prompt-enforced limit. THE Seek_Agent SHALL count each Seek_Tool call made to correct an `invalid_plan` error as a Round, and SHALL treat any Retrieval_Unit still `unsound` after the second Round as having no retained Candidates.
5. IF no Candidate is retained after the final Round, THEN THE Seek_Agent SHALL return a result stating that no augmentation applies and SHALL include no CVE id, fix commit, or CWE-derived guidance.
6. THE Seek_Agent SHALL retain only Candidates whose CVE id appears in a Seek_Tool output of the current invocation, and SHALL take every CVE id, fix commit, and CWE name in its response verbatim from that output without inventing any.

### Requirement 8: Security context output

**User Story:** As a main-agent user, I want a compact security context, so that the answer or generated code reflects real vulnerability patterns.

#### Acceptance Criteria

1. WHEN at least one Candidate is retained after the final Round, THE Seek_Agent SHALL return a Security_Context containing, for each retained Candidate, the CVE id, the CWE id and name, and fixing guidance, and SHALL include the fix commit and repository only if the Seek_Tool output contains them for that Candidate.
2. THE Seek_Agent SHALL write the fixing guidance for each retained Candidate as 1 to 3 sentences of at most 500 characters, derived only from that Candidate's CVE description and fix data in the Seek_Tool output and from the selected CWE name, and SHALL NOT include a CVE id, fix commit, or CWE name that is absent from the Seek_Tool output.
3. THE Seek_Agent SHALL limit the Security_Context to 4000 characters when the `top_k` used in the final Seek_Tool call is 4 or less, and to 6000 characters when that `top_k` is greater than 4.
4. THE Seek_Agent SHALL return the Security_Context as the text of its final response to the Main_Agent, with no tool call after it.
5. THE Seek_Agent SHALL state in the Security_Context the `cwe_id` of every Retrieval_Unit in the final Round's Plan as predicted, and the distinct CWE ids of the retained Candidates as retained.
6. IF the assembled Security_Context exceeds the character limit in criterion 3, THEN THE Seek_Agent SHALL omit whole retained Candidates in ascending Relevance_Score order, lowest first, until the Security_Context is within the limit, and SHALL state the number of Candidates omitted.

### Requirement 9: BSKG access and secrets

**User Story:** As a security engineer, I want the BSKG key isolated in bellud, so that the model and the client never see it.

#### Acceptance Criteria

1. WHEN Bellud starts, THE BSKG_Client SHALL read the BSKG base URL and API key from Bellud configuration or environment variables, and an environment variable SHALL take precedence over the configuration value when both are set.
2. IF the base URL or the API key is absent, empty, or whitespace-only, or the base URL is not an absolute `https` URL (or an `http` URL whose host is `localhost` or a loopback address), THEN THE BSKG_Client SHALL treat the BSKG as unconfigured and SHALL make zero BSKG network requests.
3. WHEN THE BSKG_Client sends a request, THE BSKG_Client SHALL send the key only in the `Authorization: Bearer` header and only to the host of the configured BSKG base URL. THE BSKG_Client SHALL NOT place the key in a URL, query string, request body, or any other header, and SHALL NOT follow a redirect to a different host.
4. THE Bellud SHALL exclude the BSKG key value from tool results, logs, error messages, the agent configuration, and any text sent to the model.
5. THE BSKG_Client SHALL request only `/v1/weaknesses/{cweID}`, `/v1/weaknesses/{cweID}/vulnerabilities`, `/v1/vulnerabilities/{id}`, `/v1/graph/neighborhood` (used with `relTypes=CHILD_OF` to find weakness children), and `/v1/status`, and SHALL NOT request any other path.
6. IF a single BSKG request does not complete within 10 seconds, THEN THE BSKG_Client SHALL abort that request and report the BSKG as timed out to the Seek_Tool.
7. IF the total Seek_Tool run time reaches 30 seconds, THEN THE Seek_Tool SHALL abort all in-flight BSKG requests, return the results of Retrieval_Units already completed, and mark each unfinished Retrieval_Unit `unavailable`.
8. WHEN THE BSKG_Client builds a request path, THE BSKG_Client SHALL percent-encode every path segment so that `/`, `?`, `#`, `%`, and whitespace in a value are sent as literal data and cannot change the path or add a query string.

### Requirement 10: Failure handling

**User Story:** As a developer, I want the feature to fail closed and quietly, so that the main agent keeps working when the BSKG is unavailable.

#### Acceptance Criteria

1. IF the BSKG is unconfigured, unreachable, does not respond within the 10-second request timeout, or returns an authentication error, THEN THE Seek_Tool SHALL return a result with status `cve_unavailable`, zero Candidates, and no BSKG key, and SHALL NOT modify graph data.
2. IF the total Seek_Tool deadline of 30 seconds elapses before all Retrieval_Units finish, THEN THE Seek_Tool SHALL return the results of completed units, mark each unfinished unit `unavailable`, and return zero Candidates for those units.
3. WHEN the Seek_Tool returns `cve_unavailable`, THE Seek_Agent SHALL return a final response stating that no augmentation applies, with no CVE content, and SHALL make no further Seek_Tool calls in that invocation.
4. IF the Seek_Tool returns `invalid_plan`, THEN THE Seek_Agent SHALL correct the fields named in the error and call the Seek_Tool again, provided the invocation has used fewer than 2 Rounds.
5. IF the BSKG fails for one Retrieval_Unit while other units succeed, THEN THE Seek_Tool SHALL return the successful units' Candidates, mark the failed unit `unavailable` with zero Candidates for it, and keep the overall status distinct from `cve_unavailable`.
6. IF the Seek_Agent has not produced a Plan accepted by the Seek_Tool after 2 Rounds, THEN THE Seek_Agent SHALL return a final response stating that no augmentation applies, with no CVE content.
7. WHEN the Main_Agent receives a Seek_Agent response stating that no augmentation applies, THE Main_Agent SHALL receive it as ordinary subagent text, without a tool error, and SHALL continue the original task in the same session.
8. IF the Seek_Tool returns `cve_unavailable` or marks a unit `unavailable`, THEN THE Seek_Tool SHALL include an error indication stating the failure category (unconfigured, unreachable, timeout, or authentication), and SHALL NOT include the BSKG base URL credentials, the API key, or raw upstream response bodies.

### Requirement 11: Conventions (feature flag removed)

**User Story:** As a maintainer, I want the feature consistent with repo conventions, so that it can ship incrementally.

#### Acceptance Criteria

1. ~~THE Seek_Flag SHALL be defined with the key `seek_planner` and a non-empty description in `packages/schema/src/config/flag.ts`, and THE Core SHALL read it only through `Flag.enabled("seek_planner")` from `@bellucode/core/flag`.~~ Removed: the `seek_planner` flag was deleted.
2. ~~THE Seek_Flag SHALL default to enabled in local and dev builds and disabled in release builds, and SHALL be overridable by `experimental.seek_planner` in config or by `seek_planner` or `-seek_planner` in `BELLUCODE_FLAGS`, where a `-seek_planner` opt-out or `experimental.seek_planner: false` takes precedence over `all` and `experimental.all_flags`.~~ Removed: the `seek_planner` flag was deleted.
3. THE Core SHALL place any new HTTP route under `/api/experimental/<group>/...` with OpenAPI identifier `experimental.<group>.<method>`, any new SDK method under `client.experimental.<group>.<method>`, any new config field under `config.experimental.*`, and any new plugin hook under the name `experimental.*`, as specified in `/home/ubuntu/bellucode/AGENTS.md`.
4. THE Core SHALL pass `bun typecheck` from `packages/core` with zero errors for all new code, and THE new code SHALL contain no `any` type, no aliased imports, and no star imports, as required by the style guide in `/home/ubuntu/bellucode/AGENTS.md`.
5. IF a change alters the public Protocol or Server `HttpApi`, THEN THE change SHALL include client files regenerated by `bun run generate` from `packages/client`, and SHALL NOT include hand edits to generated client files.
6. ~~WHERE the Seek_Flag is disabled, THE Core SHALL omit `seek` from the Main_Agent's subagent descriptions, and THE Bellud SHALL return the same names, input schemas, and results for every existing `bellu-graph` tool as when the feature is absent.~~ Removed: no flag exists.
7. ~~WHERE the Seek_Flag is disabled, THE Core SHALL leave Main_Agent behavior unchanged, so that the Main_Agent's tool list, subagent list, and permission rules are identical to those of a build without this feature.~~ Removed: no flag exists.

### Requirement 12: Tests

**User Story:** As a maintainer, I want automated tests for each deterministic behavior, so that regressions are caught.

#### Acceptance Criteria

1. THE Bellud test suite SHALL use a fake BSKG server to assert, with at least one passing and one failing case each, Plan validation (Requirement 3 rules, including the limits of 1000 characters for `root_cause`, 2000 characters for `code_snippet`, and 20 weaknesses), scoping (direct children included, grandchild expansion only when no direct-scope Candidate exists, parents and siblings excluded, `unknown_cwe` for a CWE absent from the BSKG), ranking order, tie-breaking by ascending CVE id, Top_K splitting (including remainder assignment in Plan order and reassignment of unused slots), and the minimum-relevance cutoff (a Candidate at the cutoff is retained and one below it is dropped).
2. THE Bellud test suite SHALL assert that the Seek_Tool returns status `cve_unavailable` with zero Candidates for each of these cases: BSKG unconfigured, BSKG unreachable, a BSKG response delayed beyond the 10-second request timeout, and a BSKG authentication error response.
3. THE Bellud test suite SHALL assert that a failure of one Retrieval_Unit marks only that unit `unavailable` and still returns the other units' results.
4. THE Bellud test suite SHALL assert that a known key value configured for the fake BSKG server does not appear in the Seek_Tool output, in captured logs, or in error messages, for one successful run and for each failure case in criterion 2.
5. THE Bellud test suite SHALL include a property test that runs at least 100 generated valid Plans against identical BSKG data and asserts identical output on repeated runs, and a round-trip test that asserts serialize, parse, serialize yields an equivalent Plan for at least 100 generated valid Plans.
6. THE Core test suite SHALL assert, running from `packages/core`, that the `seek` agent is always registered with mode `subagent` (the flag-off case was removed with the flag), denies `*`, allows only the Seek_Tool, and has no `subagent` permission.
7. THE Core tests SHALL exercise the real implementation, SHALL NOT use mocks or `globalThis` overrides, and SHALL run from `packages/core` and not from the repository root.
8. THE test suite SHALL include one end-to-end test with a stubbed LLM that asserts the following sequence: the first Round yields an unsound prediction, feedback names a different CWE, exactly one re-planning Round runs (2 Rounds in total), and the final response is a Security_Context with at least one retained Candidate within the 4000-character limit.
9. THE test suite SHALL include one end-to-end test with a stubbed LLM that asserts a `cve_unavailable` result produces a no-augmentation response with no CVE content and no second Seek_Tool call in the same invocation.

### Requirement 13: Main agent usage rule

**User Story:** As a developer, I want the main agent to call `seek` before it changes code, so that retrieval runs before code generation on every relevant request, as in SEEK, instead of depending on the short `seek` description.

#### Acceptance Criteria

1. THE Core SHALL export a constant `PROMPT_SEEK_USAGE` from `packages/core/src/plugin/seek-prompt.ts` that contains the Seek_Usage_Rule.
2. THE Seek_Usage_Rule SHALL instruct the Main_Agent, before it edits anything for a request to fix, change, refactor, or add a feature, to call the `subagent` tool with `agent="seek"` in the foreground.
3. THE Seek_Usage_Rule SHALL instruct the Main_Agent to pass the full task, the programming language, and the relevant code in the `seek` prompt, because the Seek_Agent starts with no context.
4. THE Seek_Usage_Rule SHALL instruct the Main_Agent to use the returned Security_Context as advice while writing the change, and to call `seek` at most once for the same task.
5. WHEN the Seek_Agent response states that no augmentation applies, THE Seek_Usage_Rule SHALL instruct the Main_Agent to continue the task normally.
6. THE Seek_Usage_Rule SHALL instruct the Main_Agent to skip `seek` for typo fixes, comment changes, docs-only changes, renames, tests-only changes, and pure questions.
7. THE Core SHALL add `PROMPT_SEEK_USAGE` as a `SystemPart` for the Build agent through a `ctx.session.hook("context", ...)` in `packages/core/src/plugin/agent.ts`, without removing or replacing the model-family prompts in `packages/core/src/plugin/system-prompt/*.txt`.
8. THE Core SHALL omit `PROMPT_SEEK_USAGE` from the `seek` agent's system prompt.
9. THE Core test suite SHALL assert, running from `packages/core` with no mocks, that `PROMPT_SEEK_USAGE` names `seek`, the foreground call, and every item of the skip list, that the Build agent's `system` includes `PROMPT_SEEK_USAGE`, and that the `seek` agent's prompt does not.
10. THE Core end-to-end test with a scripted LLM SHALL assert that a "fix this feature" prompt makes the Main_Agent call `subagent` with agent `seek` before any edit tool, and that a docs-only prompt makes no `seek` call.
