# Implementation Plan: bellu-seek-planner

## Overview

The work splits into two halves joined by one MCP tool, `bellu-graph_seek_retrieve`.

- **bellud (Go, `services/bellud`)** gets the deterministic retrieval core in `internal/seek` (plan validation, scoping, ranking, Top_K allocation, retriever), a BSKG client with key handling in `internal/seek/bskg`, env loading in `internal/config/seek.go`, and the `seek_retrieve` MCP tool, registered through `facade.Config.MCPExtras` next to `lensmcp`.
- **core (TypeScript/Effect)** gets the `seek` agent in `packages/core/src/plugin/agent.ts` with its prompt, permissions and step limit. The `seek_planner` flag was added by tasks 1.1 and 10.4 and later removed, so `seek` is now always registered. Task 15 adds the Build agent usage rule.
- Two end-to-end tests with a stubbed LLM close the plan.

Each group is test-first: the example tests are written before the implementation they cover and are red until it lands. Property tests (rapid in Go) come after the implementation and are optional.

Conventions that apply to every task (from `/home/ubuntu/bellucode/AGENTS.md`):

- Run Go tests from `services/bellud`. Run Bun tests and `bun typecheck` from the package directory (`packages/core`, `packages/schema`), never from the repo root, and never run `tsc` directly.
- No mocks, no `globalThis` overrides. Fakes are real servers (`httptest`) or real in-process services. Read the `unit-tests` skill in `.bellucode/skills` before writing Bun tests.
- No `any`, no aliased imports, no star imports in TypeScript.
- No Protocol or `HttpApi` change, so no `bun run generate`, except if adding the flag changes a generated config schema. Then regenerate from `packages/client` and never hand-edit generated files.
- Use conventional commits (`feat(core): ...`, `feat(bellud): ...`, `test(...)`). Commit at each checkpoint. Use a branch of at most three words, for example `seek-planner`, based on `origin/dev`.

## Tasks

- [x] 1. Foundations
  - [x] 1.1 Add the `seek_planner` feature flag (superseded: flag removed later)
    - Add key `seek_planner` with a non-empty description to the `registry` in `packages/schema/src/config/flag.ts`
    - Keep the default behavior of existing flags (on in local and dev builds, off in releases)
    - If a generated config schema changes, run `bun run generate` from `packages/client`
    - Run `bun typecheck` from `packages/schema`
    - _Requirements: 11.1, 11.2_

  - [x] 1.2 Create shared types in `services/bellud/internal/seek`
    - Add `types.go` with the constants (`MaxWeaknesses`, `MaxLanguage`, `MaxReasoning`, `MaxRootCause`, `MaxSnippet`, `DefaultTopK`, `MinTopK`, `MaxTopK`, `MaxScope`, weights, `DefaultMinRelevance`)
    - Define `Unit`, `Plan`, `Issue`, `Dropped`, `Edge`, `WeaknessInfo`, `VulnRef`, `VulnDetail`, `Candidate`, `UnitResult`, `Result`, `ErrInfo`, and the `Source` interface
    - Result and Plan slices must marshal as `[]`, not `null`
    - _Requirements: 3.8, 4.3, 5.7, 6.2, 6.3_

- [x] 2. Plan validation
  - [x] 2.1 Write example tests for plan validation in `internal/seek/plan_test.go`
    - Boundaries: `root_cause` 1000/1001, `code_snippet` 2000/2001, 8/9 weaknesses (superseded by task 14: 20/21), `language` 64/65 and empty, `reasoning` 4000/4001, lengths counted in code points (use multibyte runes)
    - Non-object plan, unknown field, missing field, wrong types, each asserting the field path in `issues` (for example `weaknesses[2].root_cause`)
    - Malformed `cwe_id` and duplicate `cwe_id` are rejected per unit with position and reason while the rest continue in order
    - Empty `weaknesses` is valid; `ParseTopK` accepts nil (default 4), 1 and 10, rejects 0, 11, `4.5`, strings
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.2, 4.5, 12.1_

  - [x] 2.2 Implement `plan.go`
    - `ParsePlan`, `ParseTopK` and `Plan.Marshal` as in the design, using a `map[string]json.RawMessage` walk for exact paths
    - Only validated typed values leave this package. No model text is interpolated anywhere
    - Make 2.1 pass
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 4.2, 4.5_

  - [x] 2.3 Write property test for plan round trip
    - **Property 1: Plan round trip**
    - File `internal/seek/plan_roundtrip_prop_test.go`, at least 100 generated valid Plans
    - **Validates: Requirements 3.8, 12.5**

  - [x] 2.4 Write property test for unit filtering
    - **Property 3: Unit filtering keeps valid units in order**
    - File `internal/seek/plan_filter_prop_test.go`
    - **Validates: Requirements 3.4, 3.5**

- [x] 3. Scoping
  - [x] 3.1 Write example tests for scoping in `internal/seek/scope_test.go`
    - Direct children included; parents, grandparents and siblings excluded
    - A CWE that is both child and grandchild keeps depth 1
    - Edge CWE ids that do not match `^CWE-[0-9]{1,5}$` are ignored
    - Scope capped at 50 with predicted first then ascending numeric id; cycles do not loop
    - _Requirements: 5.1, 5.3, 5.6, 5.8, 12.1_

  - [x] 3.2 Implement `scope.go`
    - `Scope` and `BuildScope(predicted, edges, maxDepth)` walking edges downward from the predicted CWE
    - Make 3.1 pass
    - _Requirements: 5.1, 5.3, 5.5, 5.6, 5.8_

  - [x] 3.3 Write property test for scope bounds
    - **Property 5: Scope stays within descendants, bounded and ordered**
    - File `internal/seek/scope_prop_test.go`; generate hierarchies with cycles, shared parents and unrelated nodes
    - **Validates: Requirements 5.1, 5.3, 5.6, 5.8**

- [x] 4. Ranking and Top_K allocation
  - [x] 4.1 Write example tests for ranking in `internal/seek/rank_test.go`
    - `Tokens`, `Jaccard`, `IdentMatch`, `SignalsFor`, `Score` with known weights
    - Ordering, tie-break by ascending CVE id on scores equal at 6 decimal places, missing signals as 0
    - Cutoff: score equal to the cutoff is kept, one below is dropped
    - _Requirements: 6.2, 6.3, 6.4, 6.6, 6.7, 12.1_

  - [x] 4.2 Write example tests for allocation in `internal/seek/alloc_test.go`
    - Even split, remainder to earlier units in Plan order, more units than `topK`, reassignment of unused slots, no candidates anywhere, sum equals `min(topK, sum(have))`
    - _Requirements: 6.5, 6.9, 12.1_

  - [x] 4.3 Implement `rank.go`
    - `Signals`, `Score`, `Tokens`, `Jaccard`, `IdentMatch`, `SignalsFor`, `Rank`, `Cutoff`
    - No randomness; rounding by `round(score*1e6)` as an integer
    - Make 4.1 pass
    - _Requirements: 6.2, 6.3, 6.4, 6.6, 6.10, 6.11_

  - [x] 4.4 Implement `alloc.go`
    - `Allocate(topK, have)` following the numbered rules in the design
    - Make 4.2 pass
    - _Requirements: 6.5, 6.9_

  - [x] 4.5 Write property test for score bounds and monotonicity
    - **Property 7: Score is bounded, monotone in each signal, and treats missing signals as zero**
    - File `internal/seek/rank_score_prop_test.go`
    - **Validates: Requirements 6.2, 6.3**

  - [x] 4.6 Write property test for ordering and cutoff
    - **Property 8: Output is ordered, cut off and tie-broken**
    - File `internal/seek/rank_order_prop_test.go`
    - **Validates: Requirements 4.3, 6.4, 6.6, 6.7**

  - [x] 4.7 Write property test for allocation
    - **Property 9: Top-K allocation fills the budget fairly without overflow**
    - File `internal/seek/alloc_prop_test.go`
    - **Validates: Requirements 6.5, 6.9**

- [x] 5. BSKG client, fake server and configuration
  - [x] 5.1 Create the fake BSKG test server in `internal/seek/seektest`
    - `httptest.Server` serving JSON fixtures from `internal/seek/testdata/` for the five allowed endpoints
    - Records method, path, raw query and headers; supports per-path failure injection, delay, 401, 404, 5xx, a redirect to another host and a body that echoes the key
    - Fixtures use the field names of the BSKG API shapes (`/home/ubuntu/Bellu-security-knowelege-graph/docs/api-shapes.md`)
    - _Requirements: 12.1, 12.2, 12.4_

  - [x] 5.2 Write tests for the BSKG client in `internal/seek/bskg/client_test.go`
    - Key sent only as `Authorization: Bearer` and only to the configured host; never in URL, query or body
    - Redirect not followed (treated as unreachable); 401 maps to authentication, 404 to not found, 429/5xx and network errors to unreachable, deadline to timeout (short `Timeout`)
    - Path segments with `/ ? # % ..` and whitespace stay literal; ids are format-checked before use
    - Oversized or malformed JSON is unreachable; error bodies never surface
    - `Configured()` and `Load`: blank, whitespace, non-https, `http` loopback only, userinfo, query and fragment rejected; env takes precedence
    - Unconfigured client makes zero requests
    - Contract test: each fixture decodes with the real client and only the five allowed paths are requested
    - `Secret` prints `[REDACTED]` for `%v`, `%+v`, `%#v` and JSON
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.8, 12.2, 12.4_

  - [x] 5.3 Implement `internal/seek/bskg/client.go` and `config.go`
    - `Config`, `Secret`, `Load`, `Configured`, `New`, `Weakness`, `Children` (via `/v1/graph/neighborhood` with `relTypes=CHILD_OF`, edges child to parent), `WeaknessVulns`, `Vulnerability`, `Status`
    - `CheckRedirect` returns `http.ErrUseLastResponse`; 2 MiB response limit; `GET` only; proxy only for https
    - Error categories `ErrNotFound`, `ErrUnconfigured`, `ErrUnreachable`, `ErrTimeout`, `ErrAuth` carry no URL, key or body
    - Make 5.2 pass
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.8, 4.6_

  - [x] 5.4 Write tests for env loading in `internal/config/seek_test.go`
    - `BELLUCODE_SEEK_BSKG_URL`, `BELLUCODE_SEEK_BSKG_KEY`, `BELLUCODE_SEEK_MIN_RELEVANCE` (default 0.20, range 0.0 to 1.0)
    - Invalid min relevance is a startup error; missing or invalid URL or key means unconfigured; the warning names the variable and never the value
    - _Requirements: 6.6, 9.1, 9.2, 9.4_

  - [x] 5.5 Implement `internal/config/seek.go`
    - `LoadSeek(env)` following `internal/config/cve.go`
    - Make 5.4 pass
    - _Requirements: 6.6, 9.1, 9.2_

- [x] 6. Retriever
  - [x] 6.1 Write example tests for the retriever in `internal/seek/retrieve_test.go`
    - Run against the fake BSKG with the real client
    - Statuses: `ok`, `no_candidates` (none attached, all below cutoff), `unknown_cwe` (404), `unavailable` (one unit fails while others return)
    - Grandchild expansion only when no depth 0 or 1 CWE has a candidate, and at most once; `Expanded` reported
    - Cross-unit dedupe keeps the earliest unit; detail fetches capped at 120 ordered by CVSS desc then CVE id asc; CWE names fetched only for allocated candidates; fix commit and repository present together or omitted
    - `cve_unavailable` with zero candidates for unconfigured, unreachable, delay beyond the request timeout (short `RequestTimeout`), and 401
    - Total deadline: finished units returned, others `unavailable` (short `TotalTimeout`)
    - Empty plan and invalid plan make zero BSKG requests
    - The known key is absent from the Result, captured logs and error strings in one success run and in each failure case above
    - _Requirements: 3.1, 3.6, 4.3, 4.4, 5.2, 5.4, 5.7, 6.1, 6.5, 6.7, 6.8, 6.9, 6.12, 9.7, 10.1, 10.2, 10.5, 10.8, 12.1, 12.2, 12.3, 12.4_

  - [x] 6.2 Implement `internal/seek/retrieve.go`
    - `Config`, `Retriever`, `Run` with `context.WithTimeout(TotalTimeout)`, concurrency 8 and per-request timeout 10s
    - Merge, dedupe, rank, cutoff and allocate after fetches finish, in Plan order, so output does not depend on scheduling
    - Status model table from the design; 401 cancels all work; raw upstream bodies and URLs never copied; logs hold counts, durations and categories only
    - Make 6.1 pass
    - _Requirements: 4.3, 4.4, 4.6, 5.1, 5.2, 5.4, 5.5, 5.7, 6.1, 6.5, 6.7, 6.8, 6.9, 6.12, 9.7, 10.1, 10.2, 10.5, 10.8_

  - [x] 6.3 Write property tests for validation and request shape
    - **Property 2: Validation rejects out-of-bound input without BSKG calls**
    - **Property 4: Requests are read-only, allowlisted and injection-safe**
    - File `internal/seek/retrieve_request_prop_test.go`
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.7, 4.2, 4.5, 4.6, 9.3, 9.5, 9.8**

  - [x] 6.4 Write property tests for expansion and dedupe
    - **Property 6: Expansion happens only when the direct scope has no candidates**
    - **Property 10: A CVE is returned at most once, in the earliest unit**
    - File `internal/seek/retrieve_scope_prop_test.go`
    - **Validates: Requirements 5.2, 5.7, 6.1**

  - [x] 6.5 Write property test for determinism
    - **Property 11: Determinism**
    - File `internal/seek/retrieve_determinism_prop_test.go`, at least 100 generated valid Plans, repeated runs with different response timing, byte-identical marshaled Results
    - **Validates: Requirements 6.11, 12.5**

  - [x] 6.6 Write property test for failure isolation
    - **Property 12: One failing unit does not affect the others**
    - File `internal/seek/retrieve_isolation_prop_test.go`
    - **Validates: Requirements 5.4, 10.5, 12.3**

  - [x] 6.7 Write property test for key non-disclosure
    - **Property 13: The BSKG key never appears in any output**
    - File `internal/seek/retrieve_secret_prop_test.go`; modes: success, unreachable, timeout, 401, 5xx echoing the key, redirect to another host
    - **Validates: Requirements 9.3, 9.4, 10.8, 12.4**

- [x] 7. Checkpoint - retrieval core
  - Run `go test ./internal/seek/... ./internal/config/...` and `go vet ./...` from `services/bellud`. Ensure all tests pass, ask the user if questions arise.
  - Commit with `feat(bellud): add seek retrieval core and BSKG client`.

- [x] 8. MCP tool and wiring
  - [x] 8.1 Write tests for the MCP tool in `internal/seek/mcp_test.go`
    - Use the real `mcp.Server` with an in-memory client transport and the fake BSKG
    - Tool `seek_retrieve` is listed with `ReadOnlyHint: true` when configured, and absent when URL or key is missing or invalid
    - Valid call returns `structuredContent` and text content with status `ok`; invalid plan returns `isError: true`, status `invalid_plan` and path-bearing `issues`; unknown top-level arguments produce an `invalid_plan` issue at that path
    - `cve_unavailable` is returned as a normal (non-error) result
    - Other `bellu-graph` tools keep their names and schemas when seek is absent
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 4.7, 10.1, 11.6_

  - [x] 8.2 Implement `internal/seek/mcp.go`
    - `Register(*mcp.Server, *Retriever)` using the low-level `server.AddTool` with the loose input schema from the design, and `Extras`
    - Parse arguments with `ParsePlan` and `ParseTopK`, then call `Retriever.Run`
    - Make 8.1 pass
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 4.6, 10.1_

  - [x] 8.3 Wire `seek_retrieve` in `services/bellud/cmd/bellud/main.go`
    - Load the config with `config.LoadSeek` and `bskg.Load(os.LookupEnv)`; build the client and retriever only when configured
    - Compose one `facade.Config.MCPExtras` that calls the existing `lensmcp` registration and, when configured, `seek.Register`
    - No change to `handlers/mcp.ts` or `agentcfg`
    - Run `go build ./...` and the existing bellud tests
    - _Requirements: 4.1, 4.7, 9.1, 9.2, 11.6_

  - [x] 8.4 Write property test for configuration validity
    - **Property 14: Configuration validity decides whether any request is made**
    - File `internal/seek/mcp_config_prop_test.go`: for generated URL and key pairs, `Configured()` matches the rule, the fake server sees zero requests when false and the tool is absent from the list
    - **Validates: Requirements 4.7, 9.1, 9.2**

- [x] 9. Checkpoint - bellud complete
  - Run `go test ./...` and `go vet ./...` from `services/bellud`. Ensure all tests pass, ask the user if questions arise.
  - Commit with `feat(bellud): serve seek_retrieve on bellu-graph`.

- [x] 10. Core: seek agent, prompt and gating
  - [x] 10.1 Extend `packages/core/test/plugin/agent.test.ts` (flag on/off cases superseded: flag removed)
    - Read `.bellucode/skills/unit-tests` first
    - Flag on: `seek` exists with mode `subagent`, description 1 to 200 characters, `steps` 4, no `model`, rules deny `*`, allow only `bellu-graph_seek_retrieve`, deny `subagent` (deny entry first)
    - Flag off through both `-seek_planner` in `BELLUCODE_FLAGS` and `experimental.seek_planner: false`: `seek` absent from `agents.list()`, `subagent` with agent `seek` returns the unknown-agent error and creates no child session, subagent description omits `seek`
    - Flag off: main agent's tool list, subagent list and permission rules equal those without the feature; `bellu-graph_seek_retrieve` removed from the tool registry
    - Flag on: subagent description lists `seek`; a `seek` child session uses the parent's provider and model
    - _Requirements: 1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 11.2, 11.6, 11.7, 12.6, 12.7_

  - [x] 10.2 Write prompt contract tests in `packages/core/test/plugin/seek-prompt.test.ts`
    - Contains the JSON contract (`language`, `reasoning`, `weaknesses`), `^CWE-[0-9]{1,5}$`, limits 8 (superseded by task 14: 20), 1000 and 2000, the empty-list rule, the 2-Round rule, the 4000 and 6000 character limits and the `cve_unavailable` stop rule
    - Contains no language allowlist or language refusal wording; mentions the single tool `bellu-graph_seek_retrieve`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.7, 2.8, 7.4, 7.6, 8.3, 10.3, 12.7_

  - [x] 10.3 Add `packages/core/src/plugin/seek-prompt.ts`
    - Export `PROMPT_SEEK` with the planner, selector, re-plan, failure-handling and final-answer sections from the design
    - Make 10.2 pass
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.7, 2.8, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 10.3, 10.4, 10.6_

  - [x] 10.4 Register the `seek` agent in `packages/core/src/plugin/agent.ts` (flag gating superseded: flag removed, always registered)
    - Read `Flag.enabled("seek_planner")` from `@bellucode/core/flag`; check at implementation that it re-evaluates on config reload and otherwise evaluate it inside the transform callback
    - When on: `ctx.agent.transform` with `editor.update(Agent.ID.make("seek"), ...)` setting name, description (at most 200 characters), `system = PROMPT_SEEK`, `mode = "subagent"`, `steps = 4`, and permissions pushed in order deny `*`, allow `bellu-graph_seek_retrieve`, deny `subagent`; leave `item.model` unset
    - When off: no `seek` agent, and `ctx.tool.transform(editor => editor.remove("bellu-graph_seek_retrieve"))`
    - No temperature is set because `Agent.Info` has none (R2.6 has no effect yet); no new routes, config fields or hooks
    - Make 10.1 pass; run `bun typecheck` from `packages/core` and `packages/schema`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 2.6, 7.4, 11.1, 11.3, 11.4, 11.6, 11.7_

- [x] 11. Checkpoint - core complete
  - Run `bun test` for the touched files and `bun typecheck` from `packages/core` and `packages/schema`. Ensure all tests pass, ask the user if questions arise.
  - Commit with `feat(core): add seek subagent behind seek_planner flag`.

- [x] 12. End-to-end tests with a stubbed LLM
  - [x] 12.1 Build the e2e harness in `packages/core/test/plugin/seek.e2e.test.ts`
    - Read `test/host.ts` and the `unit-tests` skill first
    - Scripted LLM provider from `test/host.ts` that returns planned assistant turns and tool calls, and records each tool call
    - In-process MCP server exposing `seek_retrieve` with the same result schema (design "Result"), returning scripted results and counting calls; reaches the agent as `bellu-graph_seek_retrieve`
    - Drive the main agent through `subagent(agent=seek)` so the real registration, permissions and step limit are exercised
    - _Requirements: 1.4, 1.5, 12.7_

  - [x] 12.2 Add the re-plan scenario
    - Round 1 plan has an unsound prediction; the verdict names a different replacement CWE not predicted before; exactly one re-planning call (2 tool calls in total) with a plan holding only the replacement unit
    - Final response is a Security_Context with at least one retained candidate, only CVE ids, CWE names and fix commits present in tool results, lists predicted and retained CWE ids, and is at most 4000 characters
    - The main agent receives it as ordinary subagent text
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.6, 8.1, 8.2, 8.3, 8.4, 8.5, 10.7, 12.8_

  - [x] 12.3 Add the `cve_unavailable` scenario
    - The tool returns `cve_unavailable`; the final response states that no augmentation applies, contains no CVE, fix commit or CWE guidance, and the tool was called exactly once
    - The main agent continues in the same session without a tool error
    - _Requirements: 10.1, 10.3, 10.7, 12.9_

- [x] 13. Final checkpoint - everything green
  - Run from `services/bellud`: `go test ./...` and `go vet ./...`. Run from `packages/core` and `packages/schema`: `bun test` and `bun typecheck`. Run `bun run check` from the repo root.
  - Ensure all tests pass, ask the user if questions arise.
  - Commit with `test(core): add seek planner end-to-end tests`. State in the PR body that the `seek_planner` flag guards the change.

- [x] 14. Raise the weakness cap to 20 and count submitted items
  - [x] 14.1 Update tests for the new cap
    - `services/bellud/internal/seek/plan_test.go`: boundaries 20/21 weaknesses; a test that 21 submitted items with some malformed `cwe_id` is `invalid_plan` at `weaknesses`
    - `packages/core/test/plugin/seek-prompt.test.ts`: expects the "at most 20" cap wording and the distinct-risk rule (no broader or narrower variant of an already predicted CWE)
    - Property generators in `plan_roundtrip_prop_test.go`, `plan_filter_prop_test.go` and `retrieve_request_prop_test.go` use the new limit
    - _Requirements: 2.2, 3.3_

  - [x] 14.2 Implement the new cap
    - `MaxWeaknesses = 20` in `services/bellud/internal/seek/types.go`
    - `ParsePlan` checks the submitted count before per-unit rejection
    - `PROMPT_SEEK` in `packages/core/src/plugin/seek-prompt.ts` says at most 20 weaknesses and only distinct risks
    - Make 14.1 pass
    - _Requirements: 2.2, 3.3_

  - [x] 14.3 Checkpoint - cap change green
    - Run `go test ./internal/seek/...` from `services/bellud`, `bun test` for the seek tests and `bun typecheck` from `packages/core`. Ensure all tests pass, ask the user if questions arise.
    - Commit with `fix(bellud): cap seek plans at 20 submitted weaknesses` on branch `seek-planner`, adding explicit paths only. Do not push.
    - _Requirements: 2.2, 3.3_

- [x] 15. Main agent usage rule
  - [x] 15.1 Add `PROMPT_SEEK_USAGE` in `packages/core/src/plugin/seek-prompt.ts`
    - Write the test first in `packages/core/test/plugin/seek-prompt.test.ts`: the text names `seek`, the foreground `subagent(agent="seek")` call, and the skip list (typos, comments, docs-only, renames, tests-only, pure questions)
    - Export `PROMPT_SEEK_USAGE` with the rule from the design section "Main agent usage rule": call before editing, pass task, language and code, use the Security_Context as advice, no second call, continue on no augmentation
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.9_
  - [x] 15.2 Append the rule to the Build agent in `packages/core/src/plugin/agent.ts`
    - `item.system` is not usable: an agent `system` replaces the model-family prompts in `packages/core/src/plugin/system-prompt/*.txt`
    - Append `PROMPT_SEEK_USAGE` through `ctx.session.hook("context", ...)`, which pushes a `SystemPart` for the Build agent only; leave the `seek` agent's `system = PROMPT_SEEK`
    - Extend `packages/core/test/plugin/agent.test.ts`: Build's context hook adds the rule, the `seek` agent's prompt does not
    - _Requirements: 13.7, 13.8, 13.9_
  - [x] 15.3 Extend `packages/core/test/plugin/seek.e2e.test.ts`
    - A "fix this feature" prompt makes the scripted main agent call `subagent(agent="seek")` before any edit tool
    - A docs-only prompt makes no `seek` call
    - _Requirements: 13.10_
  - [x] 15.4 Checkpoint - verify and commit
    - Run `bun test` and `bun typecheck` from `packages/core`. Ensure all tests pass, ask the user if questions arise.
    - Restart the bellucode systemd service, then check live that an "add a login endpoint" request triggers `seek` first
    - Commit with `feat(core): require seek before code changes`, adding explicit paths only. Do not push.
    - _Requirements: 13.1, 13.7, 13.9, 13.10_

## Notes

- Tasks marked with `*` are optional property tests and can be skipped for a faster MVP. Example and end-to-end tests are required because Requirement 12 mandates them.
- Each property test uses `pgregory.net/rapid` (already in `go.mod`) with at least 100 iterations, and carries the comment `// Feature: bellu-seek-planner, Property N: <title>` followed by `**Validates: Requirements ...**`.
- Properties 1 to 14 are all assigned: P1 (2.3), P2 and P4 (6.3), P3 (2.4), P5 (3.3), P6 and P10 (6.4), P7 (4.5), P8 (4.6), P9 (4.7), P11 (6.5), P12 (6.6), P13 (6.7), P14 (8.4).
- The agent registration, prompt, flag and LLM behavior have no Correctness Properties in the design, so they use example tests only.
- The tool is gated in bellud on BSKG configuration only (design D2). The core flag gate was removed. `seek_retrieve` is reachable only when the graph engine is up (design Open Point 5).
- Requirement 11.5 does not apply unless a change alters generated client files.
- Task 15 adds only the usage rule, with example tests only (no Correctness Properties).

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1", "3.1", "4.1", "4.2", "5.1", "5.4", "10.1", "10.2"] },
    { "id": 2, "tasks": ["2.2", "3.2", "4.3", "4.4", "5.2", "5.5", "6.1", "8.1", "10.3"] },
    { "id": 3, "tasks": ["2.3", "2.4", "3.3", "4.5", "4.6", "4.7", "5.3", "10.4"] },
    { "id": 4, "tasks": ["6.2", "12.1"] },
    { "id": 5, "tasks": ["6.3", "6.4", "6.5", "6.6", "6.7", "8.2", "12.2"] },
    { "id": 6, "tasks": ["8.3", "8.4", "12.3"] },
    { "id": 7, "tasks": ["14.1"] },
    { "id": 8, "tasks": ["14.2"] },
    { "id": 9, "tasks": ["15.1"] },
    { "id": 10, "tasks": ["15.2"] },
    { "id": 11, "tasks": ["15.3"] }
  ]
}
```
