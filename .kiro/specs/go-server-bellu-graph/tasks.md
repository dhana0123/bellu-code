# Implementation Plan: Go Server with Bellu Graph Engine (`bellud`)

## Overview

Build `services/bellud` incrementally so every step compiles and runs. The order is: toolchain and scaffold, auth parity, route table, TS child supervisor, reverse proxy, front door (`bellud serve` proxying the existing TS server end to end), sync/rename tool and vendored engine, in-process facade, redaction guard, collectors, graph HTTP/MCP API, protocol contract and SDK, agent wiring, web UI, OpenAPI merge, contract harness, then ops.

Repo rules that apply to every task:
- Go tests run from `services/bellud` (`go test ./...`). TS tests run from the package directory (`packages/schema`, `packages/protocol`), never from the repo root.
- Run `bun typecheck` from each touched TS package. Run `bun run generate` from `packages/client` after any protocol change; never edit generated client files.
- No `.changeset` files. Branch base is `dev`. Commits use `type(scope): summary`.
- Bun is at `/home/ubuntu/.bun/bin/bun`. Go may not be installed (task 1.1).
- Property tests use `pgregory.net/rapid` (Go) or `fast-check` (TS). Compatibility names stay unchanged and are marked "(compatibility name)" in comments and docs.

## Tasks

- [x] 1. Toolchain and module scaffold
  - [x] 1.1 Install or verify Go >= 1.26.9
    - Run `go version`; if missing or older, download the official linux tarball and install to `/usr/local/go` with sudo (fallback `~/go-toolchain` if sudo is unavailable), and put it on PATH via `~/.profile`
    - Verify `go version` reports >= 1.26.9; also verify `/home/ubuntu/.bun/bin/bun --version`
    - If an older Go is installed, use `GOTOOLCHAIN` or replace it rather than lowering the `go.mod` directive
    - _Requirements: 24.5_

  - [x] 1.2 Scaffold `services/bellud` module, config and naming
    - Create `services/bellud/go.mod` with module `github.com/bellu/bellucode/services/bellud` and `go 1.26.9`; add `pgregory.net/rapid` and a YAML library at pinned versions
    - Create `cmd/bellud/main.go` with a `serve` subcommand (flags `--hostname`, `--port`) that parses config, logs, and serves a placeholder 200 on `/healthz` for now
    - Create `internal/config`: read only `BELLUCODE_PASSWORD` (fallback `OPENCODE_PASSWORD`, marked compatibility name), `BELLUCODE_HOSTNAME`, `BELLUCODE_PORT`, `BELLUCODE_CORS`, `BELLUCODE_WEB_DIST`; defaults `127.0.0.1:4096`; helpers for `~/.config/bellucode/` and `~/.local/share/bellucode/` paths; warn when hostname is non-loopback and password is empty
    - Create `internal/logx` that prefixes every line with `[bellud]` and a relay writer that prefixes `[ts-child]`
    - Add `.gitignore` entry for `services/bellud/dist`
    - Verify `go build ./... && go vet ./...` and `go run ./cmd/bellud serve` answers `/healthz`
    - _Requirements: 1.1, 1.9, 23.7, 24.5, 24.7, 25.1, 25.2, 25.3_

  - [x]* 1.3 Write unit tests for config and naming
    - Test defaults, `OPENCODE_PASSWORD` fallback precedence, path helpers, log prefixes
    - _Requirements: 1.1, 3.1, 3.2, 23.7, 25.2, 25.3_

- [x] 2. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Authentication parity
  - [x] 3.1 Implement `internal/auth`
    - `Authenticator` with `Authorize`, `IssueSession`, `VerifySession`, `SessionCookieName(host)`; username `opencode`, cookie `opencode_session[_<port>]`, HMAC context `opencode-session-v1`, 30 day TTL (all marked compatibility name)
    - Constant-time comparison; empty password rejects everything; malformed header/token returns false without panic
    - Helper that writes 401 with `WWW-Authenticate: Basic`
    - Read `packages/server/src/auth.ts` first and mirror it exactly
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.9, 3.10, 3.11, 3.12, 3.13_

  - [x] 3.2 Generate shared TS/Go auth fixtures
    - Add a Bun script that imports the real `packages/server/src/auth.ts` and emits `internal/auth/testdata/vectors.json` (password, now, token, expected, plus tokens issued by TS)
    - Add a Go test that loads the vectors and checks `VerifySession` plus Go-issued tokens in a TS-verification vector set
    - _Requirements: 3.8_

  - [x]* 3.3 Write property test for auth parity
    - **Property 12: Auth parity**
    - Fixture-driven parity with TS plus rapid-generated tokens/times; rotation invalidates old tokens; malformed input never panics
    - **Validates: Requirements 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.14**

  - [x]* 3.4 Write unit tests for the authenticator
    - Basic with password, Basic with session token, cookie by Host port, empty password, 401 header
    - _Requirements: 3.3, 3.4, 3.5, 3.11, 3.12, 3.13_

- [x] 4. Route table and validation
  - [x] 4.1 Implement `internal/server/routes` types, loader, `Lookup` and `Validate`
    - `Route`, `RouteTable`, specificity ranking (exact > `{param}` > `/*`; specific method > `*`), order-independent lookup, overlap rejection naming both patterns, totality check naming method and path
    - _Requirements: 1.2, 1.3, 1.6, 1.10, 2.1, 2.2, 2.3, 2.4_

  - [x] 4.2 Generate and embed `routes.yaml`
    - Add a Bun script that produces the protocol operation list from the TS `Api` OpenAPI, and a generator that writes `internal/server/routes.yaml` with every operation assigned owner `ts`, `Stream` set for SSE/WebSocket routes, `Public` for the web shell
    - Embed with `go:embed`; `MustLoadEmbedded()` validates against the operation list in a test
    - Owner `go` only for registered handlers (graph routes are flipped in task 15)
    - _Requirements: 2.1, 2.5, 2.6, 2.7_

  - [x]* 4.3 Write property test for the route table
    - **Property 11: Route table total and disjoint**
    - Permute the table and assert `Lookup` is unchanged; embedded table is total over operations and disjoint
    - **Validates: Requirements 1.3, 1.4, 1.7, 1.12, 2.1, 2.2, 2.3, 2.4**

  - [x]* 4.4 Write unit tests for specificity and validation errors
    - Overlap error names both patterns; missing operation error names method and path; default owner `ts` on no match
    - _Requirements: 1.3, 1.6, 2.3, 2.4_

- [x] 5. TS child supervisor
  - [x] 5.1 Implement `internal/tschild`
    - Spawn `bun run src/index.ts serve --hostname 127.0.0.1 --port 0` in `packages/cli`, stdin pipe as lease, parse `{"url": ...}` stdout line, probe `/api/server/info` with the internal credential, 30s start timeout
    - Generate internal credential with `crypto/rand`; pass only via child env `OPENCODE_PASSWORD` (compatibility name); strip external password from child env and args; relay child stdout/stderr with `[ts-child]` prefix and never log credentials
    - Restart loop with backoff 500 ms to 15 s, reset on success; `degraded` state after repeated failures keeping last stderr lines; `Current()` returns nil while starting
    - `Stop`: close stdin, grace period, kill
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.10, 4.11, 4.12, 7.2, 7.3, 23.7_

  - [x]* 5.2 Write tests for the supervisor using a real stub child
    - Use a small script child (not mocks) to exercise ready, timeout, crash and backoff reset, lease close, no credential in logs
    - _Requirements: 4.3, 4.5, 4.6, 4.7, 4.11, 4.12_

- [x] 6. Reverse proxy (HTTP, SSE, WebSocket) and credential isolation
  - [x] 6.1 Implement `internal/proxy` for HTTP and SSE
    - `httputil.ReverseProxy` with `FlushInterval = -1` for stream routes and `text/event-stream`; remove hop-by-hop headers; set `X-Forwarded-*`; preserve `Host`; leave `Content-Encoding`/`Content-Length` and bodies untouched
    - Strip client `Authorization` and `Cookie`, inject Basic `opencode:<internal>` (compatibility name)
    - 503 + `Retry-After: 2` + protocol-shaped JSON error when no child; clean close of client stream when the child exits mid-SSE
    - _Requirements: 4.8, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.6, 7.1_

  - [x] 6.2 Add WebSocket upgrade splice
    - Hijack both sides and copy bidirectionally with pooled buffers; preserve frame order; pass close frames and close both connections
    - _Requirements: 6.3, 6.4, 6.5_

  - [x]* 6.3 Write property test for proxy transparency
    - **Property 6: Proxy transparency**
    - Use `httptest` upstream with rapid-generated methods, headers, bodies and chunk splits; compare bytes both ways
    - **Validates: Requirements 5.1, 5.3, 5.4, 5.5, 5.7**

  - [x]* 6.4 Write property test for streaming
    - **Property 7: Streaming preserved**
    - Assert each SSE chunk/WebSocket frame is observable before the stream ends; order and content preserved in both directions
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**

  - [x]* 6.5 Write property test for credential isolation
    - **Property 8: Credential isolation**
    - Upstream records headers; assert only the internal credential arrives, external password absent from child env, args and captured logs
    - **Validates: Requirements 7.1, 7.2, 4.2, 4.13**

- [x] 7. Front door and runnable `bellud serve`
  - [x] 7.1 Implement `internal/server` front door
    - `Server.ServeHTTP`: lookup, public routes before auth, auth then dispatch to Go handler or Proxy, default owner `ts` on no match, 404 (not `index.html`) for unmatched API-side paths owned by Go, CORS from `BELLUCODE_CORS`
    - API side: `/api`, `/api/*`, `/auth/*`, `/openapi.json`
    - _Requirements: 1.2, 1.4, 1.5, 1.6, 1.7, 1.8, 20.13, 20.14_

  - [x] 7.2 Wire `bellud serve` end to end
    - Start supervisor, build server with embedded table, bind the listener, send `READY=1` exactly once after bind (stdlib unix datagram to `NOTIFY_SOCKET`), exit non-zero with hostname/port in the log if bind fails
    - SIGTERM/SIGINT: stop accepting, drain up to 30s, stop child, exit 0 within 10s of SIGTERM for the child stop path; non-zero on forced cancel
    - Verify manually: with a password set, the existing TS server is reachable through `:4096` with Basic auth
    - _Requirements: 1.1, 4.9, 11.8, 11.9, 23.3, 23.4, 23.8_

  - [x]* 7.3 Write integration tests with a real TS child
    - Temp HOME, spawn bellud + TS child, hit `/api/server/info`, open the SSE event feed, kill the child mid-stream and assert clean close and later recovery, 401 without credentials
    - _Requirements: 1.4, 1.5, 3.12, 4.6, 4.8, 4.9, 6.6, 23.3_

- [x] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Sync/rename tool and vendored engine
  - [x] 9.1 Implement the rename engine and map
    - `services/bellud/script/rename.map.yaml` and `internal/rename`: ordered rules (module, proto, env `TOISE_`->`BELLU_GRAPH_`, metric, URI, identifier, user-facing text "Bellu Graph Engine", binary, path)
    - Rule validation up front: fail before touching any file if any rule output matches any rule input
    - _Requirements: 8.6, 8.7, 8.8, 9.4, 9.5_

  - [x] 9.2 Implement `cmd/sync-bellu-graph` and `script/sync-bellu-graph`
    - Validate 40-char lowercase hex commit; fetch tarball and verify checksum; process files in bytewise path order; CRLF to LF; exclude `internal/demo/**` and `.git/**`
    - Copy upstream `LICENSE` byte-for-byte; write `NOTICE` (project name + full SHA); idempotent modification marker on `.go` files, keeping upstream notices; write `UPSTREAM.md` (repo, SHA, license, tool version, no date)
    - Regenerate proto and GraphQL outputs; leftover `toise` scan (case-insensitive, path and content) with Allow_List `NOTICE`, `UPSTREAM.md`, attribution blocks; one line per offender
    - Stage in a temp dir, atomic replace, delete files removed upstream; on any failure delete staging and leave the vendored tree untouched; touch only `services/bellud/internal/bellugraph`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.9, 8.10, 8.11, 8.12, 8.13, 8.14, 8.15, 9.1, 9.2, 9.3, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 25.7_

  - [x]* 9.3 Write property test for rename idempotence and determinism
    - **Property 1: Rename idempotence and determinism**
    - Generated trees: `Sync` twice yields identical output; `rename(rename(x)) == rename(x)`
    - **Validates: Requirements 8.4, 8.5, 8.6, 8.7, 8.8**

  - [x]* 9.4 Write property test for no leftover upstream names
    - **Property 2: No leftover upstream names**
    - Outside the allow-list there is no case-insensitive `toise`, `TOISE_`, `toise_` or `toise://`
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.4**

  - [x]* 9.5 Write property test for license preservation
    - **Property 3: License preservation**
    - LICENSE byte-identical, NOTICE has the SHA, each transformed `.go` file has the marker exactly once
    - **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**

  - [x] 9.6 Vendor Toise at a pinned commit
    - At implementation time fetch the latest `main` SHA of `https://github.com/toise-dev/toise` (for example `git ls-remote` or `gh api`), record the full 40-char SHA, and run the sync tool with it
    - Add dependencies to `go.mod`/`go.sum` (pebble, gqlgen, MCP go-sdk, OTel pdata, grpc), run `go mod tidy` and `go mod verify`
    - Confirm `go build ./...`, `go vet ./...`, `go test ./...` pass from `services/bellud`, including the renamed upstream tests; commit LICENSE, NOTICE and UPSTREAM.md
    - If the latest main does not build with the rename map, fix the map and rerun the tool rather than hand-editing vendored files
    - _Requirements: 8.1, 8.16, 9.5, 10.1, 10.2, 25.1_

- [x] 10. In-process graph engine facade
  - [x] 10.1 Implement `internal/graph` Open, config and storage security
    - Config from `BELLU_GRAPH_ENABLED/DIR/OTLP_LISTEN/RETENTION/LOG_LEVEL` with parse errors that name the variable; default dir `~/.local/share/bellucode/graph`; disabled means no store open and 503 `graph_unavailable`; OTLP listener off when empty
    - Create dir 0700 and files 0600; refuse to open if `mode & 0077 != 0` without changing permissions; locked/corrupt/wrong perms disables the engine within 5s, logs the lock holder path once, and never writes to a corrupt log
    - Dev default on, release default off, explicit value wins
    - _Requirements: 11.1, 11.10, 11.11, 11.12, 11.13, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 19.8_

  - [x] 10.2 Implement `Ingest`, `Query`, identity and pagination
    - Facade exposes exactly `Ingest`, `Query`, `MCPHandler`, `Close`; only `internal/graph` imports vendored packages
    - `identity.Hash(kind, attrs)` over registered identity attributes; reject unknown kind or missing identity attribute
    - `Apply` as single atomic append; reject any batch with an attributed relation naming it, appending nothing; `recorded_at` set at append, `observed_at` preserved
    - `Query`: entity (with as-of), find, neighbors, history, changes, diff; not-found errors; default page 100, max 1000, reject page size < 1 or > 1000; derive added/changed/removed from full observations
    - _Requirements: 11.2, 11.3, 11.4, 11.5, 11.6, 11.14, 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9, 13.10, 13.11, 13.12, 13.13_

  - [x] 10.3 Implement the MCP handler and graceful close
    - `MCPHandler()` exposes exactly the 12 upstream tools; `annotate_entity` writes an audit record (token identity, entity ID, timestamp) before applying, and does not apply the annotation if the audit write fails
    - `Close` flushes the store; integrate with shutdown in `serve`
    - _Requirements: 11.7, 11.8, 16.13, 16.14_

  - [x]* 10.4 Write property test for identity hash determinism
    - **Property 9: Identity hash determinism**
    - **Validates: Requirements 13.1, 13.2, 13.3, 13.4**

  - [x]* 10.5 Write property test for as-of equals replay
    - **Property 10: As-of equals replay**
    - Random event logs; compare `Query.Entity` with a fold of `projection.Apply`; cache on/off identical
    - **Validates: Requirements 13.6, 13.7, 13.8, 13.9**

  - [x]* 10.6 Write property test for the relation constraint
    - **Property 14: Relation constraint**
    - Batches with attributed relations are rejected whole; accepted batches have none
    - **Validates: Requirements 11.14, 14.7**

  - [x]* 10.7 Write unit tests for storage security, config errors and pagination
    - Permission refusal leaves modes untouched, corrupt log unchanged, bad env values, page limits, not-found
    - _Requirements: 11.6, 11.12, 12.2, 12.3, 12.5, 13.12, 13.13_

- [x] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Redaction guard
  - [x] 12.1 Implement the pattern generator
    - `go generate` tool reads the `redaction` patterns from `/home/ubuntu/bellu-ai-cyber/bellu.yaml` and writes `internal/redact/patterns.go`; no runtime dependency on that repo
    - Fail naming the rule id on a compile error and leave the existing `patterns.go` unchanged
    - _Requirements: 15.1, 15.9_

  - [x] 12.2 Implement `Guard.Scrub` and `Guard.Leaks`
    - Replace matches with `[REDACTED:<rule_id>]` in every string value; keep entity IDs, counts and field names; do not mutate input; idempotent
    - Leak check after scrubbing; a leak drops the whole batch and emits an audit event with collector and rule id only
    - _Requirements: 15.2, 15.3, 15.4, 15.5, 15.7, 15.8_

  - [x]* 12.3 Write property test for scrub idempotence
    - **Property 5: Scrub idempotence**
    - **Validates: Requirements 15.2, 15.3, 15.4, 15.5**

  - [x]* 12.4 Write unit tests for the guard and generator
    - Known patterns, input unmodified, bad pattern failure message
    - _Requirements: 15.1, 15.4, 15.7, 15.9_

- [x] 13. Collectors
  - [x] 13.1 Implement the collector runner
    - `Collector` interface, per-collector interval, 30s tick timeout, backoff-limited logging, `collector_status` recording, scrub then `Apply`, discard on guard failure or leak, other collectors continue
    - Wire the runner into `serve`, started only when the engine is enabled
    - _Requirements: 14.8, 14.11, 14.13, 14.14, 11.1, 11.10_

  - [x] 13.2 Host collector
    - `/proc` processes, `/proc/net/tcp*`, `/proc/net/udp*`, hostname -> `host`, `process`, `listening_port`; Linux build tag, no-op elsewhere; interval >= 5s
    - _Requirements: 14.1, 14.8, 14.10_

  - [x] 13.3 Docker collector
    - Read-only API subset over the Docker socket (list/inspect only) -> `container`, `image`, `network`, `volume`; keep env keys only, drop values; interval >= 30s; absent socket means no observations, no error log
    - _Requirements: 14.2, 14.3, 14.8, 14.12_

  - [x] 13.4 Codesec collector
    - Parse `package.json`, `bun.lock`, `go.mod`, `requirements.txt`, `.github/workflows/*.yml` -> `repository`, `dependency` (keyed by repo, name, range), `workflow`, `secret_ref`; fsnotify rescan within 5s; skip files > 1 MiB and `node_modules`, `.git`
    - _Requirements: 14.4, 14.7, 14.9_

  - [x] 13.5 IaC collector
    - Terraform `*.tf` and Kubernetes manifests -> `iac_resource`, `k8s_object`; relations without attributes
    - _Requirements: 14.5, 14.7_

  - [x] 13.6 Secrets collector
    - Rule-based scan emitting `secret_finding` with only `{path, line, rule_id, hash_prefix}`; `hash_prefix` is the first 8 lowercase hex chars of SHA-256; the value is discarded inside the scanner function
    - _Requirements: 14.6, 15.6_

  - [x]* 13.7 Write property test for no secret bytes in stored events
    - **Property 4: No secret bytes in stored events**
    - Generate files with secrets matching each pattern, run collect, scrub, apply, then scan raw log bytes for the secret and for substrings longer than 8 chars
    - **Validates: Requirements 14.13, 15.6, 15.7, 15.8**

  - [x]* 13.8 Write unit tests for collectors
    - Fixture `/proc` tree, fake Docker socket server, repo fixtures, platform no-op, timeout and failure status
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.10, 14.11, 14.12_

- [x] 14. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Graph HTTP API and MCP endpoint
  - [x] 15.1 Implement `internal/api/graph` handlers
    - `GET` `/entities`, `/entities/:id`, `/entities/:id/neighbors`, `/entities/:id/history`, `/changes`, `/diff`, `/schema`, `/status`
    - 404 for unknown entity, 400 for malformed id/limit/range, default limit 100, cap 1000 with the applied limit in the response, 503 `graph_unavailable` when disabled
    - `status` reports engine and TS child state (`degraded` included) and answers within 1s with no child
    - _Requirements: 4.10, 16.1, 16.4, 16.5, 16.6, 16.7, 16.8, 16.9_

  - [x] 15.2 Implement the MCP endpoint and bearer token
    - Per-start token from 32+ bytes of `crypto/rand`, memory only, constant-time compare; endpoint `/api/experimental/graph/mcp` accepts only that token (401 for password, session token, none); token rejected on every other route
    - _Requirements: 16.10, 16.11, 16.12, 18.6_

  - [x] 15.3 Wire graph routes into the front door
    - Flip owner to `go` for `experimental.graph.*` and the MCP endpoint in `routes.yaml`; the MCP route uses bearer auth, other graph routes use normal auth
    - Register handlers in `serve`; verify with curl through `:4096`
    - _Requirements: 2.5, 2.7, 16.2, 16.4_

  - [x]* 15.4 Write handler tests
    - 401/404/400 paths, limit clamping, status without child, MCP token matrix, audit failure behaviour
    - _Requirements: 16.4, 16.5, 16.6, 16.7, 16.8, 16.9, 16.10, 16.12, 16.14_

- [x] 16. Protocol contract, schema and SDK generation
  - [x] 16.1 Add graph wire schemas
    - Create `packages/schema/src/graph.ts` with `Graph.*` identifiers, `optional(...)` fields, no `Schema.Any`; export per package conventions; read `packages/schema/AGENTS.md` first
    - Add tests: one valid decode and one rejected value per schema
    - Run `bun typecheck` and tests from `packages/schema`
    - _Requirements: 17.3, 17.8, 17.9_

  - [x] 16.2 Add `ExperimentalGraphGroup`
    - Create `packages/protocol/src/groups/experimental-graph.ts` modelled on `experimental.ts`; ids `experimental.graph.<method>`, paths `/api/experimental/graph/...`, description "Experimental: may change without compatibility guarantees."; register in the protocol API
    - Run `bun typecheck` and tests from `packages/protocol`
    - _Requirements: 17.1, 17.2, 17.4_

  - [x] 16.3 Regenerate the client
    - Run `bun run generate` from `packages/client`; confirm `client.experimental.graph.*` exists and no hand edits; rerun and confirm no file changes; run `bun typecheck` in `packages/client`
    - Regenerate the route operation list so TS-declared graph operations are accounted for (owner `go`)
    - _Requirements: 17.5, 17.6, 17.7, 2.7_

  - [x]* 16.4 Write schema and identifier tests
    - Extend `experimental-identifiers` coverage check and add fast-check round trips for `Graph.*` schemas
    - _Requirements: 17.3, 17.4, 17.9_

- [ ] 17. Agent MCP wiring, skill, agent and feature flag
  - [x] 17.1 Add the `bellu_graph` flag
    - Add key and description in `packages/schema/src/config/flag.ts`; gate TS-side surfaces with `Flag.enabled("bellu_graph")` where they are registered
    - Run `bun typecheck` and tests in the touched packages
    - _Requirements: 19.6, 19.7_

  - [x] 17.2 Build the child config with `mcp.bellu-graph`
    - `internal/agentcfg`: build `OPENCODE_CONFIG_CONTENT` (compatibility name) with a remote `bellu-graph` entry (URL from the listen address, bearer header, `oauth: false`) conforming to `Mcp.RemoteConfig`; merge into a valid inbound object preserving other keys and `mcp` entries; refuse to start the child with an stderr error and non-zero exit on an invalid inbound value; omit the entry when the flag is off
    - Pass the config through `ChildConfig.Env` in `serve`
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.7_

  - [~] 17.3 Embed the `security-context` skill and `security` agent
    - Embed files; skill lists all MCP tool names and forbids requesting secret values
    - Without `OPENCODE_CONFIG_DIR`, write to a generated dir under `~/.config/bellucode/` and pass it as `OPENCODE_CONFIG_DIR` (compatibility name); with a user dir, leave it untouched and inject via `OPENCODE_CONFIG_CONTENT`; fall back to injection with a warning if the write fails
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 25.4_

  - [~]* 17.4 Write tests for config building and definitions
    - Merge cases, invalid inbound JSON, flag off, dir fallback paths, skill mentions every tool name, parse output against `Mcp.RemoteConfig` shape
    - _Requirements: 18.3, 18.4, 18.5, 18.7, 19.2, 19.5_

- [ ] 18. Web UI serving
  - [x] 18.1 Implement `internal/webui`
    - Asset FS from `go:embed` (release) or `BELLUCODE_WEB_DIST` (fail to start if set but unreadable, no fallback); GET/HEAD file else `index.html`; 404 `no-store` for missing `_assets/` and `icons/`; 405 for other methods; 404 when `index.html` is absent
    - Cache headers, brotli variants (never for `index.html`) with `vary`, `nosniff`, CSP with the sha256 of the `oc-theme-preload-script` inline script (omit when absent)
    - Mirror `packages/cli/src/services/web-ui.ts`
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8, 20.9, 20.10, 20.11, 20.12_

  - [~] 18.2 Wire the web UI as a public route
    - Serve before auth for unauthenticated `/`; `/api`, `/api/*`, `/auth/*`, `/openapi.json` stay on the API side
    - _Requirements: 1.7, 20.13, 20.14, 20.15_

  - [~]* 18.3 Write web UI tests
    - Fixture dist directory covering the status/header matrix, brotli, CSP digest, unreadable dist failure
    - _Requirements: 20.3, 20.4, 20.5, 20.8, 20.9, 20.11, 20.12, 20.15_

- [ ] 19. OpenAPI merge
  - [x] 19.1 Implement the merger
    - Fetch child `/openapi.json` with the internal credential (10s per attempt, up to 3 retries at 1s); add embedded Go-contract operations; drop `go`-owned operations still declared by the child so each method+path appears once; cache; discard on child restart
    - Build-time embedded Go contract document generated from the TS protocol group
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.5_

  - [~] 19.2 Serve `/openapi.json` from the cache
    - Respond from the cached document in under 100 ms; define the behaviour when all fetches fail per criterion 21.5
    - _Requirements: 21.5, 21.6_

  - [~]* 19.3 Write merger tests
    - Real httptest upstream: merge, dedupe, retry, failure, restart invalidation
    - _Requirements: 21.2, 21.3, 21.4, 21.5, 21.6_

- [x] 20. Migration and contract test harness
  - [x] 20.1 Capture TS fixtures
    - Bun script that records request/response fixtures from the real TS server into `internal/contract/testdata` (status, content type, body, SSE event sequences)
    - _Requirements: 22.3, 22.4, 22.9_

  - [x] 20.2 Implement `contract.Check`
    - Replay fixtures against a Go handler; check status, content type, schema validity (JSON Schema derived from `packages/protocol`), SSE payloads and event type sequence
    - _Requirements: 22.3, 22.4_

  - [x] 20.3 Owner gate test
    - Fail when a route group is `go` while any operation has a missing fixture or failing contract test; keep Stage 0 as only graph routes `go`; document the stage order; assert Go never opens `opencode-local.db` (compatibility name) and reads session data via the child API
    - _Requirements: 2.5, 22.1, 22.2, 22.6, 22.7, 22.8_

  - [-]* 20.4 Write property test for contract compatibility
    - **Property 13: Contract compatibility**
    - Run the same fixture set against the TS server and Go for every `go`-owned operation; flipping an operation does not change fixture status or schema validity
    - **Validates: Requirements 22.1, 22.2, 22.3, 22.4, 22.5, 22.9**

  - [x] 20.5 Proxy latency benchmark
    - Go benchmark over >= 1,000 requests with bodies <= 4 KiB; fail if median added latency is >= 1 ms
    - _Requirements: 22.10_

- [~] 21. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 22. Operations, build and CI
  - [x] 22.1 Turbo build task
    - Add `services/bellud/package.json` with a `build` script running `go build -trimpath -o dist/bellud ./cmd/bellud`; depend on `packages/app#build` when embedding; failing step is reported; confirm `turbo.json` picks up the package/workspace
    - _Requirements: 24.1, 24.2, 24.3_

  - [x] 22.2 Root Makefile targets
    - Create `Makefile` with `bellud` (same output as 22.1) and `sync-graph` (runs the sync tool with `COMMIT=`)
    - _Requirements: 24.6_

  - [x] 22.3 systemd unit and operations docs
    - Add `services/bellud/ops/bellucode.service` (`Type=notify`, `KillMode=mixed`, `ExecStart=/usr/local/bin/bellud serve --hostname 127.0.0.1 --port 4096`, `EnvironmentFile` unchanged) and `services/bellud/README.md` covering install, rollback to the previous `ExecStart`, `daemon-reload`, restart and status verification; mark compatibility names
    - _Requirements: 23.1, 23.2, 23.5, 23.6, 25.5, 25.6_

  - [x] 22.4 CI checks
    - Add a workflow job: Go >= 1.26.9, `go mod verify`, checksum presence in `go.sum`, `govulncheck ./...`, six-way `GOOS/GOARCH` cross-compile, sync-tool leftover check, PR/commit title format rule
    - _Requirements: 24.4, 24.5, 24.8, 24.9, 24.10, 25.7_

- [~] 23. Final checkpoint - Ensure all tests pass
  - Run `go build ./... && go vet ./... && go test ./...` from `services/bellud`, `bun typecheck` and tests in `packages/schema`, `packages/protocol`, `packages/client`, and `bun run check` at the repo root.
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP.
- Each task references specific acceptance criteria for traceability.
- Checkpoints ensure incremental validation; each step leaves `go build ./...` green and `bellud serve` runnable.
- Property tests validate the 14 correctness properties; unit tests cover examples and edge cases.
- Task 9.6 pins the upstream SHA at implementation time; record it in `UPSTREAM.md` only.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["1.3", "3.1", "4.1", "5.1", "9.1", "12.1", "16.1"] },
    { "id": 3, "tasks": ["3.2", "3.3", "3.4", "4.2", "4.3", "4.4", "5.2", "6.1", "9.2", "12.2", "16.2", "17.1"] },
    { "id": 4, "tasks": ["6.2", "6.3", "6.5", "7.1", "9.3", "9.4", "9.5", "9.6", "12.3", "12.4", "16.3", "16.4"] },
    { "id": 5, "tasks": ["6.4", "7.2", "10.1", "18.1", "19.1", "20.1", "22.1", "22.2"] },
    { "id": 6, "tasks": ["7.3", "10.2", "20.2", "20.5", "22.3"] },
    { "id": 7, "tasks": ["10.3", "10.4", "10.5", "10.6", "10.7", "13.1", "20.3"] },
    { "id": 8, "tasks": ["13.2", "13.3", "13.4", "13.5", "13.6", "15.1", "15.2"] },
    { "id": 9, "tasks": ["13.7", "13.8", "15.3"] },
    { "id": 10, "tasks": ["15.4", "17.2", "20.4", "22.4"] },
    { "id": 11, "tasks": ["17.3"] },
    { "id": 12, "tasks": ["17.4", "18.2"] },
    { "id": 13, "tasks": ["18.3", "19.2"] },
    { "id": 14, "tasks": ["19.3"] }
  ]
}
```
