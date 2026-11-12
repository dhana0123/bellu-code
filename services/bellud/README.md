# bellud

`bellud` is the Go front door for bellucode. It listens on `:4096` (default `127.0.0.1`), owns the Go routes (currently `experimental.graph.*` and the graph MCP endpoint), runs the embedded Bellu Graph Engine in-process, and spawns the TypeScript server (`packages/cli`) as a loopback-only child. It reverse-proxies every route it does not own, including SSE and WebSocket.

## Build

```sh
bun run --cwd services/bellud build   # go build -trimpath -o dist/bellud ./cmd/bellud
make bellud                           # same output; make may not be installed
bun run --cwd services/bellud build:embed   # also embeds packages/app/dist
bun run --cwd services/bellud test
```

Go is looked up in `/usr/local/go/bin` if it is not on `PATH`. Output: `services/bellud/dist/bellud`.

## Configuration

| Variable | Purpose |
| --- | --- |
| `BELLUCODE_PASSWORD` | Basic auth password. |
| `BELLUCODE_PASSWORD` | Compatibility name. Fallback when `BELLUCODE_PASSWORD` is unset. |
| `BELLUCODE_HOSTNAME`, `BELLUCODE_PORT` | Listen address (flags `--hostname`, `--port` also work). |
| `BELLUCODE_CORS` | Allowed CORS origins. |
| `BELLUCODE_WEB_DIST` | Read web assets from disk (dev) instead of the embedded copy. |
| `BELLUCODE_REPO` | Repo root, used to find `packages/cli` for the child server. |
| `BELLU_GRAPH_ENABLED`, `BELLU_GRAPH_DIR`, `BELLU_GRAPH_OTLP_LISTEN`, `BELLU_GRAPH_RETENTION`, `BELLU_GRAPH_LOG_LEVEL` | Graph engine. |

Compatibility names kept on purpose: the `bellucode` basic-auth username, the auth cookie name and HMAC context, `BELLUCODE_PASSWORD`, and the `BELLUCODE_CONFIG_CONTENT` / `BELLUCODE_CONFIG_DIR` variables passed to the child.

Data and config:

- Graph data: `~/.local/share/bellucode/graph` (mode 0700)
- Generated config: `~/.config/bellucode/generated`
- Environment file for the service: `~/.config/bellucode/env` (the unit uses the absolute path, since systemd does not expand `~`)

## Install (systemd)

The unit lives in `ops/bellucode.service`. It keeps the same user, working directory, `EnvironmentFile` and name as the current unit, and changes `ExecStart` to bellud with `Type=notify` and `KillMode=mixed`.

```sh
bun run --cwd services/bellud build
sudo install -m 0755 services/bellud/dist/bellud /usr/local/bin/bellud
sudo cp /etc/systemd/system/bellucode.service /etc/systemd/system/bellucode.service.bak
sudo install -m 0644 services/bellud/ops/bellucode.service /etc/systemd/system/bellucode.service
sudo systemctl daemon-reload
sudo systemctl restart bellucode
```

## Rollback

Restore the previous unit, whose `ExecStart` was `/home/ubuntu/.bun/bin/bun run src/index.ts serve --hostname 127.0.0.1 --port 4096`:

```sh
sudo cp /etc/systemd/system/bellucode.service.bak /etc/systemd/system/bellucode.service
sudo systemctl daemon-reload
sudo systemctl restart bellucode
```

If no backup exists, edit the unit: set that `ExecStart`, remove `Type=notify`, `KillMode=mixed` and `BELLUCODE_REPO`, then run the two commands above.

## Verify

```sh
systemctl status bellucode
journalctl -u bellucode -n 100 --no-pager
curl -u bellucode:<password> http://127.0.0.1:4096/api/info
```

`systemctl status` should show `active (running)`. `/api/info` should return JSON. A wrong or missing password returns 401.

## Bellu Graph Engine

The engine is original in-tree code under `internal/bellugraph/internal/bge`, used through the `internal/bellugraph` facade. It runs inside bellud.

Features: append-only event log, bi-temporal as-of reads, history/diff/flapping, search, path and impact queries, endpoint resolution, 12 MCP tools plus resources and prompts, GraphQL, SSE subscribe, a debug UI, OTLP ingest, snapshots and retention, and metrics.

Routes live under `/api/experimental/graph`: `mcp`, `graphql`, `subscribe`, `debug`, `metrics`, `batches` and the read endpoints.

Token roles:

- `read`: all read routes.
- `ingest`: `POST /batches` only.
- `write`: held by bellud itself (front-door requests).

bellud rewrites `~/.local/share/bellucode/graph-tokens.json` (mode 0600) on every start. It holds the read and ingest tokens for collectors.

Config: `BELLU_GRAPH_ENABLED`, `BELLU_GRAPH_DIR`, `BELLU_GRAPH_OTLP_LISTEN`, `BELLU_GRAPH_RETENTION`, `BELLU_GRAPH_LOG_LEVEL`.

### Upgrade note

Before the first start of this version, delete `~/.local/share/bellucode/graph`. Copy `audit.jsonl` out first if you need it. Collectors rebuild the graph, and entity IDs change once.
