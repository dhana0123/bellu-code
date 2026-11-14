# Security Graph

An experimental page that draws a security knowledge graph (code, services, dependencies, data, cloud resources, external APIs, security controls and AI agents) with semantic zoom. The graph on screen is a projection of a full in-memory graph that a `GraphSource` supplies. The projection is never the source of truth.

Today the only source is a deterministic mock (100, 5,000 or 50,000 nodes) with a simulated agent event stream. Nothing is built server-side.

## Setup

### Enable the flag

The page is gated by the `security_graph` flag (`packages/schema/src/config/flag.ts`). Enable it in config with either:

```json
{ "experimental": { "security_graph": true } }
```

or `experimental.all_flags: true`. An explicit `experimental.security_graph: false` wins over `all_flags`.

The app cannot call Core's `Flag.enabled`. `enabled.ts` reads the flag from the config entries returned by `config.get()`, and `available.ts` runs that check per server. As a result, `BELLUCODE_FLAGS` and the build default (on in local and dev builds, off in releases) do not show the page. Only config entries do.

### Where it appears

Home > Security > Knowledge graph (`home/route.tsx` loads `ui/panels.tsx` lazily when the flag is on for the selected server).

### Run the app

Follow `packages/app/AGENTS.md`, Local Dev. Run the backend and the app dev server separately, and do not restart a service that is already running:

```sh
# repository root
bun dev serve --port 4096
# packages/app
bun dev -- --port 4444
```

Open `http://localhost:4444`. Use the 100 / 5k / 50k toggle in the toolbar to switch mock sizes.

## Architecture

The projection engine, layout and renderer are framework-free TypeScript. Only the chrome under `ui/` is Solid, with `createStore`.

```
GraphSource (mock | bellud adapter seam)
   │ entities, relationships, boundaries, attack paths, events, deltas
   ▼
Projection engine ── LOD cut + overrides ──► Visible { nodes, edges, paths, boundaries }
   │                                              │
   ├── layout (ForceAtlas2 worker, d3-force)      ▼
   └── position cache                      Sigma renderer + canvas overlay
                                                  ▲
Interaction machine (pure) ◄── driver.ts ─────────┘ ◄──► Solid chrome (ui/)
```

### Module map

| Path | Role |
| --- | --- |
| `model.ts` | `Entity`, `Relationship`, `Boundary`, `AttackPath`, `AgentEvent`, `GraphData`, `GraphDelta`; `entityTypes`, `severities`, `relations`, area ids |
| `source.ts` | `GraphSource` interface, `GraphSize`, `EventStream` |
| `bellud-adapter.ts` | Types only: `ProjectionQuery`, `BelludGraphAdapter`. No implementation |
| `enabled.ts`, `available.ts` | Flag check from config entries, and the per-server query that uses it |
| `theme.ts` | The one tokens file: palettes, node type colors and icon ids, severity scale and shapes, pill styles, sizes, zoom thresholds, `zoomLevel()` |
| `mock/generator.ts`, `mock/source.ts`, `mock/stream.ts` | Seeded graph generator (and the reference sample), the mock `GraphSource`, the replayable simulated agent stream |
| `projection/hierarchy.ts` | Containment tree from `parentId` (orphans attach to an area root) |
| `projection/lod.ts` | `targetDepth()` and `cut()`: visible nodes for a zoom level and overrides |
| `projection/aggregate.ts` | Severity, hidden-descendant count and risk-tag union for collapsed nodes |
| `projection/lift.ts` | Edge lifting to the visible cut |
| `projection/paths.ts` | Attack-path aggregation into segments over visible nodes |
| `projection/attack-paths.ts` | Shortest and bounded risky-path search |
| `projection/engine.ts` | `createEngine`: `project`, `expand`, `collapse`, `setOverride`, `applyDelta`, `search`, position cache |
| `layout/worker.ts`, `layout/client.ts`, `layout/compute.ts`, `layout/seed.ts` | Global ForceAtlas2 layout in a Web Worker and its main-thread client |
| `layout/local.ts`, `layout/anchor.ts` | d3-force layout of an expanded subtree, radial start and neighbor nudge |
| `layout/hulls.ts` | Trust-boundary hulls (d3-polygon) |
| `render/sigma.ts`, `render/types.ts` | Sigma renderer, LOD tiers, hover and selection fade |
| `render/programs/*` | Icon circle, count badge, ring and arrowhead edge programs |
| `render/atlas.ts` | Texture atlas for node, severity, language and brand icons |
| `render/overlay.ts` | 2D canvas overlay: labels, pills, edge labels, hulls, boundary captions, crossing markers |
| `render/animate.ts` | One rAF loop interpolating positions and opacity |
| `machine.ts` | Pure interaction `transition` with history |
| `driver.ts` | DOM events to machine events, effects to engine, camera and renderer |
| `filters.ts` | Pure filter predicate and option lists |
| `agents/events.ts`, `agents/driver.ts` | Pure agent event reducer; the driver that paces a stream and publishes snapshots |
| `ui/*` | Solid chrome: `graph-view`, `panels`, `inspector`, `search`, `breadcrumb`, `filters`, `minimap`, `tooltip`, `activity`, `attack-paths`, `export`, `export-menu`, `store` |
| `bench/` | `bench.ts`, `harness.ts`, `request.ts` |

## Semantic zoom

`zoomLevel(scale)` in `theme.ts` maps the camera scale to a level using `zoom.levels` (L1 = 0, L2 = 0.6, L3 = 1.4, L4 = 3; larger means closer). The levels are Global, Architecture, Component and Code and security.

### LOD cut

`lod.ts` `targetDepth()` gives the depth at which the cut stops: L1 = 0, L2 = 1, L3 = 2, L4 = leaves. `cut()` walks the hierarchy from the area roots. A node stays visible (and its descendants hidden) when it has no children, is overridden to `collapsed`, or has no override and its depth has reached the target.

### Manual overrides

An override (`expanded` or `collapsed`, set by `expand`, `collapse` or `setOverride`) beats the automatic depth for its own node, at any zoom. With overrides on both an ancestor and a descendant, the deepest one decides for its node. A collapsed ancestor hides the subtree, so overrides below it have no visible effect.

### Aggregation

A collapsed node shows the maximum severity of its descendants, its hidden descendant count, and the union of its descendants' risk tags with per-label counts. Only tags with `severity: "risk"` are aggregated.

### Edge lifting

`lift.ts` maps each relationship endpoint to the visible node that stands for it. If both map to the same node, the relationship is internal and dropped. The rest are grouped by (visible source, visible target, relation) into one lifted edge with a `count`. A group of one keeps the real relationship id. A larger group gets a derived id (`lift:<source>><target>:<relation>`), which is opaque and never parsed.

Known behavior: relationships that end on an expanded container are not drawn. An expanded container is not part of the visible cut, so it has no visible owner, and `lift()` skips (and does not count) any relationship with an endpoint that has no owner. Relationships between the container's children, or between a child and something outside, are drawn as usual. Filtered-out entities are skipped the same way.

### Attack paths

`paths.ts` maps each step's endpoints to visible ancestors, merges consecutive steps that collapse onto the same pair and drops internal steps. The chain splits back into the real steps as the cut deepens. `attack-paths.ts` finds paths from entities tagged `Internet Exposed` to entities tagged `PII` or `Sensitive`.

## GraphSource and the bellud adapter seam

All data enters through `GraphSource` (`source.ts`):

```ts
interface GraphSource {
  load(size: "100" | "5k" | "50k"): Promise<GraphData>
  events(): AsyncIterable<AgentEvent> & { simulated: boolean }
  subscribe(onDelta: (delta: GraphDelta) => void): () => void
}
```

`load` returns the whole graph, `events` the agent stream (`simulated: true` shows the "Simulated" label in the Activity panel), and `subscribe` pushes incremental `GraphDelta` updates. `engine.applyDelta` keeps existing positions and places new nodes near their parent or placed neighbors.

`bellud-adapter.ts` is the seam for the bellud graph (`bellu-graph-native`). It holds types only:

```ts
type ProjectionQuery = {
  level: 1 | 2 | 3 | 4
  viewport: { x: number; y: number; width: number; height: number }
  overrides: Record<string, "expanded" | "collapsed">
}
interface BelludGraphAdapter extends GraphSource {
  project(query: ProjectionQuery): Promise<GraphData>
  deltas(): AsyncIterable<GraphDelta>
  agentEvents(): AsyncIterable<AgentEvent>
}
```

A real adapter replaces the mock source. The engine and renderer do not change.

## Projection API (proposed, not built)

For graphs too large to load whole, the server would answer viewport- and level-scoped queries. This is a sketch that follows `ProjectionQuery`. No endpoint, schema or client exists, and nothing is built server-side. A real one would start under `/api/experimental/` per the repository's experimental API rules.

Request:

```json
{
  "level": 2,
  "viewport": { "x": -800, "y": -450, "width": 1600, "height": 900 },
  "overrides": { "area:backend": "expanded", "svc:auth": "collapsed" },
  "filters": { "severity": ["critical", "high"], "tag": ["Internet Exposed"] }
}
```

Response (`GraphData` for the visible part, with aggregates the client cannot compute from partial data):

```json
{
  "entities": [{ "id": "area:backend", "type": "cluster", "name": "Backend", "tags": [], "metadata": {}, "provenance": { "source": "bellud", "observedAt": 1700000000000 } }],
  "relationships": [{ "id": "lift:area:backend>area:database:reads", "source": "area:backend", "target": "area:database", "relation": "reads", "directed": true, "metadata": { "count": 12 } }],
  "boundaries": [],
  "attackPaths": [],
  "aggregates": { "area:backend": { "severity": "high", "count": 412, "tags": [{ "label": "Internet Exposed", "count": 3 }] } }
}
```

`filters` and `aggregates` are not in the current types. They are proposals for the server contract.

## Benchmark

From `packages/app`:

```sh
bun run bench:security-graph          # 100, 5k and 50k
bun run bench:security-graph 5k       # one or more sizes
```

For each size it logs generation, engine creation, projection time at L1 to L4 (cold and median of 5), expand and collapse, `applyDelta`, ForceAtlas2 layout time, and an FPS proxy: a scripted pan and zoom for 5 seconds in headless Chromium (`/usr/bin/chromium-browser`, via `@playwright/test`). The FPS step is skipped with a message when either is missing.

The server has no GPU, so Chromium renders in software and the FPS numbers are a floor, not what a user with a GPU sees. Rendering is not covered by tests.

## Extension guide

Add every user-visible string as an English key in `packages/app/src/runtime/i18n/en.ts` (`security.graph.*`). Do not add literal font families or colors outside `theme.ts`.

### Add a node type

1. `model.ts`: add the value to `entityTypes`.
2. `theme.ts`: add it to `NodeTypeKey` and to `nodeTypes` (`color` and `icon` id). `nodeTypes` is a `Record<NodeTypeKey, ...>`, so the compiler flags a missing entry.
3. `render/atlas.ts`: add the icon id to `lineIcons` (or a colored mark). The atlas is built from `nodeTypes`, so an icon id without a drawing stays blank.
4. `runtime/i18n/en.ts`: add `security.graph.tooltip.kind.<type>`. The tooltip, Inspector and search read this key.
5. `projection/engine.ts`: if entities of this type can lose their parent, add the area it falls back to in `typeArea`.
6. `mock/generator.ts`: generate entities of the type and attach them under a parent so they show in the mock.

### Add a tag

Tags are data. Put `{ label, severity: "risk" | "info" }` in an entity's `tags`; there is no tag registry.

- Pill style comes from `severity` only: `pills[mode].risk` or `.neutral` in `theme.ts`. Change those entries to restyle, or extend the mapping in `render/overlay.ts` if a label needs its own style.
- Only `risk` tags are aggregated onto collapsed nodes (`projection/aggregate.ts`).
- The filter panel lists tag labels found in the data (`filters.ts`), so a new label appears there without code changes.
- The label is shown as written. `security.graph.tag.*` keys exist in `en.ts` for the known labels; add one if a place should show a localized name.
- To produce it in the mock, add the label in `mock/generator.ts` (`riskTags` or a specific entity).

### Add a zoom level

1. `theme.ts`: add the key to `ZoomLevelKey` and its threshold to `zoom.levels`. Keep `zoomLevel()` ordered from closest to farthest.
2. `projection/lod.ts`: return its depth from `targetDepth()`.
3. `ui/graph-view.tsx`: add the level to the label map (`security.graph.zoom.l<n>`) and the zoom controls.
4. `runtime/i18n/en.ts`: add the `security.graph.zoom.l<n>` key.
5. Check the `level: 1 | 2 | 3 | 4` type in `bellud-adapter.ts` and any code that switches on `ZoomLevelKey` (`agents/events.ts` `AgentView`).

### Add an agent event type

1. `model.ts`: add the value to `AgentEvent["type"]`.
2. `agents/events.ts`: add it to the `execution` map (a `satisfies Record<AgentEvent["type"], ...>`, so a missing entry fails typecheck) and handle any new state in `reduce`. The reducer must stay pure and return the same state for unknown entities or edges.
3. `mock/stream.ts`: emit it in the simulated stream.
4. `ui/activity.tsx`: render it. The text key is `security.graph.activity.event.<type>`.
5. `agents/driver.ts`: handle any side effect (for example `finding` adds a tag to the entity).
6. `runtime/i18n/en.ts`: add `security.graph.activity.event.<type>`.

## Testing

Two test files, both `bun test`, with no mocks and no timing assertions:

- `projection/engine.test.ts`: LOD cut, overrides, aggregation, edge lifting, attack-path aggregation, stable ids, incremental updates.
- `machine.test.ts`: interaction `transition` sequences, history, and same-object returns for no-op events.

Run from `packages/app` (tests cannot run from the repository root):

```sh
bun test src/security-graph/projection/engine.test.ts src/security-graph/machine.test.ts
bun typecheck
```

Rendering, layout, UI and performance are not unit-tested. Use the benchmark for timings.
