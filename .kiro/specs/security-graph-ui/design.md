# Design Document

## Overview

The Security Graph is a SolidJS feature in `packages/app/src/security-graph/`, gated by a `security_graph` flag. The projection engine, layout and renderer are framework-free TypeScript. Only the chrome (inspector, search, filters, breadcrumb, minimap, panels) is Solid, with state in `createStore`. The graph on screen is a projection of a persistent knowledge graph supplied by a `GraphSource`. It is never the source of truth. Language: TypeScript.

```
GraphSource (mock | bellud adapter seam)
   │ entities / relationships / boundaries / attackPaths / events
   ▼
Graphology graph (full, in memory, stable IDs)
   │            ▲ pinned positions (cache)
   ▼            │
Projection engine ── LOD cut + overrides ──► visible graph (nodes, lifted edges, paths)
   │                                              │
   ├── layout worker (ForceAtlas2, global)        ▼
   └── d3-force (local, on expand)        Sigma renderer + canvas overlay
                                                  ▲
Interaction machine (pure transition) ◄── thin driver (pointer, keys, rAF) ──► Solid chrome
```

## Flag and wiring

- Add `security_graph` to `registry` in `packages/schema/src/config/flag.ts` ("Enable the experimental Security Graph view.").
- `Flag.enabled` is a Core (server-side) call. The app cannot call it, so the app reads the flag the same way `settings/connectors/enabled.ts` does: from config entries (`experimental.security_graph`, `all_flags`) via a small `security-graph/enabled.ts`. The route and nav entry register only when it is on.
- Monaco is not shipped by the app, so the code view reuses the app's existing code viewer (`@bellucode/ui` file/code component, highlighted by `@pierre/highlights`). Task 5.5 picks the exact component.

## Module layout (`packages/app/src/security-graph/`)

| Path | Role |
| --- | --- |
| `model.ts` | Entity, Relationship, Boundary, AttackPath, Tag, Severity, AgentEvent types |
| `source.ts` | `GraphSource` interface; `mock/` generator (100/5k/50k) and simulated event stream; `bellud-adapter.ts` seam (types and doc only) |
| `theme.ts` | The one tokens file: dark and light palettes, node type colors/icons, severity scale, sizes, zoom thresholds |
| `projection/` | `hierarchy.ts` (d3-hierarchy), `lod.ts` (cut), `aggregate.ts` (severity, counts, tags), `lift.ts` (edge lifting), `paths.ts` (attack-path aggregation), `engine.ts` (public API) |
| `layout/` | `worker.ts` (ForceAtlas2), `local.ts` (d3-force for expansion), `anchor.ts` (radial placement, neighbor nudge), `hulls.ts` (d3-polygon) |
| `render/` | `sigma.ts`, node programs (icon circle, badge, ring), arrowhead edge program, `atlas.ts`, `overlay.ts` (pills, labels, edge labels, hulls), `animate.ts` (rAF + d3-interpolate) |
| `machine.ts` | Interaction state union and pure `transition` |
| `driver.ts` | Thin edge: DOM events to machine events, rAF, effects |
| `agents/` | `events.ts` (reducer from AgentEvent to highlight state), replay |
| `ui/` | Solid components: `graph-view.tsx`, `inspector.tsx`, `search.tsx`, `filters.tsx`, `breadcrumb.tsx`, `minimap.tsx`, `panels.tsx`, `export.ts` |
| `bench/bench.ts`, `README.md` | Benchmark script and docs |

Rules from the AGENTS files apply: no import aliases or star imports, no `any`, no literal font families (canvas uses the CSS variable value read once from `getComputedStyle`), `--line-height-compact`/`--line-height-base` tokens in chrome, `Loader` for loading states, plain `overflow-y-auto` + `data-scrollable` for scrolling, all text through `language.t` keys added to `runtime/i18n/en.ts` (new keys only, `security.graph.*`).

## Data model

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info" | "remediated" | "validated"
type Relation = "uses" | "contains" | "calls" | "reads" | "writes" | "exposes" | "assumes" | "depends_on"
type Tag = { label: string; severity: "risk" | "info" }
type Entity = {
  id: string; type: EntityType; name: string; parentId?: string
  repo?: string; service?: string; env?: string; language?: string
  severity?: Severity; tags: Tag[]; boundaryId?: string
  sourceLocation?: { path: string; line: number }
  metadata: Record<string, string | number | boolean>
  provenance: { source: string; observedAt: number }
}
type Relationship = { id: string; source: string; target: string; relation: Relation; directed: true; metadata: Record<string, string | number | boolean> }
type Boundary = { id: string; label: string; memberIds: string[]; parentId?: string }
type AttackPath = { id: string; steps: string[]; entry: string; target: string; severity: Severity; evidence: string[]; remediation: string }
type AgentEvent = { agentId: string; type: "visit" | "traverse" | "finding" | "tool_call"; entityId: string; edgeId?: string; ts: number }
interface GraphSource {
  load(size: "100" | "5k" | "50k"): Promise<GraphData>
  events(): AsyncIterable<AgentEvent> & { simulated: boolean }
  subscribe(onDelta: (delta: GraphDelta) => void): () => void
}
```

Credentials are modelled as references (`metadata.secretRef`), never values. `Entity.parentId` is the containment hierarchy; areas (L1) are the roots.

## Projection engine

Pure, synchronous, framework-free. Input: full Graphology graph, `zoom`, `overrides: Map<id, "expanded" | "collapsed">`. Output: `Visible { nodes, edges, paths }`.

1. **Hierarchy.** d3-hierarchy builds from `parentId`; each node stores depth and descendant list (computed once per data change).
2. **LOD cut.** Zoom thresholds map to a target depth (L1=0, L2=1, L3=2, L4=leaf). Walk from the roots: a node is a leaf of the cut if its depth equals the target depth, unless an override says otherwise. An override on a node applies to that subtree only and beats the automatic depth.
3. **Aggregation.** A collapsed node gets `severity = max(descendants)` by Severity_Scale rank, `count = descendants.length`, and the union of its descendants' risk tags (deduplicated by label, with a per-label count).
4. **Edge lifting.** Each relationship maps both endpoints to their visible ancestor (the node itself if visible). If both map to the same node, the edge is internal and dropped. Otherwise edges are grouped by `(visibleSource, visibleTarget, relation)` into one Lifted_Edge with `count`. A group of one keeps the real edge ID, so IDs are stable at L4.
5. **Attack paths.** Each step's endpoints map to visible ancestors; consecutive steps that collapse into the same pair merge, internal steps vanish. The result is a chain of aggregated segments that splits back into real steps as the cut deepens.
6. **Incremental updates.** `applyDelta(delta)` adds entities and relationships to the Graphology graph and invalidates only affected hierarchy branches. Existing positions are never touched. A new node gets a position near its parent, or the mean of its placed neighbors, plus a small deterministic offset from its ID hash.

Positions live on the Graphology nodes (`x`, `y`) and in a position cache keyed by Entity ID. Collapsed parents keep their own position (the spatial anchor). Children keep their last cached position so a collapse followed by an expand restores them.

## Layout

- **Global:** ForceAtlas2 (`graphology-layout-forceatlas2`) in a Web Worker on the first load only. The worker receives node/edge arrays and returns a `Float32Array` of positions. The main thread never runs it. Positions are cached; later interactions never rerun it.
- **Local expansion:** on expand, children start at the parent position and move outward with d3-force (radial for few children, link+collide for many) for a fixed tick budget. Only the subtree is simulated; parent is fixed. Neighbors overlapping the new footprint get a one-step push along the vector from the parent, scaled by the overlap, and only if needed. elkjs is added only if d3-force output proves unreadable (not planned).
- **Collapse:** children animate back to the parent position, then leave the visible set.
- **Animation:** `animate.ts` runs one rAF loop with d3-interpolate over positions and opacity; the camera is not moved by expand/collapse.
- **Boundaries:** `hulls.ts` computes a d3-polygon convex hull (padded; circle for fewer than 3 members) from visible member positions each frame the members move; nested boundaries pad by depth.

## Rendering

- Sigma.js on Graphology. Custom node programs: icon circle (atlas sprite), count badge, ring (external third-party). A custom arrowhead edge program draws 1px straight or lightly curved edges.
- LOD in the renderer: far = colored dots; medium (zoom above threshold A) = icons and badges; close (above threshold B) = labels, pills, edge labels. Thresholds live in `theme.ts`.
- Canvas overlay: one 2D canvas above Sigma. For each in-viewport node (viewport culling via Sigma's camera bounds) above threshold B, draw two-line label, tag pills (stacked at top-right) and edge labels rotated along the edge with a background halo. No DOM per node.
- Hover/selection: a `focus` set (node, neighbors, edges) is passed to the node and edge reducers; everything else gets alpha 0.15.
- Atlas: `atlas.ts` rasterizes line icons, language icons and brand logos (Stripe, Auth0, OpenAI) into one texture at startup.
- Severity uses color plus a shape or icon per level so it is not color-only.
- Theme: `theme.ts` holds `dark` and `light` token sets (canvas `#0B0F17`/white, dot grid ~24px) and type colors (API `#2F4C8F`, Module/Service `#14BFA6`, Dependency `#8B5CF6`, Data model `#FBA91A`, Framework mint-teal, plus tokens for the remaining types). Dark pills use translucent equivalents. Chrome components read CSS variables derived from it.

## Interaction machine

`machine.ts` exports one union and a pure `transition(state, event): { state, effects }` returning the same object when nothing changes.

```ts
type State =
  | { type: "idle" }
  | { type: "hovering"; id: string }
  | { type: "panning" }
  | { type: "dragging"; id: string }
  | { type: "selected"; id: string; hover?: string }
  | { type: "focused"; id: string }
  | { type: "animating"; kind: "expand" | "collapse" | "focus"; id: string; next: State }
type Event =
  | { type: "hover"; id?: string } | { type: "click"; id: string; badge: boolean } | { type: "dblclick"; id: string }
  | { type: "pan-start" } | { type: "pan-end" } | { type: "drag-start"; id: string } | { type: "drag-end" }
  | { type: "anim-done" } | { type: "back" } | { type: "forward" } | { type: "reset" } | { type: "fit" }
  | { type: "escape" }
type Effect = { type: "expand" | "collapse" | "select" | "focus" | "fit" | "reset"; id?: string }
```

History (back/forward) is part of the machine's context, kept in a second field of the transition result's owner (`{ state, history }`), so the pure function is the single owner. The driver (`driver.ts`) translates pointer, wheel, key and rAF events into machine events and runs effects (calls to the projection engine, camera, animation). Solid reads state through selectors only.

## Agents and attack paths

- `agents/events.ts` is a pure reducer: `(AgentState, AgentEvent) → AgentState`, holding the highlighted entity, lit edges (with the event `ts` for fade-out), current task per agent and findings per entity. Replaying the same events in order yields the same state. A `finding` event adds a tag and evidence to the entity via an incremental delta.
- The mock stream is a deterministic generator over mock entities and is labelled "Simulated" in the Activity panel header (`security.graph.agents.simulated` key). No motion occurs without an event.
- Show attack path: BFS for the shortest path and bounded DFS (depth ≤ 8, ≤ 50 paths) over risky relations (`exposes`, `calls`, `assumes`, `reads`, `writes`) from an entity tagged Internet Exposed to entities tagged PII or Sensitive. Results become transient `AttackPath` records.
- Boundary crossings: a step whose endpoints are in different boundaries where one is untrusted gets a crossing marker drawn on the edge midpoint.

## Chrome (Solid)

Components read one `createStore` per view (selection, filters, search query, panel sizes, size toggle). Filters are applied before projection (hide nodes, then lift). Search uses a prebuilt lowercase name index; selecting a result sets overrides expanding its ancestors and moves the camera. The breadcrumb comes from the ancestor chain. The minimap draws visible node dots on a small canvas with the viewport rectangle. Export: PNG via `canvas.toBlob` of composited layers, SVG built from the visible graph, JSON of the visible projection. Panels use the app's existing resize handle pattern with keyboard-operable separators. Loading uses `Loader`; the Inspector scrolls with `overflow-y-auto` and `data-scrollable`.

## Library decision

| Library | Decision | Reason |
| --- | --- | --- |
| Sigma.js + Graphology | Chosen | WebGL, handles 50k nodes / 100k edges, custom programs give full styling control, Graphology gives the data model and algorithms |
| Cytoscape.js | Rejected | Canvas renderer too slow at 50k nodes; compound nodes exist but expand/collapse and styling at scale are limited |
| AntV G6 | Rejected | Combos support grouping, but styling control is more limited than custom WebGL programs and large-graph rendering is slower |
| Cosmograph | Rejected | Very fast GPU layout, but no compound nodes and limited styling (no icons, pills or labels) |
| Reagraph | Rejected | Built on React and three.js; not Solid, and too slow past a few thousand nodes |
| deck.gl | Rejected | Powerful renderer, but graph semantics (hierarchy, labels, edges with arrowheads) must be built from scratch with no benefit over Sigma programs |
| React Flow | Rejected | React, DOM node per element, no compound expand/collapse at scale |

## Error handling

- `GraphSource.load` failure: the view shows an error state with a retry action (machine-free; a small load state union `loading | ready | failed` in the view store).
- WebGL unavailable: show an error message from an i18n key; no fallback renderer.
- Delta referencing an unknown parent: the entity attaches to its area root and the provenance notes the orphan; it is not dropped.
- Event referencing an unknown entity or edge: the reducer ignores it and keeps state unchanged.
- Worker error: layout falls back to cached positions or, for a first load, to a deterministic grid, and shows a warning.

## Testing strategy

Only two suites, both `bun test` from `packages/app`, with no mocks, no timing assertions, and real graphs built by small in-test helpers: `projection/engine.test.ts` and `machine.test.ts`. Rendering, UI, layout and performance are not unit-tested; the benchmark script logs timings. The tests follow the `unit-tests` skill: no sleeps, no wall-clock assertions.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Stable identity across levels

For any graph, zoom level and set of manual overrides, every visible node ID is an Entity ID of the full graph, and every visible edge ID is either a Relationship ID of the full graph or a Lifted_Edge ID derived from visible endpoints and a relation.

**Validates: Requirements 2.1, 3.5**

### Property 2: Override beats the cut

For any graph, zoom and override on a node, the visible descendants of that node match the override (expanded shows its children, collapsed hides all descendants) regardless of zoom, and nodes outside the subtree are unaffected.

**Validates: Requirements 2.3, 2.4**

### Property 3: Aggregates equal descendant folds

For any collapsed node, its severity is the maximum Severity_Scale rank of its descendants, its count equals its descendant count, and its risk tags are the union of descendant risk tags.

**Validates: Requirements 3.2**

### Property 4: Edge lifting conserves relationships

For any graph and any collapse, no visible edge has both endpoints inside the collapsed subtree, and the sum of Lifted_Edge counts for the subtree plus the dropped internal edges equals the number of Relationships touching the subtree.

**Validates: Requirements 3.3, 3.4**

### Property 5: Expand and collapse round trip

For any graph and any node, collapsing then expanding it yields the same visible node and edge IDs as before, and the children return to their cached positions.

**Validates: Requirements 3.1, 3.5**

### Property 6: Expand moves only the subtree

For any graph and expanded node, the position of every visible node outside the subtree, other than neighbors nudged for overlap, is unchanged.

**Validates: Requirements 3.1, 3.6**

### Property 7: Attack-path aggregation and splitting

For any Attack_Path and any visible cut, every aggregated segment connects visible ancestors of real step endpoints, and with all nodes expanded the segments equal the real steps in order.

**Validates: Requirements 8.3, 8.4**

### Property 8: Incremental updates preserve positions

For any graph with positions and any delta, every existing node keeps its position, and each new node is placed within a bounded distance of its parent or placed neighbors.

**Validates: Requirements 9.1, 9.2**

### Property 9: Interaction transitions are total and history-consistent

For any state and event, `transition` returns a valid state; for any event sequence, back followed by forward restores the prior history entry, and an event that changes nothing returns the same state object.

**Validates: Requirements 4.1, 4.2, 4.3, 4.4**

### Property 10: Agent replay is deterministic

For any ordered Agent_Event list, reducing it twice produces equal agent state.

**Validates: Requirements 7.5**
