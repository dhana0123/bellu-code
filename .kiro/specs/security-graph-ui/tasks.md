# Implementation Plan: Security Graph UI

## Overview

Build the Security Graph in `packages/app/src/security-graph/` bottom-up: model, mock data and theme; the projection engine and its tests; the layout worker and renderer; the interaction machine and its test; the Solid chrome; agents and attack paths; the benchmark script and README. The renderer and projection engine are framework-free TypeScript. Only the chrome uses Solid, with `createStore`.

Rules for every task:
- Run commands from `packages/app`, never from the repo root. Never restart services. The web build is `cd packages/app && bun run build`; never run `vite build --watch`.
- Follow `AGENTS.md` and `packages/app/AGENTS.md`: no import aliases, no star imports, no `any`, no literal font families, line-height tokens, `Loader` for loading states, plain `overflow-y-auto` with `data-scrollable` for scrolling.
- Every user-visible string is an English key in `runtime/i18n/en.ts`. Task 1.1 adds all `security.graph.*` keys up front. Later tasks use them and do not edit `en.ts` (if a key is missing, add it in a task that runs in a later wave than any other `en.ts` editor).
- Before writing a test, read `.bellucode/skills/unit-tests/SKILL.md`. Tests use `bun test`, no mocks, no sleeps, no wall-clock assertions. There are no e2e or visual tests.
- Do not add test tasks beyond 2.4 and 4.2.

## Tasks

- [ ] 1. Model, mock data and theme
  - [x] 1.1 Add the feature flag, enable check and i18n keys
    - Add `security_graph` to `registry` in `packages/schema/src/config/flag.ts`.
    - Create `security-graph/enabled.ts` that reads the flag from config entries, following `settings/connectors/enabled.ts`.
    - Add all `security.graph.*` keys (nav title, toolbar, inspector sections and actions, filters, tooltips, breadcrumb, activity panel, "Simulated" label, severity names, tag labels, relation names, boundary captions, error and empty states) to `runtime/i18n/en.ts`. Do not rename existing keys.
    - _Requirements: 1.1, 1.5, 6.10_
  - [x] 1.2 Define the model and `GraphSource` interface
    - Create `model.ts` (Entity, Relationship, Boundary, AttackPath, Tag, Severity, AgentEvent, GraphDelta) and `source.ts` (`GraphSource`).
    - Add `bellud-adapter.ts` with the adapter seam types and a doc comment only.
    - _Requirements: 1.2, 1.6, 2.6_
  - [x] 1.3 Implement the mock graph generator
    - Create `mock/generator.ts` with deterministic, seeded generation at 100, 5,000 and 50,000 nodes across the nine L1 areas, with boundaries and attack paths.
    - Include the reference sample: `/login` API, `Lim.API` module, `log4j:log4j 1.2.12` (Critical CVE), PII data model, Stripe/Auth0/OpenAI in "Untrusted boundaries", Written-to-log relationship, Internet Exposed and Sensitive Logic tags, and an internet-to-PII attack path.
    - _Requirements: 1.3, 1.4_
  - [x] 1.4 Create the theme tokens file
    - Create `theme.ts` with dark and light palettes, node type colors and icon ids, the severity scale with shapes, pill styles, sizes and zoom thresholds.
    - Take font families from CSS variables, with no literal family.
    - _Requirements: 6.1, 6.8, 6.9_
  - [x] 1.5 Implement the simulated agent event stream
    - Create `mock/stream.ts`: a deterministic, replayable `AsyncIterable<AgentEvent>` over the mock entities, flagged `simulated: true`.
    - _Requirements: 1.5, 7.4_

- [x] 2. Projection engine
  - [x] 2.1 Implement hierarchy and LOD cut
    - Create `projection/hierarchy.ts` (d3-hierarchy from `parentId`) and `projection/lod.ts` (zoom to depth, cut, manual overrides).
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [x] 2.2 Implement aggregation and edge lifting
    - Create `projection/aggregate.ts` (max severity, count, risk tag union) and `projection/lift.ts` (visible-ancestor mapping, internal edges dropped, Lifted_Edge counts, stable IDs).
    - _Requirements: 3.2, 3.3, 3.4, 3.5_
  - [x] 2.3 Implement attack-path aggregation, deltas and the engine API
    - Create `projection/paths.ts` (collapse and split of path steps) and `projection/engine.ts` (`project`, `applyDelta` with pinned positions and new-node placement).
    - _Requirements: 8.3, 8.4, 9.1, 9.2_
  - [x] 2.4 Write unit tests for the projection engine
    - `projection/engine.test.ts`: LOD cut, expand/collapse, edge lifting with counts, severity aggregation, attack-path aggregation, stable IDs through expand/collapse, incremental updates keep positions.
    - **Properties 1, 2, 3, 4, 5, 7, 8**
    - **Validates: Requirements 2.1, 2.3, 2.4, 3.2, 3.3, 3.4, 3.5, 8.3, 8.4, 9.1, 9.2**

- [ ] 3. Layout worker and renderer
  - [x] 3.1 Implement the global layout worker
    - Create `layout/worker.ts` (ForceAtlas2, returns a `Float32Array`) and a main-thread client with position caching.
    - _Requirements: 10.3_
  - [x] 3.2 Implement local expansion layout and anchoring
    - Create `layout/local.ts` (d3-force on the expanded subtree, parent fixed) and `layout/anchor.ts` (radial start, minimal neighbor nudge).
    - _Requirements: 3.1, 10.4_
  - [x] 3.3 Implement trust-boundary hulls
    - Create `layout/hulls.ts` with d3-polygon convex hulls, circle fallback, nesting padding and member-follow.
    - _Requirements: 6.7_
  - [x] 3.4 Build the texture atlas and Sigma programs
    - Create `render/atlas.ts` (icons, language icons, Stripe/Auth0/OpenAI logos) and the icon-circle, count-badge and ring node programs plus the arrowhead edge program.
    - _Requirements: 6.2, 6.3, 6.5, 10.1, 10.5_
  - [x] 3.5 Implement the Sigma renderer and canvas overlay
    - Create `render/sigma.ts` (LOD tiers, hover/selection fade to 15%, viewport culling) and `render/overlay.ts` (two-line labels, stacked pills, rotated edge labels with halo, hulls and captions, only for in-viewport nodes above the threshold).
    - _Requirements: 6.2, 6.4, 6.5, 6.6, 6.7, 10.2_
  - [x] 3.6 Implement the expand/collapse animation
    - Create `render/animate.ts` with one rAF loop and d3-interpolate over positions and opacity; the camera stays fixed.
    - _Requirements: 3.6_

- [x] 4. Interactions and state machine
  - [x] 4.1 Implement the interaction machine
    - Create `machine.ts`: the state union, events, effects, history and the pure `transition`; return the same object when nothing changes.
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - [x] 4.2 Write unit tests for the machine transition
    - `machine.test.ts`: replay event sequences for click, badge click, double-click focus, pan and drag, animation completion, back/forward, reset and escape, plus same-object returns for no-op events.
    - **Property 9**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4**
  - [x] 4.3 Implement the driver and graph view
    - Create `driver.ts` (wheel, pinch, drag-pan, double-click, keyboard, effects to engine and camera) and `ui/graph-view.tsx` (mounts Sigma and overlay, source toggle 100/5k/50k, zoom controls, fit-to-screen, reset view, `Loader` while loading, error state).
    - _Requirements: 1.3, 3.6, 4.5, 4.6, 5.5_

- [x] 5. Inspector, search, filters, breadcrumb, minimap, export and panels
  - [x] 5.1 Create the view store and Inspector
    - Create `ui/store.ts` (`createStore` for selection, focus, filters, search, panel sizes) and `ui/inspector.tsx` with all sections and the four actions (Ask AI agent, Generate fix, Validate fix, Open in editor). Use the app's existing code viewer for source locations, since Monaco is not shipped.
    - _Requirements: 2.5, 5.4_
  - [x] 5.2 Implement search and breadcrumb
    - Create `ui/search.tsx` (autocomplete from a name index; selecting expands ancestors and centers the camera) and `ui/breadcrumb.tsx` (ancestor chain, back/forward).
    - _Requirements: 4.4, 5.1, 5.2_
  - [x] 5.3 Implement filters
    - Create `filters.ts` (pure predicate by repository, service, environment, node type, tag, severity, trust boundary, agent) and `ui/filters.tsx`.
    - _Requirements: 5.3_
  - [x] 5.4 Implement the minimap and hover tooltip
    - Create `ui/minimap.tsx` (visible dots and viewport rectangle on a small canvas) and `ui/tooltip.tsx`.
    - _Requirements: 5.5_
  - [x] 5.5 Implement export
    - Create `ui/export.ts` for PNG (composited canvases), SVG (visible graph) and JSON (visible projection).
    - _Requirements: 5.6_
  - [x] 5.6 Compose docked panels and register the route
    - Create `ui/panels.tsx` (resizable, keyboard-operable separators; graph as primary surface; editor, terminal and AI activity panel reachable) and register the route and nav entry only when `enabled.ts` says the flag is on.
    - _Requirements: 1.1, 5.7_

- [x] 6. Agents and attack paths
  - [x] 6.1 Implement the agent event reducer
    - Create `agents/events.ts`: a pure reducer for highlight, lit edges, current task per agent and findings per entity; ignore unknown IDs.
    - _Requirements: 7.2, 7.3, 7.4, 7.5_
  - [x] 6.2 Implement the Activity panel and event-driven highlights
    - Create `ui/activity.tsx` (task list, "Simulated" label for the mock stream) and connect reducer state to the renderer's highlight and edge-illumination hooks; agents appear as cluster, five agents, then deep entities by level.
    - _Requirements: 1.5, 7.1, 7.2, 7.3, 7.4_
  - [x] 6.3 Implement attack-path search and boundary crossings
    - Create `projection/attack-paths.ts` (shortest path and bounded all-risky-paths from Internet Exposed to PII/Sensitive entities) and crossing markers on untrusted boundaries in `render/overlay.ts`.
    - _Requirements: 8.2, 8.5_
  - [x] 6.4 Add the attack-path UI
    - Add "Show attack path" to the Inspector and path details (entry, intermediate resources, identity and permission edges, target, evidence, risk explanation, remediation); end-to-end highlight on selection.
    - _Requirements: 8.1, 8.2_

- [x] 7. Benchmark script and README
  - [x] 7.1 Write the benchmark script
    - Create `bench/bench.ts`, run with `bun run security-graph/bench/bench.ts` from `packages/app` (add a `bench:security-graph` script to `package.json`). For 100, 5,000 and 50,000 nodes, log projection time, layout time and an FPS-proxy (frames per second of a scripted pan/zoom in headless Chromium) to the terminal.
    - Print a note that the server has no GPU (software rendering), so the numbers are a floor.
    - _Requirements: 10.7_
  - [x] 7.2 Write the README
    - Create `security-graph/README.md`: setup (flag, running the app), architecture summary, the bellud adapter seam, the viewport- and level-scoped projection API shape, and an extension guide for new node types, tags, zoom levels and agent events.
    - _Requirements: 1.6, 10.6_

- [x] 8. Final checkpoint
  - Run from `packages/app`: `bun typecheck`, `bun run build`, and the two test files. Then run `bun run check` from the repository root. Fix failures. Do not restart any service.
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Only 2.4 and 4.2 are tests, and both are required. Rendering, UI and performance are not unit-tested.
- Property 6 (expand moves only the subtree) and Property 10 (agent replay) are design properties with no test task, by decision.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.4"] },
    { "id": 1, "tasks": ["1.3", "1.5", "2.1"] },
    { "id": 2, "tasks": ["2.2", "3.1", "3.2", "3.3", "3.4", "4.1", "6.1"] },
    { "id": 3, "tasks": ["2.3", "3.5", "3.6", "4.2"] },
    { "id": 4, "tasks": ["2.4", "4.3", "6.3"] },
    { "id": 5, "tasks": ["5.1", "5.4", "5.5", "6.2", "7.1"] },
    { "id": 6, "tasks": ["5.2", "5.3", "6.4"] },
    { "id": 7, "tasks": ["5.6"] },
    { "id": 8, "tasks": ["7.2"] }
  ]
}
```
