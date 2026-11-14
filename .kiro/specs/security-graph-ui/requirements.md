# Requirements Document

## Introduction

Bellu Code Security Graph is an interactive, graph-native security visualization inside `packages/app` (SolidJS, UI only; no Neo4j/Memgraph and no server APIs). It lets a developer go from the whole system down to one vulnerable function without losing context. It uses semantic zoom: the representation changes by zoom level, over one graph. The rendered graph is a projection of a persistent security knowledge graph, not the source of truth. Data comes through a `GraphSource` interface with a mock generator now and an adapter seam for the existing bellud graph (`bellu-graph-native`) later.

## Glossary

- **Security_Graph**: The feature and its UI, located in `packages/app/src/security-graph/`.
- **Entity**: A graph node with a stable ID, a type, a name, and optional parent, severity, tags, boundary and provenance.
- **Relationship**: A directed edge with a stable ID and a relation (uses, contains, calls, reads, writes, exposes, assumes, depends_on).
- **Boundary**: A trust boundary or group with a label, member IDs and an optional parent boundary.
- **Attack_Path**: An ordered chain of Relationship IDs from an entry Entity to a target Entity, with severity, evidence and remediation.
- **Projection_Engine**: The framework-free TypeScript module that derives the visible nodes and edges from the full graph, the zoom level and the manual overrides.
- **LOD_Cut**: The set of hierarchy nodes shown at a given zoom, chosen automatically by zoom level.
- **Manual_Override**: A user expand or collapse of one subtree that takes precedence over the LOD_Cut for that subtree.
- **Lifted_Edge**: An aggregated edge drawn between visible ancestors of two hidden endpoints, carrying a count.
- **Severity_Scale**: critical, high, medium, low, info, remediated, validated.
- **Zoom_Levels**: L1 Global, L2 Architecture, L3 Component, L4 Code/Security investigation.
- **Renderer**: The Sigma.js WebGL renderer plus the canvas overlay for pills and labels.
- **Interaction_Machine**: The discriminated-union state machine in `machine.ts` with a pure transition function.
- **Inspector**: The side panel that shows details of the selected Entity or Attack_Path.
- **Agent_Event**: A timestamped event `{ agentId, type: "visit"|"traverse"|"finding"|"tool_call", entityId, edgeId, ts }`.
- **Event_Stream**: A replayable stream of Agent_Events (SSE/WebSocket interface).
- **Feature_Flag**: The `security_graph` entry in `packages/schema/src/config/flag.ts`.

## Requirements

### Requirement 1: Gating and data source

**User Story:** As a developer, I want the graph behind a flag and a swappable data source, so that it ships safely and can later connect to bellud.

#### Acceptance Criteria

1. WHILE the Feature_Flag is off, THE Security_Graph SHALL NOT register its route or navigation entry.
2. THE Security_Graph SHALL read all data through a `GraphSource` interface that returns Entities, Relationships, Boundaries, Attack_Paths and an Event_Stream.
3. THE Security_Graph SHALL provide a mock `GraphSource` with 100, 5,000 and 50,000 node sizes selectable at runtime.
4. THE mock `GraphSource` SHALL include a `/login` API, a `Lim.API` module, a `log4j:log4j 1.2.12` dependency with a Critical CVE, a PII data model, Stripe, Auth0 and OpenAI as external nodes inside an "Untrusted boundaries" Boundary, a Written-to-log relationship, Internet Exposed and Sensitive Logic tags, and at least one Attack_Path from an internet-exposed Entity to the PII data model.
5. THE Security_Graph SHALL label the mock Event_Stream as simulated in the UI.
6. THE Security_Graph SHALL document an adapter seam for the bellud graph and the viewport- and level-scoped projection API shape in the README.

### Requirement 2: Semantic zoom and LOD cut

**User Story:** As a developer, I want the representation to change with zoom, so that I see an overview first and detail on demand.

#### Acceptance Criteria

1. THE Projection_Engine SHALL derive all four Zoom_Levels from one graph, keeping each Entity's ID and Relationships at every level.
2. WHEN the zoom level is L1, THE Projection_Engine SHALL show one cluster node per area (Application, Backend, Frontend, Database, Cloud Infrastructure, External APIs, Dependencies, Security, AI Agents).
3. WHEN the zoom crosses a level threshold, THE Projection_Engine SHALL compute a new LOD_Cut through the hierarchy.
4. WHERE a Manual_Override exists for a subtree, THE Projection_Engine SHALL apply the override instead of the LOD_Cut for that subtree.
5. WHEN the zoom level is L4, THE Inspector SHALL be available for files, functions, API endpoints, vulnerable code locations, dependency versions, IAM policies, credential references, CVE details, attack-path steps and evidence.
6. IF an Entity carries a credential, THEN THE Security_Graph SHALL show only a reference to the credential and never its secret value.

### Requirement 3: Expand, collapse and aggregation

**User Story:** As a developer, I want expand and collapse to preserve my mental map, so that I never lose my place.

#### Acceptance Criteria

1. WHEN a user expands a node, THE Projection_Engine SHALL place its children around the parent position and re-lay-out only the expanded subtree.
2. WHEN a user collapses a node, THE Projection_Engine SHALL hide its children and give the parent the maximum child severity, the child count and the union of risk tags.
3. WHEN a node collapses, THE Projection_Engine SHALL replace each Relationship between a hidden child and a visible outside node with a Lifted_Edge whose count equals the number of replaced Relationships.
4. WHEN a node collapses, THE Projection_Engine SHALL remove Relationships whose two endpoints are both inside the collapsed subtree.
5. THE Projection_Engine SHALL keep the same Entity ID and Relationship ID across expand and collapse.
6. WHEN an expand or collapse runs, THE Renderer SHALL animate the transition and keep the viewport unchanged.

### Requirement 4: Interaction state machine

**User Story:** As a developer, I want predictable interactions, so that pan, zoom, selection and history behave consistently.

#### Acceptance Criteria

1. THE Interaction_Machine SHALL model idle, hovering, panning, dragging, selected, focused, and animating as one discriminated union with a pure transition function.
2. WHEN the user clicks a node or its count badge, THE Interaction_Machine SHALL transition to select or toggle expansion respectively.
3. WHEN the user double-clicks a node, THE Interaction_Machine SHALL focus the node and add a history entry.
4. WHEN the user activates back or forward, THE Interaction_Machine SHALL restore the previous or next history entry.
5. THE Security_Graph SHALL support wheel zoom, pinch, drag-pan, fit-to-screen and reset view.
6. THE Security_Graph SHALL make every control reachable and operable by keyboard.

### Requirement 5: Navigation panels

**User Story:** As a developer, I want breadcrumb, search, filters, minimap and an inspector, so that I can find and understand any entity.

#### Acceptance Criteria

1. THE Security_Graph SHALL show a breadcrumb of the focused Entity's ancestor path (for example System > Backend > Auth Service > login.ts > validateUser()).
2. WHEN a user selects a search result, THE Security_Graph SHALL expand the ancestors of the Entity and center the viewport on it.
3. THE Security_Graph SHALL filter by repository, service, environment, node type, tag, severity, trust boundary and agent.
4. WHEN an Entity is selected, THE Inspector SHALL show description, source location, severity, related entities, evidence and provenance, suggested remediation, agent activity, and the actions Ask AI agent, Generate fix, Validate fix and Open in editor.
5. THE Security_Graph SHALL show a hover tooltip, a minimap and zoom controls.
6. THE Security_Graph SHALL export the current view as PNG, SVG and JSON.
7. THE Security_Graph SHALL render in resizable docked panels so the editor, terminal and AI activity panel stay reachable.

### Requirement 6: Visual language

**User Story:** As a developer, I want a calm, readable graph in dark and light themes, so that I can scan it without noise.

#### Acceptance Criteria

1. THE Security_Graph SHALL take every color, size and font from one theme file with dark (canvas `#0B0F17`, dot grid) and light (white canvas, light-grey 24px dot grid) token sets.
2. THE Renderer SHALL draw nodes as filled circles with a white line icon, a type label above a muted name label, and a count badge for collapsed children.
3. THE Renderer SHALL draw external third-party nodes as white circles with a thin grey ring and a brand logo, and code-owned nodes with a small language icon.
4. THE Renderer SHALL draw tag pills from `node.tags[]`, risk pills in the risk style and info pills in the neutral style.
5. THE Renderer SHALL draw edges at 1px with arrowheads, and edge labels rotated along the edge only above the label zoom threshold.
6. WHEN a node is hovered or selected, THE Renderer SHALL keep the node, its direct neighbors and their edges at full opacity and fade the rest to 15% opacity.
7. THE Renderer SHALL draw each Boundary as a thin-stroke convex hull with a muted caption, computed from its members, following dragged members, and supporting nesting.
8. THE Renderer SHALL show severity by color together with a distinct icon or shape from the Severity_Scale.
9. THE Security_Graph SHALL use app font tokens and line-height tokens and SHALL NOT write a literal font family.
10. THE Security_Graph SHALL read all visible text from English i18n keys in `runtime/i18n/en.ts`.

### Requirement 7: Agents as graph entities

**User Story:** As a developer, I want to see what agents are doing in the graph, so that I can trust and follow their work.

#### Acceptance Criteria

1. THE Projection_Engine SHALL show agents as one AI Agents cluster at L1, five agent nodes (Security, Offensive, Code, Testing, Remediation) at L2, and task, tool, accessed entities, findings and messages at L4.
2. WHEN an Agent_Event arrives, THE Renderer SHALL highlight the target Entity, light the traversed edge and show the task in the Activity panel.
3. WHEN a `finding` Agent_Event arrives, THE Security_Graph SHALL attach the finding to the Entity named by `entityId`.
4. THE Security_Graph SHALL drive all agent motion from Agent_Events and SHALL NOT animate without an event.
5. WHEN the Event_Stream is replayed, THE Security_Graph SHALL produce the same highlights in the same order.

### Requirement 8: Attack paths

**User Story:** As a security engineer, I want attack paths as first-class chains, so that I can see how an attacker reaches sensitive data.

#### Acceptance Criteria

1. WHEN a user selects an Attack_Path, THE Renderer SHALL highlight it end to end and THE Inspector SHALL show entry point, intermediate resources, identity and permission edges, target asset, evidence, risk explanation and remediation.
2. WHEN a user chooses Show attack path on an Internet-Exposed Entity, THE Security_Graph SHALL find the shortest and all risky paths to PII or sensitive Entities.
3. WHILE steps of an Attack_Path are collapsed, THE Projection_Engine SHALL draw the path as one aggregated path between the visible ancestors of its endpoints.
4. WHEN a user zooms in or expands, THE Projection_Engine SHALL split the aggregated path into its real steps.
5. THE Renderer SHALL mark each place where an Attack_Path crosses an untrusted Boundary.

### Requirement 9: Incremental updates

**User Story:** As a developer, I want new findings to appear without the graph jumping, so that my view stays stable.

#### Acceptance Criteria

1. WHEN new Entities or findings arrive, THE Projection_Engine SHALL keep the positions of all existing nodes unchanged.
2. WHEN new Entities arrive, THE Projection_Engine SHALL place each new node near its parent or its neighbors.
3. WHEN new data arrives, THE Renderer SHALL keep the viewport unchanged.

### Requirement 10: Performance

**User Story:** As a developer, I want a smooth graph on large systems, so that it stays usable.

#### Acceptance Criteria

1. THE Renderer SHALL draw nodes and edges with WebGL and SHALL NOT create SVG or DOM elements per node.
2. THE Renderer SHALL draw labels, pills and edge labels only for nodes inside the viewport and above the label zoom threshold.
3. THE Security_Graph SHALL run the global layout in a Web Worker and never on the main thread.
4. WHEN a node expands, THE Security_Graph SHALL run only a local layout for the expanded subtree.
5. THE Security_Graph SHALL draw all icons and brand logos from one texture atlas.
6. THE Security_Graph SHALL send only the viewport- and level-scoped part of the graph to the Renderer.
7. THE benchmark script SHALL log FPS-proxy, layout time and projection time to the terminal for 100, 5,000 and 50,000 nodes.
