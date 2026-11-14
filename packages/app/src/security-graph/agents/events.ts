import type { AgentEvent } from "../model"
import type { ZoomLevelKey } from "../theme"

/** Lookup of entities and edges the graph currently knows. Events naming anything else are ignored. */
export type Known = { entity(id: string): boolean; edge(id: string): boolean }

export type AgentExecution = "exploring" | "calling-tool" | "reporting"

export type AgentStatus = {
  id: string
  execution: AgentExecution
  /** Current task, derived from the latest event: what the agent is doing and on which entity. */
  task: { type: AgentEvent["type"]; entityId: string }
  /** Entity of the latest `tool_call`, if any. */
  tool?: string
  /** Entity the agent is currently on. */
  target: string
  /** Entities the agent has touched, in first-access order. */
  accessed: string[]
  ts: number
}

export type Finding = { agentId: string; ts: number }

export type AgentState = {
  agents: Record<string, AgentStatus>
  /** Entities currently targeted by any agent. */
  highlighted: string[]
  /** Edge id to the `ts` of the event that lit it; the renderer fades by comparing against its own clock. */
  litEdges: Record<string, number>
  findings: Record<string, Finding[]>
  /** Accepted events in arrival order. */
  log: AgentEvent[]
}

export const initialAgentState: AgentState = { agents: {}, highlighted: [], litEdges: {}, findings: {}, log: [] }

const execution = {
  visit: "exploring",
  traverse: "exploring",
  tool_call: "calling-tool",
  finding: "reporting",
} satisfies Record<AgentEvent["type"], AgentExecution>

/** Pure. Returns the same `state` object when the event names an unknown entity or edge. */
export function reduce(state: AgentState, event: AgentEvent, known: Known): AgentState {
  if (!known.entity(event.entityId)) return state
  if (event.edgeId !== undefined && !known.edge(event.edgeId)) return state
  const prev = state.agents[event.agentId]
  const agent: AgentStatus = {
    id: event.agentId,
    execution: execution[event.type],
    task: { type: event.type, entityId: event.entityId },
    tool: event.type === "tool_call" ? event.entityId : prev?.tool,
    target: event.entityId,
    accessed: prev?.accessed.includes(event.entityId) ? prev.accessed : [...(prev?.accessed ?? []), event.entityId],
    ts: event.ts,
  }
  const agents = { ...state.agents, [event.agentId]: agent }
  return {
    agents,
    highlighted: [...new Set(Object.values(agents).map((item) => item.target))],
    litEdges: event.edgeId === undefined ? state.litEdges : { ...state.litEdges, [event.edgeId]: event.ts },
    findings:
      event.type === "finding"
        ? {
            ...state.findings,
            [event.entityId]: [...(state.findings[event.entityId] ?? []), { agentId: event.agentId, ts: event.ts }],
          }
        : state.findings,
    log: [...state.log, event],
  }
}

export function replay(events: readonly AgentEvent[], known: Known, from: AgentState = initialAgentState) {
  return events.reduce((state, event) => reduce(state, event, known), from)
}

export type AgentView =
  | { level: "L1"; activeAgents: number; findings: number }
  | { level: "L2" | "L3"; agents: { id: string; execution: AgentExecution; findings: number }[] }
  | { level: "L4"; agents: (AgentStatus & { findings: Record<string, Finding[]> })[] }

/** What the Activity panel and renderer show per zoom level: cluster summary at L1, per agent at L2/L3, full detail at L4. */
export function view(state: AgentState, level: ZoomLevelKey): AgentView {
  const counts = state.log.reduce<Record<string, number>>((acc, event) => {
    if (event.type === "finding") acc[event.agentId] = (acc[event.agentId] ?? 0) + 1
    return acc
  }, {})
  const agents = Object.values(state.agents).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  if (level === "L1") {
    return { level, activeAgents: agents.length, findings: Object.values(counts).reduce((sum, n) => sum + n, 0) }
  }
  if (level === "L4") {
    return {
      level,
      agents: agents.map((agent) => ({
        ...agent,
        findings: Object.fromEntries(
          Object.entries(state.findings)
            .map(([id, list]) => [id, list.filter((item) => item.agentId === agent.id)] as const)
            .filter(([, list]) => list.length > 0),
        ),
      })),
    }
  }
  return {
    level,
    agents: agents.map((agent) => ({ id: agent.id, execution: agent.execution, findings: counts[agent.id] ?? 0 })),
  }
}
