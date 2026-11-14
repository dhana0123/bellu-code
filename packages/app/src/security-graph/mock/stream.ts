import type { AgentEvent, GraphData, Relationship, Severity } from "../model"
import type { EventStream } from "../source"

/** Fixed base so the same graph always yields identical events. */
const baseTs = 1_700_000_000_000
const tickMs = 250
const stepsPerAgent = 8
const flagged: readonly Severity[] = ["critical", "high", "medium"]

/**
 * Deterministic, replayable simulated agent stream built from the entities and relationships of `data`.
 * Each `ai-agent` entity walks the graph along real relationships. Every iteration restarts from the first event.
 * `delayMs` paces live consumption; the default 0 replays without waiting.
 */
export function createMockStream(data: GraphData, delayMs = 0): EventStream {
  const events = build(data)
  return {
    simulated: true,
    async *[Symbol.asyncIterator]() {
      for (const event of events) {
        if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs))
        yield event
      }
    },
  }
}

function build(data: GraphData) {
  const entities = new Map(data.entities.map((entity) => [entity.id, entity]))
  const adjacent = data.relationships.reduce((acc, rel) => {
    acc.set(rel.source, [...(acc.get(rel.source) ?? []), rel])
    acc.set(rel.target, [...(acc.get(rel.target) ?? []), rel])
    return acc
  }, new Map<string, Relationship[]>())
  const agents = data.entities.filter((entity) => entity.type === "ai-agent")

  const walks = agents.map((agent, index) => {
    const seen = new Set<string>()
    const out: Omit<AgentEvent, "ts">[] = [{ agentId: agent.id, type: "visit", entityId: agent.id }]
    let current = agent.id
    let previous: string | undefined
    Array.from({ length: stepsPerAgent }).forEach((_, step) => {
      const options = adjacent.get(current) ?? []
      const fresh = options.filter((rel) => rel.id !== previous)
      const pool = fresh.length ? fresh : options
      const edge = pool[(step * 7 + index) % Math.max(pool.length, 1)]
      if (!edge) return
      const next = edge.source === current ? edge.target : edge.source
      const target = entities.get(next)
      if (!target) return
      out.push({ agentId: agent.id, type: "traverse", entityId: next, edgeId: edge.id })
      out.push({ agentId: agent.id, type: "visit", entityId: next })
      out.push({ agentId: agent.id, type: "tool_call", entityId: next })
      const risky = (target.severity && flagged.includes(target.severity)) || target.tags.some((t) => t.severity === "risk")
      if (risky && !seen.has(next)) out.push({ agentId: agent.id, type: "finding", entityId: next })
      seen.add(next)
      previous = edge.id
      current = next
    })
    return out
  })

  // Round-robin across agents so their activity interleaves, then stamp increasing timestamps.
  const longest = walks.reduce((max, walk) => Math.max(max, walk.length), 0)
  return Array.from({ length: longest })
    .flatMap((_, i) => walks.flatMap((walk) => (walk[i] ? [walk[i]] : [])))
    .map((event, i): AgentEvent => ({ ...event, ts: baseTs + i * tickMs }))
}
