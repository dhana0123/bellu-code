// Thin edge between an agent EventStream and the rest of the view. It owns the iterator, the pacing and the abort
// controller. Every accepted event goes through the pure `reduce` in ./events; the driver only publishes the result,
// turns it into a renderer highlight and tags findings on entities. Nothing runs without an event.
import type { Driver } from "../driver"
import type { Engine } from "../projection/engine"
import type { Highlight } from "../render/types"
import type { EventStream } from "../source"
import { initialAgentState, reduce, type AgentState, type Known } from "./events"

export type AgentPlayback = "playing" | "paused" | "ended"
export type AgentSnapshot = { state: AgentState; playback: AgentPlayback }

export type AgentDriverOptions = {
  /** Create the stream with a `delayMs` for live pacing. */
  stream: EventStream
  engine: Engine
  driver: Driver
  /** Localized tag label added to an entity that receives a finding. */
  findingLabel: string
  /** Called with every new snapshot. */
  onSnapshot: (snapshot: AgentSnapshot) => void
  /** Highlight parts owned by someone else (focus, attack paths), merged into every update. */
  base?: () => Pick<Highlight, "focus" | "paths">
}

export function createAgentDriver(options: AgentDriverOptions) {
  const { engine, driver } = options
  const known: Known = {
    entity: (id) => engine.entity(id) !== undefined,
    edge: (id) => engine.relationship(id) !== undefined,
  }
  let state = initialAgentState
  let playback: AgentPlayback = "playing"
  let run = new AbortController()
  let gate: PromiseWithResolvers<void> | undefined

  const publish = () => options.onSnapshot({ state, playback })

  const highlight = () => {
    const base = options.base?.()
    const lit = Object.entries(state.litEdges).map(([id, ts]) => ({ id, ts }))
    // The stream clock: the fade is measured against the latest event, so it only moves when an event arrives.
    const now = state.log.at(-1)?.ts
    driver.setHighlight({ focus: base?.focus ?? [], paths: base?.paths ?? [], agent: state.highlighted, lit, now })
  }

  const tag = (id: string) => {
    const entity = engine.entity(id)
    if (!entity || entity.tags.some((item) => item.label === options.findingLabel)) return
    driver.applyDelta({ entities: [{ ...entity, tags: [...entity.tags, { label: options.findingLabel, severity: "risk" }] }] })
  }

  const consume = async (signal: AbortSignal) => {
    const iterator = options.stream[Symbol.asyncIterator]()
    signal.addEventListener("abort", () => void iterator.return?.(), { once: true })
    while (!signal.aborted) {
      const next = await iterator.next()
      if (signal.aborted) return
      if (next.done) {
        playback = "ended"
        publish()
        return
      }
      if (gate) await gate.promise
      if (signal.aborted) return
      const reduced = reduce(state, next.value, known)
      if (reduced === state) continue
      state = reduced
      if (next.value.type === "finding") tag(next.value.entityId)
      highlight()
      publish()
    }
  }

  const start = () => {
    run = new AbortController()
    void consume(run.signal).catch(() => {
      if (run.signal.aborted) return
      playback = "ended"
      publish()
    })
  }

  const release = () => {
    gate?.resolve()
    gate = undefined
  }

  start()
  publish()

  return {
    pause() {
      if (playback !== "playing") return
      playback = "paused"
      gate = Promise.withResolvers<void>()
      publish()
    },
    resume() {
      if (playback !== "paused") return
      playback = "playing"
      release()
      publish()
    },
    /** Clears the agent state and plays the stream again from its first event. */
    replay() {
      run.abort()
      release()
      state = initialAgentState
      playback = "playing"
      highlight()
      publish()
      start()
    },
    dispose() {
      run.abort()
      release()
    },
  }
}

export type AgentDriver = ReturnType<typeof createAgentDriver>
