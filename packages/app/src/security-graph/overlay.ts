import { Schema } from "effect"
import { OverlayEvent } from "@bellucode/schema/graph"
import type { ServerApi } from "@/runtime/server/api"

const decode = Schema.decodeUnknownOption(OverlayEvent)

/**
 * Opens the overlay stream through the server's authenticated API and yields each frame that matches the schema.
 * A frame that does not decode is skipped. The stream ends when the server ends it or the signal aborts.
 */
export async function* openOverlay(api: ServerApi, input: { replay?: string; signal: AbortSignal }) {
  const frames = api.experimental.graph.overlay({ replay: input.replay }, { signal: input.signal })
  for await (const frame of frames) {
    const event = decode(frame)
    if (event._tag === "Some") yield event.value
  }
}

/** The events that name a rendered entity, in their original order, with absent ids trimmed from `path`. */
export function playable(events: readonly OverlayEvent[], nodeIds: ReadonlySet<string>) {
  return events.flatMap((event) => {
    if (!nodeIds.has(event.entity)) return []
    if (!event.path) return [event]
    return [{ ...event, path: event.path.filter((id) => nodeIds.has(id)) }]
  })
}
