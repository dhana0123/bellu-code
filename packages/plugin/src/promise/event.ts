import type { BelluCodeEvent } from "@bellucode/client"
import type { SelectedEvent, SubscribeOptions } from "@bellucode/client/promise/api"

type EventType = Exclude<BelluCodeEvent["type"], "server.connected">

export interface EventDomain {
  readonly subscribe: <Type extends EventType = EventType>(
    options?: SubscribeOptions<Type>,
  ) => AsyncIterable<SelectedEvent<BelluCodeEvent, Type>>
}
