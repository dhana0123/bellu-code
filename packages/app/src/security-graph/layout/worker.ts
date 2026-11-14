import { layout, type LayoutRequest, type LayoutResponse } from "./compute"
export type { LayoutRequest, LayoutResponse }
/** Runs in a Web Worker. The main thread never runs ForceAtlas2. */
type Scope = {
  addEventListener(type: "message", listener: (event: MessageEvent<LayoutRequest>) => void): void
  postMessage(message: LayoutResponse, transfer: Transferable[]): void
}

const scope = self as unknown as Scope

scope.addEventListener("message", (event) => {
  const request = event.data
  try {
    const positions = layout(request)
    scope.postMessage({ id: request.id, positions }, [positions.buffer])
  } catch (error) {
    scope.postMessage({ id: request.id, error: error instanceof Error ? error.message : String(error) }, [])
  }
})
