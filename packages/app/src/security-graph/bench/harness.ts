// Runs in the browser. Mounts the real renderer and driver on the mock graph for the FPS proxy.
import { createDriver } from "../driver"
import { layout } from "../layout/compute"
import { generateGraph } from "../mock/generator"
import { createEngine } from "../projection/engine"
import { createAtlas } from "../render/atlas"
import { createRenderer } from "../render/sigma"
import type { GraphSize } from "../source"
import { layoutRequest } from "./request"
declare global {
  interface Window {
    mount(size: GraphSize): Promise<{ nodes: number; edges: number }>
    frameCount(): number
  }
}
let count = 0
const tick = () => {
  count++
  requestAnimationFrame(tick)
}
requestAnimationFrame(tick)
window.frameCount = () => count
window.mount = async (size) => {
  const container = document.getElementById("graph")!
  container.replaceChildren()
  const data = generateGraph(size)
  const positions = layout(layoutRequest(data))
  const map = new Map(data.entities.map((entity, i) => [entity.id, { x: positions[i * 2], y: positions[i * 2 + 1] }]))
  const renderer = createRenderer(container, { mode: "dark", atlas: createAtlas(), typeLabel: (type) => type, relationLabel: (relation) => relation })
  const driver = createDriver(container, { renderer, engine: createEngine(data, map) })
  driver.fit()
  await new Promise((resolve) => setTimeout(resolve, 800))
  const visible = driver.visible()
  return { nodes: visible.nodes.length, edges: visible.edges.length }
}
