// Security Graph benchmark. Logs timings to the terminal; there is no report file.
// Run from packages/app: bun run src/security-graph/bench/bench.ts [100|5k|50k ...]
import { layout } from "../layout/compute"
import { generateDelta, generateGraph } from "../mock/generator"
import { createEngine } from "../projection/engine"
import type { GraphSize } from "../source"
import type { ZoomLevelKey } from "../theme"
import { layoutRequest } from "./request"
const levels: ZoomLevelKey[] = ["L1", "L2", "L3", "L4"]
const runs = 5
const fpsSeconds = 5
const chromium = "/usr/bin/chromium-browser"
const ms = (value: number) => `${value.toFixed(1)} ms`
const median = (values: number[]) => values.toSorted((a, b) => a - b)[Math.floor(values.length / 2)]
function time<T>(run: () => T) {
  const start = performance.now()
  const value = run()
  return { value, ms: performance.now() - start }
}
function repeat<T>(run: () => T) {
  const samples = Array.from({ length: runs }, () => time(run))
  return { value: samples[0].value, ms: median(samples.map((sample) => sample.ms)) }
}
const requested = process.argv.slice(2)
const sizes = (requested.length ? requested : ["100", "5k", "50k"]) as GraphSize[]
console.log("Security Graph benchmark")
console.log("NOTE: this server has no GPU. Chromium uses software rendering (SwiftShader), so FPS numbers are a floor.")
console.log(`Projection times are the median of ${runs} runs. Layout and generation run once.\n`)
const fps = new Map<GraphSize, string>()
for (const size of sizes) {
  const generated = time(() => generateGraph(size))
  const data = generated.value
  const created = time(() => createEngine(data))
  const engine = created.value
  console.log(`=== ${size} (${data.entities.length} entities, ${data.relationships.length} relationships) ===`)
  console.log(`generation       ${ms(generated.ms)}`)
  console.log(`engine creation  ${ms(created.ms)}`)
  const rows = levels.map((level) => {
    // The first call builds lazily cached aggregates; it is reported separately from the median.
    const cold = time(() => engine.project({ level }))
    const warm = repeat(() => engine.project({ level }))
    return { level, cold: ms(cold.ms), median: ms(warm.ms), nodes: warm.value.nodes.length, edges: warm.value.edges.length }
  })
  console.table(rows)
  const root = engine.project({ level: "L1" }).nodes.find((node) => node.hasChildren && node.count > 0)
  if (root) {
    const expand = time(() => {
      engine.expand(root.id)
      return engine.project({ level: "L1" })
    })
    const collapse = time(() => {
      engine.collapse(root.id)
      return engine.project({ level: "L1" })
    })
    console.log(`expand+project   ${ms(expand.ms)} (${root.name}, ${root.count} hidden, ${expand.value.nodes.length} visible nodes)`)
    console.log(`collapse+project ${ms(collapse.ms)}`)
  }
  const delta = generateDelta(data, 1)
  console.log(`applyDelta       ${ms(time(() => engine.applyDelta(delta)).ms)}`)
  const request = layoutRequest(data)
  const laid = time(() => layout(request))
  console.log(`layout           ${ms(laid.ms)} (ForceAtlas2 in the bench process, ${request.iterations} iterations budget, ${request.budgetMs} ms cap)`)
  fps.set(size, await measureFps(size))
  console.log(`fps              ${fps.get(size)}\n`)
}
async function measureFps(size: GraphSize) {
  if (!(await Bun.file(chromium).exists())) return `skipped: ${chromium} not found`
  const playwright = await import("@playwright/test").catch(() => undefined)
  if (!playwright) return "skipped: @playwright/test is not installed"
  const built = await Bun.build({ entrypoints: [new URL("./harness.ts", import.meta.url).pathname], target: "browser" })
  if (!built.success) return `skipped: harness build failed (${built.logs.join("; ")})`
  const script = await built.outputs[0].text()
  const server = Bun.serve({
    port: 0,
    fetch: (request) =>
      new URL(request.url).pathname === "/harness.js"
        ? new Response(script, { headers: { "content-type": "text/javascript" } })
        : new Response('<!doctype html><body style="margin:0"><div id="graph" style="width:1280px;height:800px"></div><script src="/harness.js"></script>', {
            headers: { "content-type": "text/html" },
          }),
  })
  const browser = await playwright.chromium.launch({ executablePath: chromium, args: ["--no-sandbox"] })
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } })
    await page.goto(`http://localhost:${server.port}/`)
    await page.waitForFunction(() => typeof window.mount === "function")
    const shown = await page.evaluate((value) => window.mount(value), size)
    const before = await page.evaluate(() => window.frameCount())
    const start = performance.now()
    // Scripted pan (drag) and zoom (wheel) until the time is up.
    await page.mouse.move(640, 400)
    for (let step = 0; performance.now() - start < fpsSeconds * 1000; step++) {
      await page.mouse.down()
      await page.mouse.move(640 + 120 * Math.sin(step / 3), 400 + 80 * Math.cos(step / 3), { steps: 8 })
      await page.mouse.up()
      await page.mouse.wheel(0, step % 6 < 3 ? -240 : 240)
    }
    const seconds = (performance.now() - start) / 1000
    const frames = (await page.evaluate(() => window.frameCount())) - before
    return `${(frames / seconds).toFixed(1)} fps over ${seconds.toFixed(1)} s (${shown.nodes} nodes, ${shown.edges} edges visible at start)`
  } catch (error) {
    return `skipped: ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`
  } finally {
    await browser.close()
    await server.stop(true)
  }
}
