// Copies packages/app/dist into internal/webui/dist and writes .br variants for compressible assets.
import { brotliCompressSync, constants } from "node:zlib"
import { cp, readdir, readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"

const root = path.resolve(import.meta.dir, "..")
const src = path.resolve(root, "../../packages/app/dist")
const dst = path.join(root, "internal/webui/dist")
const compressible = /\.(html|js|mjs|css|json|svg|txt|map|wasm|xml)$/

await rm(dst, { recursive: true, force: true })
await cp(src, dst, { recursive: true })

async function walk(dir: string): Promise<string[]> {
  const out: string[] = []
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) out.push(...(await walk(p)))
    else out.push(p)
  }
  return out
}

for (const file of await walk(dst)) {
  if (!compressible.test(file)) continue
  const data = await readFile(file)
  const br = brotliCompressSync(data, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } })
  await writeFile(file + ".br", br)
}
