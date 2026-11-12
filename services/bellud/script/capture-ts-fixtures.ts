// Records request/response fixtures from the real TS server into internal/contract/testdata.
// Run: bun services/bellud/script/capture-ts-fixtures.ts
// Starts its own server on a random loopback port with a temp HOME/XDG dirs; never touches the live service.
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"

const root = path.join(import.meta.dir, "../../..")
const outDir = path.join(import.meta.dir, "../internal/contract/testdata")
const PASSWORD = "fixture-password"
const USERNAME = "bellucode"
const SSE_WINDOW_MS = 1500

const tmp = mkdtempSync(path.join(tmpdir(), "bellud-fixtures-"))
const dirs = ["home", "data", "config", "cache", "state"].map((d) => {
  const p = path.join(tmp, d)
  mkdirSync(p, { recursive: true })
  return p
})
const [home, data, config, cache, state] = dirs

const probe = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("") })
const port = probe.port
probe.stop(true)
const base = `http://127.0.0.1:${port}`

const proc = Bun.spawn(["bun", "run", "src/index.ts", "serve", "--hostname", "127.0.0.1", "--port", String(port)], {
  cwd: path.join(root, "packages/cli"),
  env: {
    ...process.env,
    HOME: home,
    XDG_DATA_HOME: data,
    XDG_CONFIG_HOME: config,
    XDG_CACHE_HOME: cache,
    XDG_STATE_HOME: state,
    BELLUCODE_PASSWORD: PASSWORD,
    BELLUCODE_SERVER_USERNAME: USERNAME,
    BELLUCODE_DISABLE_MODELS_FETCH: "1",
  },
  stdout: "ignore",
  stderr: "ignore",
})

const basic = (user: string, pw: string) => "Basic " + Buffer.from(`${user}:${pw}`).toString("base64")
const good = basic(USERNAME, PASSWORD)

async function cleanup() {
  proc.kill()
  await proc.exited.catch(() => {})
  rmSync(tmp, { recursive: true, force: true })
}

// Normalization: replace volatile values with placeholders.
const UUIDISH = /\b(?:[a-z]{3}_[0-9A-Za-z]{10,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/g
const SESSION = /\b\d{9,}\.[A-Za-z0-9_-]{20,}\b/g
const volatileKey = /^(time|timestamp|created|updated|started|startedAt|expires|expiresAt|version|pid|id)$/i
function normStr(s: string): string {
  return s
    .replaceAll(tmp, "<TMP>")
    .replaceAll(String(port), "<PORT>")
    .replace(SESSION, "<TOKEN>")
    .replace(UUIDISH, "<ID>")
}
function norm(v: unknown, key = ""): unknown {
  if (typeof v === "string" && key === "hostname") return "<HOSTNAME>"
  if (typeof v === "string" && key === "code") return "<CODE>"
  if (typeof v === "string") return volatileKey.test(key) && key.toLowerCase() === "version" ? "<VERSION>" : normStr(v)
  if (typeof v === "number") return volatileKey.test(key) ? "<NUMBER>" : v
  if (Array.isArray(v)) return v.map((x) => norm(x, key))
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, norm(x, k)]))
  return v
}

type Fixture = {
  operationId: string
  name: string
  method: string
  path: string
  request: { headers: Record<string, string>; body?: unknown }
  status: number
  contentType: string
  body?: unknown
  events?: { type: string }[]
}

const fixtures: Fixture[] = []
let code = ""

async function record(opts: {
  operationId: string
  name: string
  method?: string
  path: string
  auth?: string
  headers?: Record<string, string>
  body?: unknown
}) {
  const method = opts.method ?? "GET"
  const headers: Record<string, string> = { ...opts.headers }
  if (opts.auth) headers.authorization = opts.auth
  const res = await fetch(base + opts.path, {
    method,
    headers: opts.body === undefined ? headers : { "content-type": "application/json", ...headers },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    redirect: "manual",
  })
  const contentType = (res.headers.get("content-type") ?? "").split(";")[0].trim()
  const text = await res.text()
  let body: unknown = text === "" ? undefined : text
  if (contentType.includes("json") && text) body = norm(JSON.parse(text))
  else if (typeof body === "string") body = normStr(body)
  fixtures.push({
    operationId: opts.operationId,
    name: opts.name,
    method,
    path: code ? opts.path.replaceAll(code, "<CODE>") : opts.path,
    // Credentials are recorded symbolically, never literally.
    request: {
      headers: Object.fromEntries(
        Object.entries(opts.headers ?? {}).concat(opts.auth ? [["authorization", `<AUTH:${opts.name}>`]] : []),
      ),
      ...(opts.body === undefined ? {} : { body: opts.body }),
    },
    status: res.status,
    contentType,
    ...(body === undefined ? {} : { body }),
  })
  return { res, text }
}

async function recordSSE(name: string, auth: string) {
  const ctl = new AbortController()
  const res = await fetch(base + "/api/event", {
    headers: { authorization: auth, accept: "text/event-stream" },
    signal: ctl.signal,
  })
  const contentType = (res.headers.get("content-type") ?? "").split(";")[0].trim()
  const events: { type: string }[] = []
  let buf = ""
  const timer = setTimeout(() => ctl.abort(), SSE_WINDOW_MS)
  try {
    const dec = new TextDecoder()
    for await (const chunk of res.body as any) {
      buf += dec.decode(chunk, { stream: true })
      let i: number
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, i)
        buf = buf.slice(i + 2)
        const dataLines = frame.split("\n").filter((l) => l.startsWith("data:"))
        if (!dataLines.length) continue
        try {
          const j = JSON.parse(dataLines.map((l) => l.slice(5).trimStart()).join("\n"))
          events.push({ type: String(j.type), ...(norm(j) as object) } as any)
        } catch {
          events.push({ type: "<unparsed>" })
        }
      }
    }
  } catch {
    // aborted at end of window
  } finally {
    clearTimeout(timer)
  }
  fixtures.push({
    operationId: "event.subscribe",
    name,
    method: "GET",
    path: "/api/event",
    request: { headers: { accept: "text/event-stream", authorization: `<AUTH:${name}>` } },
    status: res.status,
    contentType,
    events,
  })
}

try {
  // Wait for readiness.
  const deadline = Date.now() + 60_000
  for (;;) {
    try {
      const r = await fetch(base + "/api/info", { headers: { authorization: good } })
      if (r.ok) break
    } catch {}
    if (Date.now() > deadline) throw new Error("TS server did not become ready")
    if (proc.exitCode !== null) throw new Error("TS server exited early: " + proc.exitCode)
    await Bun.sleep(250)
  }

  await record({ operationId: "server.info", name: "info-ok", path: "/api/info", auth: good })
  await record({ operationId: "server.info", name: "info-no-auth", path: "/api/info" })
  await record({ operationId: "server.info", name: "info-wrong-password", path: "/api/info", auth: basic(USERNAME, "nope") })
  await record({ operationId: "server.info", name: "info-wrong-username", path: "/api/info", auth: basic("other", PASSWORD) })
  await record({ operationId: "server.info", name: "info-password-as-bearer", path: "/api/info", auth: `Bearer ${PASSWORD}` })

  const pair = await record({ operationId: "server.pair", method: "POST", name: "pair-ok", path: "/api/pair", auth: good })
  await record({ operationId: "server.pair", method: "POST", name: "pair-no-auth", path: "/api/pair" })

  // Redeem the real code once (JSON accept returns a session token), then again (single-use => 401).
  try {
    code = String(JSON.parse(pair.text).code ?? "")
  } catch {}
  if (code) {
    const p = `/auth/connect/${code}`
    const first = await record({ operationId: "server.connect", name: "connect-ok-json", path: p, headers: { accept: "application/json" } })
    // Use the issued session token as the password.
    try {
      const token = String(JSON.parse(first.text).token ?? JSON.parse(first.text).session ?? "")
      if (token) await record({ operationId: "server.info", name: "info-session-token", path: "/api/info", auth: basic(USERNAME, token) })
    } catch {}
    await record({ operationId: "server.connect", name: "connect-reused-code", path: p, headers: { accept: "application/json" } })
  }
  await record({ operationId: "server.connect", name: "connect-bad-code", path: "/auth/connect/not-a-real-code", headers: { accept: "application/json" } })

  await recordSSE("event-stream-ok", good)
  await record({ operationId: "event.subscribe", name: "event-no-auth", path: "/api/event" })

  mkdirSync(outDir, { recursive: true })
  for (const f of fixtures) {
    writeFileSync(path.join(outDir, `${f.operationId}.${f.name}.json`), JSON.stringify(f, null, 2) + "\n")
  }
  console.log(`wrote ${fixtures.length} fixtures to ${outDir}`)
  for (const f of fixtures) console.log(`  ${f.operationId} ${f.name} -> ${f.status} ${f.contentType}${f.events ? ` (${f.events.length} events)` : ""}`)
} finally {
  await cleanup()
}
