import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { LanguageModel, type LLMRequest } from "@bellucode/ai/effect"
import { OpenAIChat } from "@bellucode/ai/protocols"
import { TestLLM } from "@bellucode/ai/testing"
import { Server, WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/server"
import { Agent } from "@bellucode/core/agent"
import { AppNodeBuilder } from "@bellucode/core/effect/app-node-builder"
import { LayerNodePlatform } from "@bellucode/core/effect/app-node-platform"
import { Watcher } from "@bellucode/core/filesystem/watcher"
import { Job } from "@bellucode/core/job"
import { LocationServiceMap } from "@bellucode/core/location-service-map"
import { Model } from "@bellucode/core/model"
import { PROMPT_SEEK } from "@bellucode/core/plugin/seek-prompt"
import { Plugin } from "@bellucode/core/plugin"
import { Provider } from "@bellucode/core/provider"
import { AbsolutePath } from "@bellucode/core/schema"
import { Session } from "@bellucode/core/session"
import { SessionRunnerModel } from "@bellucode/core/session/runner/model"
import { Tool } from "@bellucode/core/tool"
import { LayerNode } from "@bellucode/util/effect/layer-node"
import { Global } from "@bellucode/util/global"
import { tempGlobalLayer } from "../fixture/global"
import { offlineModels } from "../fixture/models"
import { tmpdirScoped } from "../fixture/tmpdir"
import { testEffect } from "../lib/effect"
import { waitForTool } from "../lib/tool"

// The Result the bellud tool returns (design.md "Result"), as `structuredContent` and as text content.
export type SeekResult = {
  readonly status: "ok" | "cve_unavailable" | "invalid_plan"
  readonly top_k: number
  readonly error?: { readonly category: string; readonly message: string }
  readonly units: ReadonlyArray<{
    readonly cwe_id: string
    readonly status: "ok" | "no_candidates" | "unknown_cwe" | "unavailable"
    readonly scope: ReadonlyArray<string>
    readonly expanded: boolean
    readonly candidates: ReadonlyArray<{
      readonly cve_id: string
      readonly cwe_id: string
      readonly cwe_name: string
      readonly score: number
      readonly description: string
      readonly kev: boolean
      readonly fix_commit?: string
      readonly repository?: string
    }>
  }>
}

/** One step of the scripted conversation. `seek` steps are answered while the seek child session is running. */
export type Step =
  | { readonly agent: "main"; readonly say: "subagent"; readonly input: { readonly prompt: string } }
  | { readonly agent: "seek"; readonly say: "retrieve"; readonly input: Record<string, unknown> }
  | { readonly agent: "seek" | "main"; readonly say: "text"; readonly text: string }

export const mainID = "main"
export const subagentName = "subagent"
export const seekToolName = "bellu-graph_seek_retrieve"

/**
 * A scripted model plus a real in-process MCP server named `bellu-graph`, wired into a real location so the seek agent,
 * its permissions and its step limit are the production ones. Scenarios supply the `steps` the model plays in order and
 * the `results` the MCP tool returns in order.
 */
export const seekHarness = (input: {
  readonly steps: ReadonlyArray<Step>
  readonly results: ReadonlyArray<SeekResult>
}) =>
  Effect.gen(function* () {
    const dir = yield* tmpdirScoped()
    const sessions = yield* Session.Service
    const locations = yield* LocationServiceMap.Service
    const llm = yield* TestLLM.Test
    const mcp = yield* seekServer(input.results)
    yield* Effect.promise(() =>
      Bun.write(
        `${dir.path}/bellucode.json`,
        JSON.stringify({
          experimental: { seek_planner: true },
          permissions: [{ action: "*", resource: "*", effect: "allow" }],
          mcp: { servers: { "bellu-graph": { type: "remote", url: mcp.url, codemode: false } } },
        }),
      ),
    )
    // Every call the scripted model makes, in order, with the agent that made it.
    const toolCalls: Array<{ agent: "main" | "seek"; name: string; input: unknown }> = []
    // Request counts per role, so each role plays its own steps in order.
    const played = { main: 0, seek: 0 }
    yield* llm.serve((request) => {
      // Auxiliary requests such as title generation carry no tools and are not part of the script.
      if (request.tools.length === 0) return TestLLM.text("Seek e2e", "title")
      const agent = isSeek(request) ? "seek" : "main"
      const step = input.steps.filter((item) => item.agent === agent)[played[agent]]
      played[agent] += 1
      if (!step) return TestLLM.text(`No scripted step for ${agent} request ${played[agent]}`, `unscripted-${agent}`)
      const id = `${agent}-${played[agent]}`
      if (step.say === "text") return TestLLM.text(step.text, id)
      const name = step.say === "subagent" ? subagentName : seekToolName
      const args =
        step.say === "subagent"
          ? { agent: "seek", description: "seek planning", prompt: step.input.prompt }
          : step.input
      toolCalls.push({ agent, name, input: args })
      return TestLLM.toolCall(id, name, args)
    })
    const parent = yield* sessions.create({
      location: { directory: AbsolutePath.make(dir.path) },
      agent: Agent.ID.make("build"),
      model: Model.Ref.make({ id: Model.ID.make("parent"), providerID: Provider.ID.make("test") }),
    })
    // Plugins load asynchronously; wait until the subagent tool and the MCP tool are registered before prompting.
    const at = <A, E, R>(effect: Effect.Effect<A, E, R>) => effect.pipe(Effect.provide(locations.get(parent.location)))
    yield* at(Plugin.Service.use((plugins) => plugins.awaitActivation))
    const registry = yield* at(Tool.Service)
    yield* waitForTool(registry, subagentName)
    yield* waitForTool(registry, seekToolName)
    return {
      parent,
      sessions,
      locations,
      llm,
      mcp,
      toolCalls,
      /** Prompts the main agent and waits until its session is idle again. */
      run: (text: string) =>
        sessions.prompt({ sessionID: parent.id, text }).pipe(Effect.andThen(sessions.wait(parent.id))),
      children: sessions.list({ parentID: parent.id }).pipe(Effect.map((page) => page.data)),
    }
  })

// The seek prompt is in the child's system parts only; the main agent never sees it.
const isSeek = (request: LLMRequest) =>
  request.system.some((part) => part.text.includes(PROMPT_SEEK.slice(0, PROMPT_SEEK.indexOf("\n"))))

/** An MCP server over HTTP on an ephemeral port exposing `seek_retrieve` and counting every call. */
const seekServer = (results: ReadonlyArray<SeekResult>) =>
  Effect.acquireRelease(
    Effect.promise(async () => {
      const calls: Array<Record<string, unknown> | undefined> = []
      const protocol = new Server(
        { name: "bellu-graph", version: "1.0.0" },
        { capabilities: { tools: { listChanged: false } } },
      )
      protocol.setRequestHandler("tools/list", () =>
        Promise.resolve({
          tools: [
            {
              name: "seek_retrieve",
              description: "Retrieve CVE evidence for a plan of predicted CWE units",
              inputSchema: { type: "object" as const, additionalProperties: true },
              annotations: { readOnlyHint: true },
            },
          ],
        }),
      )
      protocol.setRequestHandler("tools/call", (request) => {
        const result = results[calls.length]
        calls.push(request.params.arguments)
        if (!result) return Promise.reject(new Error(`No scripted seek_retrieve result for call ${calls.length}`))
        return Promise.resolve({
          content: [{ type: "text" as const, text: JSON.stringify(result) }],
          structuredContent: result,
          isError: result.status === "invalid_plan",
        })
      })
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        enableJsonResponse: true,
      })
      await protocol.connect(transport)
      const http = Bun.serve({ port: 0, fetch: (request) => transport.handleRequest(request) })
      return {
        url: http.url.toString(),
        /** The arguments of each `seek_retrieve` call the server received. */
        calls,
        close: async () => {
          await protocol.close().catch(() => {})
          await http.stop(true)
        },
      }
    }),
    (server) => Effect.promise(server.close),
  )

const llmLayer = TestLLM.testLayer()
const it = testEffect(
  Layer.merge(
    llmLayer,
    AppNodeBuilder.build(LayerNode.group([Session.node, Job.node, LocationServiceMap.node]), [
      Global.node.replace(tempGlobalLayer),
      offlineModels,
      Watcher.node.replace(Watcher.configured({ enabled: false })),
      LayerNodePlatform.llmClient.replace(llmLayer),
      SessionRunnerModel.node.replace(
        Layer.succeed(SessionRunnerModel.Service, {
          resolve: () =>
            Effect.succeed(
              SessionRunnerModel.resolved(LanguageModel.make({ id: "parent", provider: "test", route: OpenAIChat.route }), {
                capabilities: { tools: true, input: ["text"], output: ["text"] },
                cost: [],
                limit: { context: 200_000, output: 32_000 },
              }),
            ),
        }),
      ),
    ]),
  ),
)

const ok: SeekResult = {
  status: "ok",
  top_k: 5,
  units: [
    {
      cwe_id: "CWE-89",
      status: "ok",
      scope: ["CWE-89"],
      expanded: false,
      candidates: [
        {
          cve_id: "CVE-2024-0001",
          cwe_id: "CWE-89",
          cwe_name: "SQL Injection",
          score: 0.9,
          description: "SQL injection in the query builder.",
          kev: false,
        },
      ],
    },
  ],
}

describe("seek e2e harness", () => {
  it.live("runs the main agent through subagent(agent=seek) to the MCP tool and back", () =>
    Effect.gen(function* () {
      const plan = { units: [{ cwe_id: "CWE-89", rationale: "string-built SQL" }] }
      const seek = yield* seekHarness({
        steps: [
          { agent: "main", say: "subagent", input: { prompt: "Plan for a login query helper" } },
          { agent: "seek", say: "retrieve", input: plan },
          { agent: "seek", say: "text", text: "Security_Context: CVE-2024-0001 (SQL Injection)" },
          { agent: "main", say: "text", text: "Used the security context" },
        ],
        results: [ok],
      })
      yield* seek.run("Write a login query helper")

      // The real registration made a seek child of the main session, on the parent's model.
      const children = yield* seek.children
      expect(children).toHaveLength(1)
      expect(children[0]).toMatchObject({ agent: "seek", model: { id: "parent", providerID: "test" } })
      // The MCP tool was reached exactly once, with the plan the seek agent sent.
      expect(seek.mcp.calls).toEqual([plan])
      expect(seek.toolCalls).toEqual([
        {
          agent: "main",
          name: subagentName,
          input: { agent: "seek", description: "seek planning", prompt: "Plan for a login query helper" },
        },
        { agent: "seek", name: seekToolName, input: plan },
      ])
      // Four scripted requests: main, seek round 1, seek final, main final. Title generation is a fifth, tool-free one.
      expect((yield* seek.llm.requests()).filter((request) => request.tools.length > 0)).toHaveLength(4)
    }),
  )
  it.live("re-plans once with only the replacement CWE after an unsound prediction", () =>
    Effect.gen(function* () {
      const plan1 = {
        language: "TypeScript",
        reasoning: "The helper builds a SQL query from a request parameter and renders the result as JSON.",
        weaknesses: [
          {
            cwe_id: "CWE-89",
            root_cause: "The login helper concatenates the username request parameter into the SQL text.",
            code_snippet: 'db.query("SELECT * FROM users WHERE name = \'" + username + "\'")',
          },
          {
            cwe_id: "CWE-79",
            root_cause: "The username may be echoed into an HTML page.",
            code_snippet: "res.send(`<p>Hello ${username}</p>`)",
          },
        ],
      }
      const plan2 = {
        language: "TypeScript",
        reasoning: "The helper does not render HTML. It loads the account by an id taken from the request, so the check on the owner is the open risk.",
        weaknesses: [
          {
            cwe_id: "CWE-639",
            root_cause: "The helper loads an account by the id in the request without comparing it to the signed-in user.",
            code_snippet: "const account = await db.accounts.find(req.params.accountId)",
          },
        ],
      }
      const round1: SeekResult = {
        status: "ok",
        top_k: 4,
        units: [
          ok.units[0],
          {
            cwe_id: "CWE-79",
            status: "ok",
            scope: ["CWE-79"],
            expanded: false,
            candidates: [
              {
                cve_id: "CVE-2023-0002",
                cwe_id: "CWE-79",
                cwe_name: "Cross-site Scripting",
                score: 0.4,
                description: "Reflected script injection in a template helper.",
                kev: false,
              },
            ],
          },
        ],
      }
      const round2: SeekResult = {
        status: "ok",
        top_k: 4,
        units: [
          {
            cwe_id: "CWE-639",
            status: "ok",
            scope: ["CWE-639"],
            expanded: false,
            candidates: [
              {
                cve_id: "CVE-2022-0003",
                cwe_id: "CWE-639",
                cwe_name: "Authorization Bypass Through User-Controlled Key",
                score: 0.8,
                description: "An account id in the request path selects another user's record.",
                kev: false,
                fix_commit: "4f2a9c1d7b3e",
                repository: "https://example.test/acme/accounts",
              },
            ],
          },
        ],
      }
      const context = [
        "Security_Context",
        "- CVE-2024-0001 (CWE-89 SQL Injection): build the query with bound parameters instead of string concatenation.",
        "- CVE-2022-0003 (CWE-639 Authorization Bypass Through User-Controlled Key): compare the requested account id with the signed-in user before loading it. Fix commit 4f2a9c1d7b3e in https://example.test/acme/accounts.",
        "predicted: CWE-639",
        "retained: CWE-89, CWE-639",
      ].join("\n")
      const seek = yield* seekHarness({
        steps: [
          { agent: "main", say: "subagent", input: { prompt: "Plan for an account lookup helper" } },
          { agent: "seek", say: "retrieve", input: plan1 },
          { agent: "seek", say: "retrieve", input: plan2 },
          { agent: "seek", say: "text", text: context },
          { agent: "main", say: "text", text: "Used the security context" },
        ],
        results: [round1, round2],
      })
      yield* seek.run("Write an account lookup helper")

      // Exactly one re-planning call, holding only a replacement CWE that round 1 did not predict.
      expect(seek.mcp.calls).toEqual([plan1, plan2])
      expect(seek.toolCalls.filter((call) => call.name === seekToolName)).toHaveLength(2)
      expect(plan2.weaknesses.map((item) => item.cwe_id)).toEqual(["CWE-639"])
      expect(plan1.weaknesses.map((item) => item.cwe_id)).not.toContain("CWE-639")
      // Seek requests: round 1, round 2, final text. Main requests: subagent call, final text.
      const requests = (yield* seek.llm.requests()).filter((request) => request.tools.length > 0)
      expect(requests.filter(isSeek)).toHaveLength(3)
      expect(requests.filter((request) => !isSeek(request))).toHaveLength(2)

      // The main agent's last request carries the subagent's tool result: the seek child's final assistant text.
      const delivered = requests
        .filter((request) => !isSeek(request))
        .at(-1)
        ?.messages.flatMap((message) => (message.role === "tool" ? message.content : []))
        .flatMap((part) => (part.type === "tool-result" && part.name === subagentName ? [part.result] : []))
      expect(delivered).toHaveLength(1)
      const text = JSON.stringify(delivered?.[0])
      expect(delivered?.[0]).toMatchObject({ type: "text" })
      expect(text).toContain("Security_Context")
      expect(text).toContain("predicted: CWE-639")
      expect(text).toContain("retained: CWE-89, CWE-639")

      // Every id, name and fix commit in the context comes from a tool result of this run.
      const candidates = [round1, round2].flatMap((result) => result.units.flatMap((unit) => unit.candidates))
      const retained = candidates.filter((candidate) => text.includes(candidate.cve_id))
      expect(retained.map((candidate) => candidate.cve_id)).toEqual(["CVE-2024-0001", "CVE-2022-0003"])
      expect(Array.from(text.matchAll(/CVE-\d{4}-\d{4,}/g), (match) => match[0])).toEqual(retained.map((candidate) => candidate.cve_id))
      retained.forEach((candidate) => {
        expect(text).toContain(candidate.cwe_name)
        if (candidate.fix_commit) expect(text).toContain(candidate.fix_commit)
      })
      expect(Array.from(text.matchAll(/\b[0-9a-f]{12}\b/g), (match) => match[0])).toEqual(["4f2a9c1d7b3e"])
      // The dropped round 1 candidate does not reach the answer.
      expect(text).not.toContain("CVE-2023-0002")
      expect(text.length).toBeLessThanOrEqual(4000)
    }),
  )
  it.live("reports no augmentation when the CVE graph is unavailable and the main agent continues", () =>
    Effect.gen(function* () {
      const plan = {
        language: "TypeScript",
        reasoning: "The helper builds a SQL query from a request parameter.",
        weaknesses: [
          {
            cwe_id: "CWE-89",
            root_cause: "The login helper concatenates the username request parameter into the SQL text.",
            code_snippet: 'db.query("SELECT * FROM users WHERE name = \'" + username + "\'")',
          },
        ],
      }
      const unavailable: SeekResult = {
        status: "cve_unavailable",
        top_k: 4,
        error: { category: "unreachable", message: "The CVE graph could not be reached." },
        units: [{ cwe_id: "CWE-89", status: "unavailable", scope: ["CWE-89"], expanded: false, candidates: [] }],
      }
      const seek = yield* seekHarness({
        steps: [
          { agent: "main", say: "subagent", input: { prompt: "Plan for a login query helper" } },
          { agent: "seek", say: "retrieve", input: plan },
          { agent: "seek", say: "text", text: "No augmentation applies: the CVE graph is unavailable for this request." },
          { agent: "main", say: "text", text: "Continued without security context" },
        ],
        results: [unavailable],
      })
      yield* seek.run("Write a login query helper")

      // One tool call, no retry.
      expect(seek.mcp.calls).toEqual([plan])
      expect(seek.toolCalls.filter((call) => call.name === seekToolName)).toHaveLength(1)

      // Seek requests: one retrieve, one final text. Main requests: subagent call, final text.
      const requests = (yield* seek.llm.requests()).filter((request) => request.tools.length > 0)
      expect(requests.filter(isSeek)).toHaveLength(2)
      const mainRequests = requests.filter((request) => !isSeek(request))
      expect(mainRequests).toHaveLength(2)

      // The seek child's tool result is the unavailable status, delivered to it as a non-error result.
      const seekResults = requests
        .filter(isSeek)
        .at(-1)
        ?.messages.flatMap((message) => (message.role === "tool" ? message.content : []))
        .flatMap((part) => (part.type === "tool-result" && part.name === seekToolName ? [part.result] : []))
      expect(seekResults).toHaveLength(1)
      expect(JSON.stringify(seekResults?.[0])).toContain("cve_unavailable")

      // The main agent receives the final text as an ordinary, non-error subagent result.
      const delivered = mainRequests
        .at(-1)
        ?.messages.flatMap((message) => (message.role === "tool" ? message.content : []))
        .flatMap((part) => (part.type === "tool-result" && part.name === subagentName ? [part.result] : []))
      expect(delivered).toHaveLength(1)
      expect(delivered?.[0]).toMatchObject({ type: "text" })
      const text = JSON.stringify(delivered?.[0])
      expect(text).toContain("No augmentation applies")
      expect(text).not.toMatch(/CVE-\d{4}-\d{4,}/)
      expect(text).not.toMatch(/CWE-\d+/)
      expect(text).not.toMatch(/\b[0-9a-f]{12}\b/)
      expect(text).not.toContain("Security_Context")

      // The main agent continued in the same session: no new session and no error in the final state.
      expect(yield* seek.children).toHaveLength(1)
    }),
  )
})
