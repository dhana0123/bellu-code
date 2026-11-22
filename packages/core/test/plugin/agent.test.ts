import path from "path"
import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { SystemPart } from "@bellucode/ai/effect"
import { Agent } from "@bellucode/core/agent"
import { App } from "@bellucode/core/app"
import { Config } from "@bellucode/core/config"
import { Database } from "@bellucode/core/database/database"
import { Bus } from "@bellucode/core/bus"
import { AppNodeBuilder } from "@bellucode/core/effect/app-node-builder"
import { Flag } from "@bellucode/core/flag"
import { Job } from "@bellucode/core/job"
import { Location } from "@bellucode/core/location"
import { LocationServiceMap } from "@bellucode/core/location-service-map"
import { Model } from "@bellucode/core/model"
import { Permission } from "@bellucode/core/permission"
import { Plugin } from "@bellucode/core/plugin"
import { AgentPlugin } from "@bellucode/core/plugin/agent"
import { PluginHooks } from "@bellucode/core/plugin/hooks"
import { PluginSupervisor } from "@bellucode/core/plugin/supervisor"
import { Provider } from "@bellucode/core/provider"
import { AbsolutePath } from "@bellucode/core/schema"
import { Session } from "@bellucode/core/session"
import { SessionExecution } from "@bellucode/core/session/execution"
import { SubagentJob } from "@bellucode/core/session/subagent-job"
import { Tool } from "@bellucode/core/tool"
import { SubagentTool } from "@bellucode/core/tool/plugin/subagent"
import { makeLocationNode } from "@bellucode/util/effect/app-node"
import { LayerNode } from "@bellucode/util/effect/layer-node"
import { Global } from "@bellucode/util/global"
import { tempGlobalLayer } from "../fixture/global"
import { offlineModels } from "../fixture/models"
import { tmpdirScoped } from "../fixture/tmpdir"
import { testEffect } from "../lib/effect"
import { executeTool, registerToolPlugin, toolIdentity } from "../lib/tool"
import { agentHost, host } from "./host"

const seekTool = "bellu-graph_seek_retrieve"
const parentModel = Model.Ref.make({ id: Model.ID.make("parent"), providerID: Provider.ID.make("test") })

// The child never needs to run: these tests only look at the session the subagent tool creates.
const idleExecution = Layer.succeed(
  SessionExecution.Service,
  SessionExecution.Service.of({
    active: Effect.succeed(new Set()),
    isActive: () => Effect.succeed(false),
    resume: () => Effect.void,
    wake: () => Effect.void,
    interrupt: () => Effect.succeed(false),
    awaitIdle: () => Effect.void,
  }),
)

// Stands in for the plugin supervisor. It installs the real subagent tool and the real agent plugin on the location's
// own services, after a stand-in for the bellu-graph MCP tool is registered, which is the order McpTool gives.
const plugins = makeLocationNode({
  name: "test/seek-plugins",
  layer: Layer.effectDiscard(
    Effect.gen(function* () {
      const agents = yield* Agent.Service
      const hooks = yield* PluginHooks.Service
      const tools = yield* Tool.Service
      yield* tools.transform((editor) =>
        editor.add({
          name: "seek_retrieve",
          options: { namespace: "bellu-graph", codemode: false },
          description: "Stand-in for the bellud seek_retrieve tool",
          input: { type: "object" },
          output: {},
          execute: () => Effect.succeed({ output: {}, content: [] }),
        }),
      )
      yield* registerToolPlugin(
        SubagentTool.Plugin,
        { session: { hook: (name, callback) => hooks.register("session", name, callback) } },
        (name, callback) => hooks.register("tool", name, callback),
      )
      yield* AgentPlugin.Plugin.effect(
        host({
          agent: agentHost(agents),
          tool: {
            transform: tools.transform,
            reload: tools.reload,
            list: tools.list,
            hook: () => Effect.die("unused tool.hook"),
          },
        }),
      )
    }),
  ),
  deps: [
    Agent.node,
    App.node,
    Config.node,
    Flag.node,
    Job.node,
    Model.node,
    Permission.node,
    Session.node,
    SubagentJob.node,
    Tool.node,
    PluginHooks.node,
  ],
})

const nodes = LayerNode.group([Database.node, Bus.node, Job.node, Session.node, LocationServiceMap.node])
const replacements = (flags?: string) =>
  [
    SessionExecution.node.replace(idleExecution),
    Global.node.replace(tempGlobalLayer),
    offlineModels,
    // Flags are off on the default test channel, so a project's `experimental.seek_planner: true` turns the flag on.
    App.node.replace(App.configured({ channel: "unknown" })),
    PluginSupervisor.node.replace(plugins),
    ...(flags === undefined
      ? []
      : [Flag.node.replace(Layer.provide(Flag.layer, Layer.succeed(Flag.Overrides, flags)) as never)]),
  ] satisfies LayerNode.Replacements

// `-seek_planner` in BELLUCODE_FLAGS is read by the Flag service when the location builds.
const it = testEffect(AppNodeBuilder.build(nodes, replacements()))
const envOff = testEffect(AppNodeBuilder.build(nodes, replacements("-seek_planner")))

const open = (experimental?: { readonly seek_planner: boolean }) =>
  Effect.gen(function* () {
    const dir = yield* tmpdirScoped()
    if (experimental)
      yield* Effect.promise(() => Bun.write(path.join(dir.path, "bellucode.json"), JSON.stringify({ experimental })))
    const sessions = yield* Session.Service
    const parent = yield* sessions.create({
      location: Location.Ref.make({ directory: AbsolutePath.make(dir.path) }),
      model: parentModel,
    })
    const locations = yield* LocationServiceMap.Service
    const at = <A, E, R>(effect: Effect.Effect<A, E, R>) => effect.pipe(Effect.provide(locations.get(parent.location)))
    yield* at(Plugin.Service.use((loaded) => loaded.awaitActivation))
    const registry = yield* at(Tool.Service.use((tools) => Effect.succeed(tools)))
    return {
      sessions,
      parent,
      at,
      registry,
      flag: at(Flag.enabled("seek_planner")),
      agents: at(Agent.Service.use((agents) => agents.list())),
      main: at(Agent.Service.use((agents) => agents.get(Agent.defaultID))),
      // CodeMode's own `execute` tool is always present and unrelated to the feature.
      tools: registry.snapshot().pipe(
        Effect.map((snapshot) =>
          snapshot.definitions
            .map((tool) => tool.name)
            .filter((name) => name !== "execute")
            .toSorted(),
        ),
      ),
      subagents: at(
        Agent.Service.use((agents) => agents.list()).pipe(
          Effect.map((list) =>
            list
              .filter((agent) => agent.mode === "subagent")
              .map((agent) => String(agent.id))
              .toSorted(),
          ),
        ),
      ),
      // The description the model sees comes from the session context hook, as in production.
      description: at(
        PluginHooks.Service.use((hooks) =>
          hooks.trigger("session", "context", {
            sessionID: parent.id,
            agent: toolIdentity.agent,
            model: parentModel,
            system: [SystemPart.make("prompt")],
            messages: [],
            options: {},
            tools: { [SubagentTool.name]: { description: SubagentTool.description, input: { type: "object" } } },
          }),
        ).pipe(Effect.map((event) => event.tools[SubagentTool.name]?.description ?? "")),
      ),
      subagent: (agent: string, background = false) =>
        executeTool(registry, {
          sessionID: parent.id,
          ...toolIdentity,
          call: {
            type: "tool-call",
            id: `call-${agent}`,
            name: SubagentTool.name,
            input: { agent, description: "seek planning", prompt: "plan", background },
          },
        }),
      children: sessions.list({ parentID: parent.id }).pipe(Effect.map((page) => page.data)),
    }
  })

// The state every flag-off route must produce: the registry and agents as they were before the feature.
const withoutFeature = {
  agents: ["build", "compaction", "explore", "general", "summary", "title"],
  subagents: ["explore", "general"],
  tools: ["subagent"],
}

const expectAbsent = (session: Effect.Success<ReturnType<typeof open>>) =>
  Effect.gen(function* () {
    expect(yield* session.flag).toBe(false)
    expect((yield* session.agents).map((agent) => String(agent.id)).toSorted()).toEqual(withoutFeature.agents)
    expect(yield* session.subagents).toEqual(withoutFeature.subagents)
    expect(yield* session.tools).toEqual(withoutFeature.tools)
    expect(yield* session.description).not.toContain("seek")
    expect(yield* session.subagent("seek")).toEqual({
      status: "error",
      error: { type: "tool.execution", message: "Unknown agent: seek" },
    })
    expect(yield* session.children).toHaveLength(0)
    expect((yield* session.main)?.permissions.some((rule) => rule.action.includes("seek"))).toBe(false)
  })

describe("seek agent", () => {
  it.live("is registered as a restricted subagent when the flag is on", () =>
    Effect.gen(function* () {
      const session = yield* open({ seek_planner: true })
      expect(yield* session.flag).toBe(true)
      const seek = (yield* session.agents).find((agent) => agent.id === Agent.ID.make("seek"))
      if (!seek) throw new Error("expected the seek agent")
      expect(seek.mode).toBe("subagent")
      expect(seek.description?.length).toBeGreaterThanOrEqual(1)
      expect(seek.description?.length).toBeLessThanOrEqual(200)
      expect(seek.steps).toBe(4)
      expect(seek.model).toBeUndefined()
      // Defaults come first; from the last `*` rule on, the agent's own rules are exactly these three, in order.
      expect(seek.permissions.slice(seek.permissions.findLastIndex((rule) => rule.action === "*"))).toEqual([
        { action: "*", resource: "*", effect: "deny" },
        { action: seekTool, resource: "*", effect: "allow" },
        { action: "subagent", resource: "*", effect: "deny" },
      ])
      expect(Permission.evaluate(seekTool, "*", seek.permissions).effect).toBe("allow")
      for (const action of ["read", "shell", "grep", "edit", "webfetch", "subagent", "bellu-graph_other"])
        expect(Permission.evaluate(action, "*", seek.permissions).effect).toBe("deny")
    }),
  )

  it.live("is listed in the subagent tool description and in the registry when the flag is on", () =>
    Effect.gen(function* () {
      const session = yield* open({ seek_planner: true })
      expect(yield* session.subagents).toEqual(["explore", "general", "seek"])
      expect(yield* session.tools).toEqual([seekTool, "subagent"])
      expect(yield* session.description).toMatch(/^- seek: .+$/m)
    }),
  )

  it.live("runs a seek child session on the parent's provider and model", () =>
    Effect.gen(function* () {
      const session = yield* open({ seek_planner: true })
      const started = yield* session.subagent("seek", true)
      expect(started.status).toBe("completed")
      const children = yield* session.children
      expect(children).toHaveLength(1)
      expect(children[0]).toMatchObject({
        agent: "seek",
        model: { providerID: parentModel.providerID, id: parentModel.id },
      })
    }),
  )

  it.live("is absent when experimental.seek_planner is false", () =>
    Effect.gen(function* () {
      yield* expectAbsent(yield* open({ seek_planner: false }))
    }),
  )

  envOff.live("is absent when BELLUCODE_FLAGS contains -seek_planner", () =>
    Effect.gen(function* () {
      yield* expectAbsent(yield* open({ seek_planner: true }))
    }),
  )

  it.live("leaves the main agent, subagents and tools as they are without the feature when the flag is off", () =>
    Effect.gen(function* () {
      const on = yield* open({ seek_planner: true })
      const off = yield* open({ seek_planner: false })
      expect((yield* off.main)?.permissions).toEqual((yield* on.main)?.permissions)
      expect((yield* off.subagents).filter((id) => id !== "seek")).toEqual(yield* off.subagents)
      expect((yield* on.subagents).filter((id) => id !== "seek")).toEqual(yield* off.subagents)
      expect((yield* on.tools).filter((name) => name !== seekTool)).toEqual(yield* off.tools)
    }),
  )
})
