import { Agent } from "@bellucode/core/agent"
import { App } from "@bellucode/core/app"
import { Artifact } from "@bellucode/core/artifact"
import { AISDK } from "@bellucode/core/aisdk"
import { Command } from "@bellucode/core/command"
import { Config } from "@bellucode/core/config"
import { Credential } from "@bellucode/core/credential"
import { Database } from "@bellucode/core/database/database"
import { Environment } from "@bellucode/core/environment/index"
import { FileAccess } from "@bellucode/core/file-access"
import { Flag } from "@bellucode/core/flag"
import { LayerNodePlatform } from "@bellucode/util/effect/app-node-platform"
import { AppProcess } from "@bellucode/util/process"
import { LayerNode } from "@bellucode/util/effect/layer-node"
import { Bus } from "@bellucode/core/bus"
import { FileSystem } from "@bellucode/core/filesystem"
import { FSUtil } from "@bellucode/util/fs-util"
import { Global } from "@bellucode/util/global"
import { Form } from "@bellucode/core/form"
import { Generate } from "@bellucode/core/generate"
import { InstructionDiscovery } from "@bellucode/core/instruction-discovery"
import { Integration } from "@bellucode/core/integration"
import { Job } from "@bellucode/core/job"
import { KV } from "@bellucode/core/kv"
import { Location } from "@bellucode/core/location"
import { Mcp } from "@bellucode/core/mcp/index"
import { Model } from "@bellucode/core/model"
import { Npm } from "@bellucode/util/npm"
import { Plugin } from "@bellucode/core/plugin"
import { PluginHooks } from "@bellucode/core/plugin/hooks"
import { Provider } from "@bellucode/core/provider"
import { Session } from "@bellucode/core/session"
import { SharedCache } from "@bellucode/core/shared-cache"
import { InstructionEntry } from "@bellucode/core/session/instruction-entry"
import { PersistentPty } from "@bellucode/core/persistent-pty"
import { LocationServiceMap } from "@bellucode/core/location-service-map"
import { AppNodeBuilder } from "@bellucode/core/effect/app-node-builder"
import { Permission } from "@bellucode/core/permission"
import { Reference } from "@bellucode/core/reference"
import { Rpc } from "@bellucode/core/rpc"
import { Skill } from "@bellucode/core/skill"
import { SkillDiscovery } from "@bellucode/core/skill/discovery"
import { Watcher } from "@bellucode/core/filesystem/watcher"
import { Tool } from "@bellucode/core/tool"
import { Vcs } from "@bellucode/core/vcs"
import { WebSearch } from "@bellucode/core/websearch"
import { Worktree } from "@bellucode/core/worktree"
import { WorktreeStrategies } from "@bellucode/core/worktree/strategies"
import { Effect, Layer } from "effect"
import { tempLocationLayer } from "../fixture/location"
import { emptyMcpLayer } from "../fixture/mcp"
import { offlineModels } from "../fixture/models"

const npmLayer = Layer.succeed(
  Npm.Service,
  Npm.Service.of({
    add: (name) => Effect.succeed({ directory: "", name }),
    resolve: (name) => Effect.succeed({ directory: "", name }),
    check: () => Effect.succeed(false),
    update: (name) => Effect.succeed({ directory: "", name }),
    which: () => Effect.undefined,
  }),
)

const generateLayer = Layer.succeed(
  Generate.Service,
  Generate.Service.of({
    text: () => Effect.succeed(""),
    image: () => Effect.die("unused"),
    decisions: () => Effect.die("unused"),
  }),
)

const configLayer = Config.testLayer()

const permissionLayer = Layer.succeed(
  Permission.Service,
  Permission.Service.of({
    close: Effect.void,
    ask: (input) => Effect.succeed({ id: input.id ?? Permission.ID.create(), effect: "ask" }),
    assert: () => Effect.void,
    assertNotDenied: () => Effect.void,
    allows: () => Effect.succeed(false),
    reply: () => Effect.void,
    get: () => Effect.succeed(undefined),
    forSession: () => Effect.succeed([]),
    list: () => Effect.succeed([]),
  }),
)

export const makePluginTestLayer = (permission = permissionLayer, generate = generateLayer) =>
  AppNodeBuilder.build(
    LayerNode.group([
      App.node,
      AppProcess.node,
      FileSystem.node,
      FSUtil.node,
      Location.node,
      Npm.node,
      Credential.node,
      Config.node,
      Flag.node,
      Database.node,
      Environment.node,
      FileAccess.node,
      Global.node,
      Bus.node,
      Form.node,
      Generate.node,
      LayerNodePlatform.httpClient,
      Plugin.node,
      Agent.node,
      Artifact.node,
      AISDK.node,
      Provider.node,
      Model.node,
      Command.node,
      InstructionDiscovery.node,
      Integration.node,
      Job.node,
      KV.node,
      Mcp.node,
      Session.node,
      SharedCache.node,
      InstructionEntry.node,
      PersistentPty.node,
      LocationServiceMap.node,
      Permission.node,
      PluginHooks.node,
      Reference.node,
      Rpc.node,
      Skill.node,
      SkillDiscovery.node,
      Tool.node,
      Vcs.node,
      Watcher.node,
      WebSearch.node,
      Worktree.node,
      WorktreeStrategies.node,
    ]),
    [
      Location.node.replace(tempLocationLayer),
      Npm.node.replace(npmLayer),
      Config.node.replace(configLayer),
      Mcp.node.replace(emptyMcpLayer),
      Generate.node.replace(generate),
      Permission.node.replace(permission),
      offlineModels,
    ],
  ).pipe(Layer.provideMerge(configLayer))

export const PluginTestLayer = makePluginTestLayer()
