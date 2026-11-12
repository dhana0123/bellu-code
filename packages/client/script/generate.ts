import { NodeFileSystem } from "@effect/platform-node"
import { compile, emitEffectImported, emitEffectShape, emitPromise, write } from "@bellucode/httpapi-codegen"
import {
  ClientApi,
  clientNamespace,
  effectOmitEndpoints,
  groupNames,
  promiseOmitEndpoints,
} from "@bellucode/protocol/client"
import { Agent } from "@bellucode/schema/agent"
import { Artifact } from "@bellucode/schema/artifact"
import { Command } from "@bellucode/schema/command"
import { Config } from "@bellucode/schema/config"
import { Credential } from "@bellucode/schema/credential"
import { Event } from "@bellucode/schema/event"
import { EventLog } from "@bellucode/schema/event-log"
import { FileDiff } from "@bellucode/schema/file-diff"
import { FileSystem } from "@bellucode/schema/filesystem"
import { Form } from "@bellucode/schema/form"
import { Generate } from "@bellucode/schema/generate"
import { Instruction } from "@bellucode/schema/instruction"
import { InstructionEntry } from "@bellucode/schema/instruction-entry"
import { Integration } from "@bellucode/schema/integration"
import { Job } from "@bellucode/schema/job"
import { Location } from "@bellucode/schema/location"
import { Mcp } from "@bellucode/schema/mcp"
import { Model } from "@bellucode/schema/model"
import { Money } from "@bellucode/schema/money"
import { Permission } from "@bellucode/schema/permission"
import { PermissionSaved } from "@bellucode/schema/permission-saved"
import { Plugin } from "@bellucode/schema/plugin"
import { Project } from "@bellucode/schema/project"
import { Worktree } from "@bellucode/schema/worktree"
import { AgentAttachment, FileAttachment, Prompt, PromptMention } from "@bellucode/schema/prompt"
import { PromptInput } from "@bellucode/schema/prompt-input"
import { Provider } from "@bellucode/schema/provider"
import { Pty } from "@bellucode/schema/pty"
import { PtyTicket } from "@bellucode/schema/pty-ticket"
import { Question } from "@bellucode/schema/question"
import { Reference } from "@bellucode/schema/reference"
import { AbsolutePath, RelativePath } from "@bellucode/schema/schema"
import { Schedule } from "@bellucode/schema/schedule"
import { Session } from "@bellucode/schema/session"
import { SessionMessage } from "@bellucode/schema/session-message"
import { SessionInbox } from "@bellucode/schema/session-inbox"
import { Shell } from "@bellucode/schema/shell"
import { Skill } from "@bellucode/schema/skill"
import { Snapshot } from "@bellucode/schema/snapshot"
import { UsageLimits } from "@bellucode/schema/usage-limits"
import { Vcs } from "@bellucode/schema/vcs"
import { WebSearch } from "@bellucode/schema/websearch"
import { Workspace } from "@bellucode/schema/workspace"
import { Effect, Schema } from "effect"
import { fileURLToPath } from "url"

const promiseContract = compile(ClientApi, {
  groupNames,
  omitEndpoints: promiseOmitEndpoints,
  namespace: clientNamespace,
  aliases: true,
})
const effectContract = compile(ClientApi, {
  groupNames,
  omitEndpoints: effectOmitEndpoints,
  namespace: clientNamespace,
  aliases: true,
})
const effectTypeReferences = [
  ...namespaceTypes("Agent", "@bellucode/schema/agent", Agent),
  ...namespaceTypes("Artifact", "@bellucode/schema/artifact", Artifact),
  ...namespaceTypes("Command", "@bellucode/schema/command", Command),
  ...namespaceTypes("Config", "@bellucode/schema/config", Config),
  ...namespaceTypes("Credential", "@bellucode/schema/credential", Credential),
  ...namespaceTypes("Event", "@bellucode/schema/event", Event),
  ...namespaceTypes("EventLog", "@bellucode/schema/event-log", EventLog),
  ...namespaceTypes("FileDiff", "@bellucode/schema/file-diff", FileDiff),
  ...namespaceTypes("FileSystem", "@bellucode/schema/filesystem", FileSystem),
  ...namespaceTypes("Form", "@bellucode/schema/form", Form),
  ...namespaceTypes("Generate", "@bellucode/schema/generate", Generate),
  ...namespaceTypes("Instruction", "@bellucode/schema/instruction", Instruction),
  ...namespaceTypes("InstructionEntry", "@bellucode/schema/instruction-entry", InstructionEntry),
  ...namespaceTypes("Integration", "@bellucode/schema/integration", Integration),
  ...namespaceTypes("Job", "@bellucode/schema/job", Job),
  typeReference("Location.PublicRef", "@bellucode/schema/location", Location.PublicRef),
  typeReference("Location.PublicInfo", "@bellucode/schema/location", Location.PublicInfo),
  ...namespaceTypes("Mcp", "@bellucode/schema/mcp", Mcp),
  ...namespaceTypes("Model", "@bellucode/schema/model", Model),
  ...namespaceTypes("Money", "@bellucode/schema/money", Money),
  ...namespaceTypes("Permission", "@bellucode/schema/permission", Permission),
  ...namespaceTypes("PermissionSaved", "@bellucode/schema/permission-saved", PermissionSaved),
  ...namespaceTypes("Plugin", "@bellucode/schema/plugin", Plugin),
  ...namespaceTypes("Project", "@bellucode/schema/project", Project),
  ...namespaceTypes("Worktree", "@bellucode/schema/worktree", Worktree),
  ...namespaceTypes("PromptInput", "@bellucode/schema/prompt-input", PromptInput),
  ...namespaceTypes("Provider", "@bellucode/schema/provider", Provider),
  ...namespaceTypes("Pty", "@bellucode/schema/pty", Pty),
  ...namespaceTypes("PtyTicket", "@bellucode/schema/pty-ticket", PtyTicket),
  ...namespaceTypes("Question", "@bellucode/schema/question", Question),
  ...namespaceTypes("Reference", "@bellucode/schema/reference", Reference),
  ...namespaceTypes("Schedule", "@bellucode/schema/schedule", Schedule),
  ...namespaceTypes("Session", "@bellucode/schema/session", Session),
  ...namespaceTypes("SessionMessage", "@bellucode/schema/session-message", SessionMessage),
  ...namespaceTypes("SessionInbox", "@bellucode/schema/session-inbox", SessionInbox),
  ...namespaceTypes("Shell", "@bellucode/schema/shell", Shell),
  ...namespaceTypes("Skill", "@bellucode/schema/skill", Skill),
  ...namespaceTypes("Snapshot", "@bellucode/schema/snapshot", Snapshot),
  ...namespaceTypes("UsageLimits", "@bellucode/schema/usage-limits", UsageLimits),
  ...namespaceTypes("Vcs", "@bellucode/schema/vcs", Vcs),
  ...namespaceTypes("WebSearch", "@bellucode/schema/websearch", WebSearch),
  ...namespaceTypes("Workspace", "@bellucode/schema/workspace", Workspace),
  typeReference("Prompt", "@bellucode/schema/prompt", Prompt),
  typeReference("PromptMention", "@bellucode/schema/prompt", PromptMention),
  typeReference("FileAttachment", "@bellucode/schema/prompt", FileAttachment),
  typeReference("AgentAttachment", "@bellucode/schema/prompt", AgentAttachment),
  typeReference("AbsolutePath", "@bellucode/schema/schema", AbsolutePath),
  typeReference("RelativePath", "@bellucode/schema/schema", RelativePath),
]

await Effect.runPromise(
  Effect.all(
    [
      write(
        emitPromise(promiseContract, {
          mutableOutputs: true,
        }),
        fileURLToPath(new URL("../src/promise/generated", import.meta.url)),
      ),
      write(
        emitEffectImported(effectContract, {
          module: "../../contract",
          api: "ClientApi",
          shapeModule: "../api/api.js",
        }),
        fileURLToPath(new URL("../src/effect/generated", import.meta.url)),
      ),
      write(
        emitEffectShape(effectContract, {
          typeReferences: effectTypeReferences,
          outputTypes: {
            "event.subscribe": {
              name: "BelluCodeEvent",
              import: 'import type { BelluCodeEvent } from "@bellucode/protocol/groups/event"',
            },
          },
        }),
        fileURLToPath(new URL("../src/effect/api", import.meta.url)),
      ),
    ],
    { concurrency: 3, discard: true },
  ).pipe(Effect.provide(NodeFileSystem.layer)),
)

function namespaceTypes(namespace: string, module: string, values: object) {
  return Object.entries(values).flatMap(([name, schema]) =>
    Schema.isSchema(schema) ? [typeReference(`${namespace}.${name}`, module, schema)] : [],
  )
}

function typeReference(name: string, module: string, schema: Schema.Top) {
  return {
    schema,
    name,
    import: `import type { ${name.split(".")[0]} } from ${JSON.stringify(module)}`,
  }
}
