// TODO: Keep additional network capabilities inside Schema and Protocol as the client grows; /effect must never import
// Core or Server. Preserve these datatype exports so internal model reorganizations do not require caller migrations.
import type { Effect } from "effect"
import type { BelluCode } from "./client.js"

export * from "./generated/index"
export { BelluCode } from "./client.js"
export type {
  AgentApi,
  AppApi,
  CommandApi,
  ConfigApi,
  EventApi,
  IntegrationApi,
  ModelApi,
  PluginApi,
  ProviderApi,
  ReferenceApi,
  RpcApi,
  RpcClient,
  WebSearchApi,
  SessionApi,
  SkillApi,
} from "./api.js"
export { Agent } from "@bellucode/schema/agent"
export { Command } from "@bellucode/schema/command"
export { Config } from "@bellucode/schema/config"
export { Credential } from "@bellucode/schema/credential"
export { Event } from "@bellucode/schema/event"
export { EventLog } from "@bellucode/schema/event-log"
export { FileSystem } from "@bellucode/schema/filesystem"
export { Form } from "@bellucode/schema/form"
export { Integration } from "@bellucode/schema/integration"
export { Location } from "@bellucode/schema/location"
export { Model } from "@bellucode/schema/model"
export { Permission } from "@bellucode/schema/permission"
export { PermissionSaved } from "@bellucode/schema/permission-saved"
export { Project } from "@bellucode/schema/project"
export { Worktree } from "@bellucode/schema/worktree"
export { Vcs } from "@bellucode/schema/vcs"
export { Provider } from "@bellucode/schema/provider"
export { Pty } from "@bellucode/schema/pty"
export { Question } from "@bellucode/schema/question"
export { Reference } from "@bellucode/schema/reference"
export { WebSearch } from "@bellucode/schema/websearch"
export { AbsolutePath, RelativePath } from "@bellucode/schema/schema"
export { Session } from "@bellucode/schema/session"
export { SessionInbox } from "@bellucode/schema/session-inbox"
export { SessionMessage } from "@bellucode/schema/session-message"
export { Skill } from "@bellucode/schema/skill"
export { Prompt } from "@bellucode/schema/prompt"
export { PromptInput } from "@bellucode/schema/prompt-input"
export type { BelluCodeEvent } from "@bellucode/protocol/groups/event"
export type BelluCodeClient = Effect.Success<ReturnType<typeof BelluCode.make>>
