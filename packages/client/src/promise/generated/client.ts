import type {
  ServerInfoOutput,
  ServerPairOutput,
  ServerConnectInput,
  ServerConnectOutput,
  LocationGetInput,
  LocationGetOutput,
  LocationReloadOutput,
  AgentListInput,
  AgentListOutput,
  AgentGetInput,
  AgentGetOutput,
  PluginListInput,
  PluginListOutput,
  PluginGuiInput,
  PluginGuiOutput,
  PluginCheckInput,
  PluginCheckOutput,
  PluginUpdateInput,
  PluginUpdateOutput,
  SessionListInput,
  SessionListOutput,
  SessionCreateInput,
  SessionCreateOutput,
  SessionActiveOutput,
  SessionGetInput,
  SessionGetOutput,
  SessionRemoveInput,
  SessionRemoveOutput,
  SessionForkInput,
  SessionForkOutput,
  SessionSwitchAgentInput,
  SessionSwitchAgentOutput,
  SessionSwitchModelInput,
  SessionSwitchModelOutput,
  SessionUpdateInput,
  SessionUpdateOutput,
  SessionMoveInput,
  SessionMoveOutput,
  SessionPromptInput,
  SessionPromptOutput,
  SessionCommandInput,
  SessionCommandOutput,
  SessionSyntheticInput,
  SessionSyntheticOutput,
  SessionShellInput,
  SessionShellOutput,
  SessionCompactInput,
  SessionCompactOutput,
  SessionRevertStageInput,
  SessionRevertStageOutput,
  SessionRevertClearInput,
  SessionRevertClearOutput,
  SessionRevertCommitInput,
  SessionRevertCommitOutput,
  SessionContextInput,
  SessionContextOutput,
  SessionDiffInput,
  SessionDiffOutput,
  SessionInboxListInput,
  SessionInboxListOutput,
  SessionInboxCancelInput,
  SessionInboxCancelOutput,
  SessionInboxUpdateInput,
  SessionInboxUpdateOutput,
  SessionGenerateInput,
  SessionGenerateOutput,
  SessionInterruptInput,
  SessionInterruptOutput,
  SessionBackgroundInput,
  SessionBackgroundOutput,
  SessionMessageGetInput,
  SessionMessageGetOutput,
  SessionFormListInput,
  SessionFormListOutput,
  SessionFormCreateInput,
  SessionFormCreateOutput,
  SessionFormGetInput,
  SessionFormGetOutput,
  SessionFormReplyInput,
  SessionFormReplyOutput,
  SessionFormCancelInput,
  SessionFormCancelOutput,
  SessionEnvironmentInput,
  SessionEnvironmentOutput,
  SessionViewInput,
  SessionViewOutput,
  ExperimentalSessionStatsInput,
  ExperimentalSessionStatsOutput,
  ExperimentalSessionImportInput,
  ExperimentalSessionImportOutput,
  ExperimentalSessionExportInput,
  ExperimentalSessionExportOutput,
  ExperimentalSessionSkillInput,
  ExperimentalSessionSkillOutput,
  ExperimentalSessionWaitInput,
  ExperimentalSessionWaitOutput,
  ExperimentalSessionInstructionsEntryListInput,
  ExperimentalSessionInstructionsEntryListOutput,
  ExperimentalSessionInstructionsEntryPutInput,
  ExperimentalSessionInstructionsEntryPutOutput,
  ExperimentalSessionInstructionsEntryRemoveInput,
  ExperimentalSessionInstructionsEntryRemoveOutput,
  ExperimentalSessionLogInput,
  ExperimentalSessionLogOutput,
  MessageListInput,
  MessageListOutput,
  ModelListInput,
  ModelListOutput,
  ModelDefaultInput,
  ModelDefaultOutput,
  ExperimentalGenerateTextInput,
  ExperimentalGenerateTextOutput,
  ExperimentalGenerateImageInput,
  ExperimentalGenerateImageOutput,
  ExperimentalGenerateDecisionsInput,
  ExperimentalGenerateDecisionsOutput,
  ExperimentalVoiceModelsOutput,
  ExperimentalVoiceSessionInput,
  ExperimentalVoiceSessionOutput,
  ProviderListInput,
  ProviderListOutput,
  ProviderGetInput,
  ProviderGetOutput,
  IntegrationListInput,
  IntegrationListOutput,
  IntegrationGetInput,
  IntegrationGetOutput,
  IntegrationConnectKeyInput,
  IntegrationConnectKeyOutput,
  IntegrationConnectExternalInput,
  IntegrationConnectExternalOutput,
  IntegrationOauthConnectInput,
  IntegrationOauthConnectOutput,
  IntegrationOauthStatusInput,
  IntegrationOauthStatusOutput,
  IntegrationOauthCompleteInput,
  IntegrationOauthCompleteOutput,
  IntegrationOauthCancelInput,
  IntegrationOauthCancelOutput,
  IntegrationCommandConnectInput,
  IntegrationCommandConnectOutput,
  IntegrationCommandStatusInput,
  IntegrationCommandStatusOutput,
  IntegrationCommandCancelInput,
  IntegrationCommandCancelOutput,
  ExperimentalIntegrationWellknownAddInput,
  ExperimentalIntegrationWellknownAddOutput,
  McpListInput,
  McpListOutput,
  McpResourceCatalogInput,
  McpResourceCatalogOutput,
  ExperimentalMcpAddInput,
  ExperimentalMcpAddOutput,
  ExperimentalMcpRemoveInput,
  ExperimentalMcpRemoveOutput,
  ExperimentalMcpConnectInput,
  ExperimentalMcpConnectOutput,
  ExperimentalMcpDisconnectInput,
  ExperimentalMcpDisconnectOutput,
  ExperimentalMcpClientTokenInput,
  ExperimentalMcpClientTokenOutput,
  CredentialListOutput,
  CredentialCreateInput,
  CredentialCreateOutput,
  CredentialUpdateInput,
  CredentialUpdateOutput,
  CredentialActivateInput,
  CredentialActivateOutput,
  CredentialRemoveInput,
  CredentialRemoveOutput,
  ProjectListInput,
  ProjectListOutput,
  ProjectUpdateInput,
  ProjectUpdateOutput,
  FormListInput,
  FormListOutput,
  PermissionRequestListInput,
  PermissionRequestListOutput,
  PermissionSavedListInput,
  PermissionSavedListOutput,
  PermissionSavedUpdateInput,
  PermissionSavedUpdateOutput,
  PermissionSavedRemoveInput,
  PermissionSavedRemoveOutput,
  PermissionCreateInput,
  PermissionCreateOutput,
  PermissionListInput,
  PermissionListOutput,
  PermissionGetInput,
  PermissionGetOutput,
  PermissionReplyInput,
  PermissionReplyOutput,
  FileReadInput,
  FileReadOutput,
  FileListInput,
  FileListOutput,
  FileFindInput,
  FileFindOutput,
  ExperimentalFileWriteInput,
  ExperimentalFileWriteOutput,
  ExperimentalFileWatchInput,
  ExperimentalFileWatchOutput,
  ExperimentalFileUnwatchInput,
  ExperimentalFileUnwatchOutput,
  CommandListInput,
  CommandListOutput,
  SkillListInput,
  SkillListOutput,
  RpcCallInput,
  RpcCallOutput,
  EventSubscribeInput,
  EventSubscribeOutput,
  PtyListInput,
  PtyListOutput,
  PtyCreateInput,
  PtyCreateOutput,
  PtyGetInput,
  PtyGetOutput,
  PtyUpdateInput,
  PtyUpdateOutput,
  PtyRemoveInput,
  PtyRemoveOutput,
  PtyConnectTokenInput,
  PtyConnectTokenOutput,
  ExperimentalPersistentPtyReadInput,
  ExperimentalPersistentPtyReadOutput,
  ExperimentalPersistentPtyListInput,
  ExperimentalPersistentPtyListOutput,
  ExperimentalPersistentPtyCreateInput,
  ExperimentalPersistentPtyCreateOutput,
  ExperimentalPersistentPtyShutdownOutput,
  ExperimentalPersistentPtyHandoffOutput,
  ExperimentalPersistentPtyGetInput,
  ExperimentalPersistentPtyGetOutput,
  ExperimentalPersistentPtyUpdateInput,
  ExperimentalPersistentPtyUpdateOutput,
  ExperimentalPersistentPtySnapshotInput,
  ExperimentalPersistentPtySnapshotOutput,
  ExperimentalPersistentPtyRemoveInput,
  ExperimentalPersistentPtyRemoveOutput,
  ExperimentalPersistentPtyConnectTokenInput,
  ExperimentalPersistentPtyConnectTokenOutput,
  ExperimentalMediaGetInput,
  ExperimentalMediaGetOutput,
  ExperimentalScheduleCreateInput,
  ExperimentalScheduleCreateOutput,
  ExperimentalScheduleListInput,
  ExperimentalScheduleListOutput,
  ExperimentalScheduleGetInput,
  ExperimentalScheduleGetOutput,
  ExperimentalSchedulePauseInput,
  ExperimentalSchedulePauseOutput,
  ExperimentalScheduleResumeInput,
  ExperimentalScheduleResumeOutput,
  ExperimentalScheduleDeleteInput,
  ExperimentalScheduleDeleteOutput,
  ExperimentalArtifactsProvidersInput,
  ExperimentalArtifactsProvidersOutput,
  ExperimentalArtifactsListInput,
  ExperimentalArtifactsListOutput,
  ExperimentalArtifactsCreateInput,
  ExperimentalArtifactsCreateOutput,
  ExperimentalArtifactsGetInput,
  ExperimentalArtifactsGetOutput,
  ExperimentalArtifactsUpdateInput,
  ExperimentalArtifactsUpdateOutput,
  ExperimentalArtifactsDeleteInput,
  ExperimentalArtifactsDeleteOutput,
  ExperimentalArtifactsViewInput,
  ExperimentalArtifactsViewOutput,
  ExperimentalJobListInput,
  ExperimentalJobListOutput,
  ExperimentalGraphFindInput,
  ExperimentalGraphFindOutput,
  ExperimentalGraphEntityInput,
  ExperimentalGraphEntityOutput,
  ExperimentalGraphNeighborsInput,
  ExperimentalGraphNeighborsOutput,
  ExperimentalGraphHistoryInput,
  ExperimentalGraphHistoryOutput,
  ExperimentalGraphChangesInput,
  ExperimentalGraphChangesOutput,
  ExperimentalGraphDiffInput,
  ExperimentalGraphDiffOutput,
  ExperimentalGraphSchemaOutput,
  ExperimentalGraphStatusOutput,
  ExperimentalGraphLensesOutput,
  ExperimentalGraphSliceInput,
  ExperimentalGraphSliceOutput,
  ExperimentalGraphIntelStatusOutput,
  ExperimentalGraphOverlayInput,
  ExperimentalGraphOverlayOutput,
  ExperimentalConnectorsStatusOutput,
  ExperimentalConnectorsCatalogOutput,
  ExperimentalConnectorsListConnectionsOutput,
  ExperimentalConnectorsCreateConnectionInput,
  ExperimentalConnectorsCreateConnectionOutput,
  ExperimentalConnectorsGetConnectionInput,
  ExperimentalConnectorsGetConnectionOutput,
  ExperimentalConnectorsUpdateConnectionInput,
  ExperimentalConnectorsUpdateConnectionOutput,
  ExperimentalConnectorsDeleteConnectionInput,
  ExperimentalConnectorsDeleteConnectionOutput,
  ExperimentalConnectorsTestConnectionInput,
  ExperimentalConnectorsTestConnectionOutput,
  ExperimentalConnectorsSyncConnectionInput,
  ExperimentalConnectorsSyncConnectionOutput,
  ExperimentalConnectorsPauseConnectionInput,
  ExperimentalConnectorsPauseConnectionOutput,
  ExperimentalConnectorsResumeConnectionInput,
  ExperimentalConnectorsResumeConnectionOutput,
  ExperimentalConnectorsReconnectConnectionInput,
  ExperimentalConnectorsReconnectConnectionOutput,
  ExperimentalConnectorsRotateCredentialInput,
  ExperimentalConnectorsRotateCredentialOutput,
  ExperimentalConnectorsListAuditInput,
  ExperimentalConnectorsListAuditOutput,
  ExperimentalConnectorsListAuthConfigsInput,
  ExperimentalConnectorsListAuthConfigsOutput,
  ExperimentalConnectorsCreateAuthConfigInput,
  ExperimentalConnectorsCreateAuthConfigOutput,
  ExperimentalConnectorsDeleteAuthConfigInput,
  ExperimentalConnectorsDeleteAuthConfigOutput,
  ExperimentalConnectorsAwsSetupInput,
  ExperimentalConnectorsAwsSetupOutput,
  ExperimentalConnectorsListGithubReposInput,
  ExperimentalConnectorsListGithubReposOutput,
  ExperimentalConnectorsListScopeOptionsInput,
  ExperimentalConnectorsListScopeOptionsOutput,
  ExperimentalConnectorsStartDeviceAuthorizationInput,
  ExperimentalConnectorsStartDeviceAuthorizationOutput,
  ExperimentalConnectorsGetDeviceAuthorizationInput,
  ExperimentalConnectorsGetDeviceAuthorizationOutput,
  ExperimentalConnectorsCancelDeviceAuthorizationInput,
  ExperimentalConnectorsCancelDeviceAuthorizationOutput,
  ExperimentalConnectorsGetScopeInput,
  ExperimentalConnectorsGetScopeOutput,
  ExperimentalConnectorsPutScopeInput,
  ExperimentalConnectorsPutScopeOutput,
  ExperimentalConnectorsUnlockVaultInput,
  ExperimentalConnectorsUnlockVaultOutput,
  ExperimentalConnectorsRotateMasterKeyOutput,
  ExperimentalConnectorsForgetAllOutput,
  ExperimentalOverviewCategoriesOutput,
  ExperimentalFindingsListInput,
  ExperimentalFindingsListOutput,
  ExperimentalFindingsGetInput,
  ExperimentalFindingsGetOutput,
  ExperimentalFindingsSetStatusInput,
  ExperimentalFindingsSetStatusOutput,
  ExperimentalScansEnqueueInput,
  ExperimentalScansEnqueueOutput,
  ExperimentalScansListInput,
  ExperimentalScansListOutput,
  ExperimentalScansScannersOutput,
  ExperimentalScansGetInput,
  ExperimentalScansGetOutput,
  ExperimentalScansCancelInput,
  ExperimentalScansCancelOutput,
  ExperimentalScansScheduleInput,
  ExperimentalScansScheduleOutput,
  ExperimentalSbomListOutput,
  ExperimentalSbomGetInput,
  ExperimentalSbomGetOutput,
  ExperimentalSbomExportInput,
  ExperimentalSbomExportOutput,
  ExperimentalCveLookupInput,
  ExperimentalCveLookupOutput,
  ExperimentalCveGraphInput,
  ExperimentalCveGraphOutput,
  ExperimentalCveStatusOutput,
  ExperimentalCveSetModeInput,
  ExperimentalCveSetModeOutput,
  ExperimentalCveGetInput,
  ExperimentalCveGetOutput,
  ExperimentalIdentityPathsInput,
  ExperimentalIdentityPathsOutput,
  ExperimentalBomSbomListOutput,
  ExperimentalBomSbomExportInput,
  ExperimentalBomSbomExportOutput,
  ExperimentalBomAiOutput,
  ExperimentalBomAiExportInput,
  ExperimentalBomAiExportOutput,
  ExperimentalBomCloudOutput,
  ExperimentalBomCloudExportInput,
  ExperimentalBomCloudExportOutput,
  ExperimentalAiEntitiesInput,
  ExperimentalAiEntitiesOutput,
  ExperimentalAiSummaryOutput,
  ExperimentalRuntimeStatusOutput,
  ExperimentalRuntimeEventsInput,
  ExperimentalRuntimeEventsOutput,
  ExperimentalRuntimeIngestInput,
  ExperimentalRuntimeIngestOutput,
  ExperimentalIssuesListInput,
  ExperimentalIssuesListOutput,
  ExperimentalIssuesGetInput,
  ExperimentalIssuesGetOutput,
  ExperimentalIssuesSetStatusInput,
  ExperimentalIssuesSetStatusOutput,
  ExperimentalRulesPacksOutput,
  ExperimentalRulesPackRulesInput,
  ExperimentalRulesPackRulesOutput,
  ExperimentalRulesOverrideInput,
  ExperimentalRulesOverrideOutput,
  ExperimentalRulesComplianceInput,
  ExperimentalRulesComplianceOutput,
  ExperimentalDataStoresInput,
  ExperimentalDataStoresOutput,
  ExperimentalDataStoreInput,
  ExperimentalDataStoreOutput,
  ShellListInput,
  ShellListOutput,
  ShellCreateInput,
  ShellCreateOutput,
  ShellGetInput,
  ShellGetOutput,
  ShellOutputInput,
  ShellOutputOutput,
  ShellRemoveInput,
  ShellRemoveOutput,
  ReferenceListInput,
  ReferenceListOutput,
  WorktreeListInput,
  WorktreeListOutput,
  WorktreeCreateInput,
  WorktreeCreateOutput,
  WorktreeRemoveInput,
  WorktreeRemoveOutput,
  WorktreeRefreshInput,
  WorktreeRefreshOutput,
  VcsInitInput,
  VcsInitOutput,
  VcsGetInput,
  VcsGetOutput,
  VcsBaseInput,
  VcsBaseOutput,
  VcsStatusInput,
  VcsStatusOutput,
  VcsBranchListInput,
  VcsBranchListOutput,
  VcsDiffInput,
  VcsDiffOutput,
  DebugHeapDumpInput,
  DebugHeapDumpOutput,
  DebugLocationListOutput,
  DebugLocationEvictInput,
  DebugLocationEvictOutput,
  ExperimentalMigrationV1StatusOutput,
  WebsearchProvidersInput,
  WebsearchProvidersOutput,
  WebsearchQueryInput,
  WebsearchQueryOutput,
  ExperimentalUsageLimitsInput,
  ExperimentalUsageLimitsOutput,
  ConfigGetInput,
  ConfigGetOutput,
  ConfigShellsOutput,
  ExperimentalConfigUpdateInput,
  ExperimentalConfigUpdateOutput,
} from "./types.js"
import { ClientError } from "./client-error.js"

export interface ClientOptions {
  readonly baseUrl: string
  readonly fetch?: typeof globalThis.fetch
  readonly headers?: RequestInit["headers"]
}

export interface RequestOptions {
  readonly signal?: AbortSignal
  readonly headers?: RequestInit["headers"]
  /** Reports every chunk a streaming response receives, including keepalive comments that yield no event. */
  readonly onActivity?: () => void
}

interface RequestDescriptor {
  readonly method: string
  readonly path: string
  readonly query?: Record<string, unknown>
  readonly headers?: Record<string, unknown>
  readonly body?: unknown
  readonly binaryBody?: true
  readonly successStatus: number
  readonly declaredStatuses: ReadonlyArray<number>
  readonly empty: boolean
  readonly binary?: true
}

const maxSseEventBytes = 16 * 1024 * 1024

export function make(options: ClientOptions) {
  const fetch = options.fetch ?? globalThis.fetch

  const prepare = (descriptor: RequestDescriptor, requestOptions?: RequestOptions) => {
    // A leading slash would replace any path prefix on baseUrl, so join relative to it.
    const baseUrl = new URL(options.baseUrl)
    if (!baseUrl.pathname.endsWith("/")) baseUrl.pathname += "/"
    const url = new URL(descriptor.path.slice(1), baseUrl)
    for (const [key, value] of Object.entries(descriptor.query ?? {})) appendQuery(url.searchParams, key, value)
    const headers = new Headers(options.headers)
    for (const [key, value] of Object.entries(descriptor.headers ?? {})) {
      if (value !== undefined && value !== null) headers.set(key, String(value))
    }
    for (const [key, value] of new Headers(requestOptions?.headers)) headers.set(key, value)
    if (descriptor.body !== undefined && !headers.has("content-type"))
      headers.set("content-type", descriptor.binaryBody ? "application/octet-stream" : "application/json")
    return {
      url,
      init: {
        method: descriptor.method,
        signal: requestOptions?.signal,
        headers,
        body:
          descriptor.body === undefined
            ? undefined
            : descriptor.binaryBody
              ? (descriptor.body as RequestInit["body"])
              : JSON.stringify(descriptor.body),
      } satisfies RequestInit,
    }
  }

  const execute = async (descriptor: RequestDescriptor, requestOptions?: RequestOptions) => {
    try {
      const prepared = prepare(descriptor, requestOptions)
      return await fetch(prepared.url, prepared.init)
    } catch (cause) {
      throw new ClientError("Transport", { cause })
    }
  }

  const responseError = async (response: Response, descriptor: RequestDescriptor): Promise<never> => {
    if (descriptor.declaredStatuses.includes(response.status))
      throw declared((await json(response)) as DeclaredErrorBody)
    try {
      await response.body?.cancel()
    } catch {}
    throw new ClientError("UnexpectedStatus", { cause: { status: response.status }, detail: String(response.status) })
  }

  const request = async <A>(descriptor: RequestDescriptor, requestOptions?: RequestOptions): Promise<A> => {
    const response = await execute(descriptor, requestOptions)
    if (response.status !== descriptor.successStatus) return responseError(response, descriptor)
    if (descriptor.binary) return new Uint8Array(await response.arrayBuffer()) as A
    if (descriptor.empty) {
      try {
        await response.body?.cancel()
      } catch {}
      return undefined as A
    }
    return (await json(response)) as A
  }

  const sse = <A>(descriptor: RequestDescriptor, requestOptions?: RequestOptions): AsyncIterable<A> => ({
    async *[Symbol.asyncIterator]() {
      const response = await execute(descriptor, requestOptions)
      if (response.status !== descriptor.successStatus) await responseError(response, descriptor)
      if (!isContentType(response, "text/event-stream")) {
        try {
          await response.body?.cancel()
        } catch {}
        throw new ClientError("UnsupportedContentType", { detail: response.headers.get("content-type") })
      }
      if (response.body === null) throw new ClientError("MalformedResponse")
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ""
      try {
        while (true) {
          let next
          try {
            next = await reader.read()
          } catch (cause) {
            throw new ClientError("Transport", { cause })
          }
          if (!next.done) requestOptions?.onActivity?.()
          buffer += decoder.decode(next.value, { stream: !next.done })
          if (buffer.length > maxSseEventBytes) throw new ClientError("SseEventTooLarge")
          const trailingCarriageReturn = !next.done && buffer.endsWith("\r")
          if (trailingCarriageReturn) buffer = buffer.slice(0, -1)
          buffer = buffer.replaceAll("\r\n", "\n").replaceAll("\r", "\n")
          if (trailingCarriageReturn) buffer += "\r"
          if (next.done && buffer !== "") buffer += "\n\n"
          let boundary = buffer.indexOf("\n\n")
          while (boundary >= 0) {
            const block = buffer.slice(0, boundary)
            buffer = buffer.slice(boundary + 2)
            const data = block
              .split("\n")
              .flatMap((line) => (line.startsWith("data:") ? [line.slice(5).trimStart()] : []))
              .join("\n")
            if (data !== "") {
              try {
                yield JSON.parse(data) as A
              } catch (cause) {
                throw new ClientError("MalformedResponse", { cause })
              }
            }
            boundary = buffer.indexOf("\n\n")
          }
          if (next.done) return
        }
      } finally {
        try {
          await reader.cancel()
        } catch {}
        reader.releaseLock()
      }
    },
  })

  const client = {
    server: {
      info: (requestOptions?: RequestOptions) =>
        request<ServerInfoOutput>(
          { method: "GET", path: `/api/info`, successStatus: 200, declaredStatuses: [400, 401], empty: false },
          requestOptions,
        ),
      pair: (requestOptions?: RequestOptions) =>
        request<ServerPairOutput>(
          { method: "POST", path: `/api/pair`, successStatus: 200, declaredStatuses: [400, 401], empty: false },
          requestOptions,
        ),
      connect: (input: ServerConnectInput, requestOptions?: RequestOptions) =>
        request<ServerConnectOutput>(
          {
            method: "GET",
            path: `/auth/connect/${encodeURIComponent(input.code)}`,
            successStatus: 200,
            declaredStatuses: [400, 401],
            empty: false,
          },
          requestOptions,
        ),
    },
    location: {
      get: (input?: LocationGetInput, requestOptions?: RequestOptions) =>
        request<LocationGetOutput>(
          {
            method: "GET",
            path: `/api/location`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      reload: (requestOptions?: RequestOptions) =>
        request<LocationReloadOutput>(
          {
            method: "POST",
            path: `/api/location/reload`,
            successStatus: 204,
            declaredStatuses: [400, 401, 503],
            empty: true,
          },
          requestOptions,
        ),
    },
    agent: {
      list: (input?: AgentListInput, requestOptions?: RequestOptions) =>
        request<AgentListOutput>(
          {
            method: "GET",
            path: `/api/agent`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      get: (input: AgentGetInput, requestOptions?: RequestOptions) =>
        request<AgentGetOutput>(
          {
            method: "GET",
            path: `/api/agent/${encodeURIComponent(input.agentID)}`,
            query: { location: input["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
    plugin: {
      list: (input?: PluginListInput, requestOptions?: RequestOptions) =>
        request<PluginListOutput>(
          {
            method: "GET",
            path: `/api/plugin`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      gui: (input: PluginGuiInput, requestOptions?: RequestOptions) =>
        request<PluginGuiOutput>(
          {
            method: "GET",
            path: `/api/plugin/gui`,
            query: { location: input["location"], id: input["id"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      check: (input?: PluginCheckInput, requestOptions?: RequestOptions) =>
        request<PluginCheckOutput>(
          {
            method: "POST",
            path: `/api/plugin/check`,
            query: { location: input?.["location"] },
            body: { target: input?.["target"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      update: (input: PluginUpdateInput, requestOptions?: RequestOptions) =>
        request<PluginUpdateOutput>(
          {
            method: "POST",
            path: `/api/plugin/update`,
            query: { location: input["location"] },
            body: { targets: input["targets"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404, 503],
            empty: true,
          },
          requestOptions,
        ),
    },
    session: {
      list: (input?: SessionListInput, requestOptions?: RequestOptions) =>
        request<SessionListOutput>(
          {
            method: "GET",
            path: `/api/session`,
            query: {
              limit: input?.["limit"],
              order: input?.["order"],
              search: input?.["search"],
              parentID: input?.["parentID"],
              archived: input?.["archived"],
              directory: input?.["directory"],
              project: input?.["project"],
              subpath: input?.["subpath"],
              cursor: input?.["cursor"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401],
            empty: false,
          },
          requestOptions,
        ),
      create: (input?: SessionCreateInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionCreateOutput }>(
          {
            method: "POST",
            path: `/api/session`,
            body: {
              id: input?.["id"],
              parentID: input?.["parentID"],
              title: input?.["title"],
              agent: input?.["agent"],
              model: input?.["model"],
              location: input?.["location"],
              metadata: input?.["metadata"],
              permissions: input?.["permissions"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      active: (requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionActiveOutput }>(
          {
            method: "GET",
            path: `/api/session/active`,
            successStatus: 200,
            declaredStatuses: [400, 401],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      get: (input: SessionGetInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionGetOutput }>(
          {
            method: "GET",
            path: `/api/session/${encodeURIComponent(input.sessionID)}`,
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      remove: (input: SessionRemoveInput, requestOptions?: RequestOptions) =>
        request<SessionRemoveOutput>(
          {
            method: "DELETE",
            path: `/api/session/${encodeURIComponent(input.sessionID)}`,
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      fork: (input: SessionForkInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionForkOutput }>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/fork`,
            body: { before: input["before"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      switchAgent: (input: SessionSwitchAgentInput, requestOptions?: RequestOptions) =>
        request<SessionSwitchAgentOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/agent`,
            body: { agent: input["agent"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      switchModel: (input: SessionSwitchModelInput, requestOptions?: RequestOptions) =>
        request<SessionSwitchModelOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/model`,
            body: { model: input["model"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      update: (input: SessionUpdateInput, requestOptions?: RequestOptions) =>
        request<SessionUpdateOutput>(
          {
            method: "PATCH",
            path: `/api/session/${encodeURIComponent(input.sessionID)}`,
            body: {
              title: input["title"],
              metadata: input["metadata"],
              permissions: input["permissions"],
              archived: input["archived"],
            },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      move: (input: SessionMoveInput, requestOptions?: RequestOptions) =>
        request<SessionMoveOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/move`,
            body: { directory: input["directory"], delivery: input["delivery"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      prompt: (input: SessionPromptInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionPromptOutput }>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/prompt`,
            body: {
              id: input["id"],
              text: input["text"],
              files: input["files"],
              agents: input["agents"],
              skills: input["skills"],
              metadata: input["metadata"],
              delivery: input["delivery"],
              resume: input["resume"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 409],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      command: (input: SessionCommandInput, requestOptions?: RequestOptions) =>
        request<SessionCommandOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/command`,
            body: {
              name: input["name"],
              text: input["text"],
              files: input["files"],
              agents: input["agents"],
              skills: input["skills"],
              delivery: input["delivery"],
            },
            successStatus: 204,
            declaredStatuses: [400, 401, 404, 500],
            empty: true,
          },
          requestOptions,
        ),
      synthetic: (input: SessionSyntheticInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionSyntheticOutput }>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/synthetic`,
            body: {
              id: input["id"],
              text: input["text"],
              description: input["description"],
              metadata: input["metadata"],
              delivery: input["delivery"],
              resume: input["resume"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 409],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      shell: (input: SessionShellInput, requestOptions?: RequestOptions) =>
        request<SessionShellOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/shell`,
            body: { id: input["id"], command: input["command"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      compact: (input: SessionCompactInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionCompactOutput }>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/compact`,
            body: { id: input["id"], delivery: input["delivery"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 409],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      revert: {
        stage: (input: SessionRevertStageInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: SessionRevertStageOutput }>(
            {
              method: "POST",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/revert/stage`,
              body: { messageID: input["messageID"], files: input["files"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        clear: (input: SessionRevertClearInput, requestOptions?: RequestOptions) =>
          request<SessionRevertClearOutput>(
            {
              method: "DELETE",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/revert`,
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: true,
            },
            requestOptions,
          ),
        commit: (input: SessionRevertCommitInput, requestOptions?: RequestOptions) =>
          request<SessionRevertCommitOutput>(
            {
              method: "POST",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/revert/commit`,
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 409],
              empty: true,
            },
            requestOptions,
          ),
      },
      context: (input: SessionContextInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionContextOutput }>(
          {
            method: "GET",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/context`,
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 500],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      diff: (input: SessionDiffInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionDiffOutput }>(
          {
            method: "GET",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/diff`,
            query: { from: input["from"], to: input["to"], context: input["context"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 500],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      inbox: {
        list: (input: SessionInboxListInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: SessionInboxListOutput }>(
            {
              method: "GET",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/inbox`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        cancel: (input: SessionInboxCancelInput, requestOptions?: RequestOptions) =>
          request<SessionInboxCancelOutput>(
            {
              method: "DELETE",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/inbox/${encodeURIComponent(input.inboxID)}`,
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        update: (input: SessionInboxUpdateInput, requestOptions?: RequestOptions) =>
          request<SessionInboxUpdateOutput>(
            {
              method: "PATCH",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/inbox/${encodeURIComponent(input.inboxID)}`,
              body: { delivery: input["delivery"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 409],
              empty: true,
            },
            requestOptions,
          ),
      },
      generate: (input: SessionGenerateInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: SessionGenerateOutput }>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/generate`,
            body: { prompt: input["prompt"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      interrupt: (input: SessionInterruptInput, requestOptions?: RequestOptions) =>
        request<SessionInterruptOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/interrupt`,
            query: { resume: input["resume"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      background: (input: SessionBackgroundInput, requestOptions?: RequestOptions) =>
        request<SessionBackgroundOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/background`,
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      message: {
        get: (input: SessionMessageGetInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: SessionMessageGetOutput }>(
            {
              method: "GET",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/message/${encodeURIComponent(input.messageID)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
      },
      form: {
        list: (input: SessionFormListInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: SessionFormListOutput }>(
            {
              method: "GET",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/form`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        create: (input: SessionFormCreateInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: SessionFormCreateOutput }>(
            {
              method: "POST",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/form`,
              body: { id: input["id"], title: input["title"], metadata: input["metadata"], fields: input["fields"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        get: (input: SessionFormGetInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: SessionFormGetOutput }>(
            {
              method: "GET",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/form/${encodeURIComponent(input.formID)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        reply: (input: SessionFormReplyInput, requestOptions?: RequestOptions) =>
          request<SessionFormReplyOutput>(
            {
              method: "POST",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/form/${encodeURIComponent(input.formID)}/reply`,
              body: { answer: input["answer"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 409],
              empty: true,
            },
            requestOptions,
          ),
        cancel: (input: SessionFormCancelInput, requestOptions?: RequestOptions) =>
          request<SessionFormCancelOutput>(
            {
              method: "DELETE",
              path: `/api/session/${encodeURIComponent(input.sessionID)}/form/${encodeURIComponent(input.formID)}`,
              query: { message: input["message"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 409],
              empty: true,
            },
            requestOptions,
          ),
      },
      environment: (input: SessionEnvironmentInput, requestOptions?: RequestOptions) =>
        request<SessionEnvironmentOutput>(
          {
            method: "PUT",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/environment`,
            body: { variables: input["variables"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      view: (input: SessionViewInput, requestOptions?: RequestOptions) =>
        request<SessionViewOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/view`,
            body: { idle: input["idle"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
    },
    experimental: {
      session: {
        stats: (input?: ExperimentalSessionStatsInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalSessionStatsOutput }>(
            {
              method: "GET",
              path: `/api/experimental/session/stats`,
              query: {
                from: input?.["from"],
                to: input?.["to"],
                project: input?.["project"],
                timezone: input?.["timezone"],
                tools: input?.["tools"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        import: (input: ExperimentalSessionImportInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalSessionImportOutput }>(
            {
              method: "POST",
              path: `/api/experimental/session/import`,
              body: { info: input["info"], messages: input["messages"], location: input["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        export: (input: ExperimentalSessionExportInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalSessionExportOutput }>(
            {
              method: "GET",
              path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/export`,
              query: { sanitize: input["sanitize"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        skill: (input: ExperimentalSessionSkillInput, requestOptions?: RequestOptions) =>
          request<ExperimentalSessionSkillOutput>(
            {
              method: "POST",
              path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/skill`,
              body: { id: input["id"], resume: input["resume"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        wait: (input: ExperimentalSessionWaitInput, requestOptions?: RequestOptions) =>
          request<ExperimentalSessionWaitOutput>(
            {
              method: "POST",
              path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/wait`,
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 503],
              empty: true,
            },
            requestOptions,
          ),
        instructions: {
          entry: {
            list: (input: ExperimentalSessionInstructionsEntryListInput, requestOptions?: RequestOptions) =>
              request<{ readonly data: ExperimentalSessionInstructionsEntryListOutput }>(
                {
                  method: "GET",
                  path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/instructions/entries`,
                  successStatus: 200,
                  declaredStatuses: [400, 401, 404],
                  empty: false,
                },
                requestOptions,
              ).then((value) => value.data),
            put: (input: ExperimentalSessionInstructionsEntryPutInput, requestOptions?: RequestOptions) =>
              request<ExperimentalSessionInstructionsEntryPutOutput>(
                {
                  method: "PUT",
                  path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/instructions/entries/${encodeURIComponent(input.key)}`,
                  body: { value: input["value"] },
                  successStatus: 204,
                  declaredStatuses: [400, 401, 404, 413],
                  empty: true,
                },
                requestOptions,
              ),
            remove: (input: ExperimentalSessionInstructionsEntryRemoveInput, requestOptions?: RequestOptions) =>
              request<ExperimentalSessionInstructionsEntryRemoveOutput>(
                {
                  method: "DELETE",
                  path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/instructions/entries/${encodeURIComponent(input.key)}`,
                  successStatus: 204,
                  declaredStatuses: [400, 401, 404],
                  empty: true,
                },
                requestOptions,
              ),
          },
        },
        log: (
          input: ExperimentalSessionLogInput,
          requestOptions?: RequestOptions,
        ): AsyncIterable<ExperimentalSessionLogOutput> =>
          sse<ExperimentalSessionLogOutput>(
            {
              method: "GET",
              path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/log`,
              query: { after: input["after"], follow: input["follow"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
      },
      generate: {
        text: (input: ExperimentalGenerateTextInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalGenerateTextOutput }>(
            {
              method: "POST",
              path: `/api/experimental/generate/text`,
              body: { prompt: input["prompt"], model: input["model"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 422, 502, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        image: (input: ExperimentalGenerateImageInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalGenerateImageOutput }>(
            {
              method: "POST",
              path: `/api/experimental/generate/image`,
              body: {
                model: input["model"],
                prompt: input["prompt"],
                images: input["images"],
                n: input["n"],
                aspect: input["aspect"],
                resolution: input["resolution"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 422, 502, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        decisions: (input: ExperimentalGenerateDecisionsInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalGenerateDecisionsOutput }>(
            {
              method: "POST",
              path: `/api/experimental/generate/decisions`,
              body: { model: input["model"], input: input["input"], questions: input["questions"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 422, 502, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
      },
      voice: {
        models: (requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalVoiceModelsOutput }>(
            {
              method: "GET",
              path: `/api/experimental/voice/models`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        session: (input: ExperimentalVoiceSessionInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalVoiceSessionOutput }>(
            {
              method: "POST",
              path: `/api/experimental/voice/session`,
              body: { model: input["model"], session: input["session"], transport: input["transport"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
      },
      integration: {
        wellknown: {
          add: (input: ExperimentalIntegrationWellknownAddInput, requestOptions?: RequestOptions) =>
            request<ExperimentalIntegrationWellknownAddOutput>(
              {
                method: "POST",
                path: `/api/experimental/integration/wellknown`,
                query: { location: input["location"] },
                body: { url: input["url"] },
                successStatus: 204,
                declaredStatuses: [400, 401, 404],
                empty: true,
              },
              requestOptions,
            ),
        },
      },
      mcp: {
        add: (input: ExperimentalMcpAddInput, requestOptions?: RequestOptions) =>
          request<ExperimentalMcpAddOutput>(
            {
              method: "PUT",
              path: `/api/experimental/mcp/${encodeURIComponent(input.server)}`,
              query: { location: input["location"] },
              body: { config: input["config"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        remove: (input: ExperimentalMcpRemoveInput, requestOptions?: RequestOptions) =>
          request<ExperimentalMcpRemoveOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/mcp/${encodeURIComponent(input.server)}`,
              query: { location: input["location"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        connect: (input: ExperimentalMcpConnectInput, requestOptions?: RequestOptions) =>
          request<ExperimentalMcpConnectOutput>(
            {
              method: "POST",
              path: `/api/experimental/mcp/${encodeURIComponent(input.server)}/connect`,
              query: { location: input["location"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        disconnect: (input: ExperimentalMcpDisconnectInput, requestOptions?: RequestOptions) =>
          request<ExperimentalMcpDisconnectOutput>(
            {
              method: "POST",
              path: `/api/experimental/mcp/${encodeURIComponent(input.server)}/disconnect`,
              query: { location: input["location"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        client: {
          token: (input: ExperimentalMcpClientTokenInput, requestOptions?: RequestOptions) =>
            request<ExperimentalMcpClientTokenOutput>(
              {
                method: "POST",
                path: `/api/experimental/client-mcp/token`,
                query: { location: input["location"], name: input["name"] },
                headers: { "x-bellucode-ticket": input["x-bellucode-ticket"] },
                successStatus: 200,
                declaredStatuses: [400, 401, 403, 404],
                empty: false,
              },
              requestOptions,
            ),
        },
      },
      file: {
        write: (input: ExperimentalFileWriteInput, requestOptions?: RequestOptions) =>
          request<ExperimentalFileWriteOutput>(
            {
              method: "POST",
              path: `/api/experimental/fs/write`,
              query: { location: input["location"], path: input["path"] },
              body: input["payload"],
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
              binaryBody: true,
            },
            requestOptions,
          ),
        watch: (input: ExperimentalFileWatchInput, requestOptions?: RequestOptions) =>
          request<ExperimentalFileWatchOutput>(
            {
              method: "POST",
              path: `/api/experimental/fs/watch`,
              query: { location: input["location"] },
              body: { path: input["path"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 503],
              empty: true,
            },
            requestOptions,
          ),
        unwatch: (input: ExperimentalFileUnwatchInput, requestOptions?: RequestOptions) =>
          request<ExperimentalFileUnwatchOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/fs/watch`,
              query: { location: input["location"] },
              body: { path: input["path"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
      },
      persistentPty: {
        read: (input: ExperimentalPersistentPtyReadInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalPersistentPtyReadOutput }>(
            {
              method: "GET",
              path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/terminal/read`,
              query: { lines: input["lines"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        list: (input: ExperimentalPersistentPtyListInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalPersistentPtyListOutput }>(
            {
              method: "GET",
              path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/terminal`,
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        create: (input: ExperimentalPersistentPtyCreateInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalPersistentPtyCreateOutput }>(
            {
              method: "POST",
              path: `/api/experimental/session/${encodeURIComponent(input.sessionID)}/terminal`,
              body: {
                command: input["command"],
                args: input["args"],
                cwd: input["cwd"],
                title: input["title"],
                env: input["env"],
                size: input["size"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        shutdown: (requestOptions?: RequestOptions) =>
          request<ExperimentalPersistentPtyShutdownOutput>(
            {
              method: "POST",
              path: `/api/experimental/persistent-pty/shutdown`,
              successStatus: 204,
              declaredStatuses: [400, 401, 503],
              empty: true,
            },
            requestOptions,
          ),
        handoff: (requestOptions?: RequestOptions) =>
          request<ExperimentalPersistentPtyHandoffOutput>(
            {
              method: "POST",
              path: `/api/experimental/persistent-pty/handoff`,
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        get: (input: ExperimentalPersistentPtyGetInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalPersistentPtyGetOutput }>(
            {
              method: "GET",
              path: `/api/experimental/persistent-pty/${encodeURIComponent(input.ptyID)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        update: (input: ExperimentalPersistentPtyUpdateInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalPersistentPtyUpdateOutput }>(
            {
              method: "PUT",
              path: `/api/experimental/persistent-pty/${encodeURIComponent(input.ptyID)}`,
              body: { attachmentID: input["attachmentID"], size: input["size"], title: input["title"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 501, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        snapshot: (input: ExperimentalPersistentPtySnapshotInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalPersistentPtySnapshotOutput }>(
            {
              method: "GET",
              path: `/api/experimental/persistent-pty/${encodeURIComponent(input.ptyID)}/snapshot`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        remove: (input: ExperimentalPersistentPtyRemoveInput, requestOptions?: RequestOptions) =>
          request<ExperimentalPersistentPtyRemoveOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/persistent-pty/${encodeURIComponent(input.ptyID)}`,
              successStatus: 204,
              declaredStatuses: [400, 401, 404, 503],
              empty: true,
            },
            requestOptions,
          ),
        connectToken: (input: ExperimentalPersistentPtyConnectTokenInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalPersistentPtyConnectTokenOutput }>(
            {
              method: "POST",
              path: `/api/experimental/persistent-pty/${encodeURIComponent(input.ptyID)}/connect-token`,
              headers: { "x-bellucode-ticket": input["x-bellucode-ticket"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
      },
      media: {
        get: (input: ExperimentalMediaGetInput, requestOptions?: RequestOptions) =>
          request<ExperimentalMediaGetOutput>(
            {
              method: "GET",
              path: `/api/experimental/media/${encodeURIComponent(input.hash)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
              binary: true,
            },
            requestOptions,
          ),
      },
      schedule: {
        create: (input: ExperimentalScheduleCreateInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalScheduleCreateOutput }>(
            {
              method: "POST",
              path: `/api/experimental/schedule`,
              body: {
                sessionID: input["sessionID"],
                name: input["name"],
                when: input["when"],
                if: input["if"],
                until: input["until"],
                ends: input["ends"],
                prompt: input["prompt"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        list: (input: ExperimentalScheduleListInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalScheduleListOutput }>(
            {
              method: "GET",
              path: `/api/experimental/schedule`,
              query: { sessionID: input["sessionID"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        get: (input: ExperimentalScheduleGetInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalScheduleGetOutput }>(
            {
              method: "GET",
              path: `/api/experimental/schedule/${encodeURIComponent(input.scheduleID)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        pause: (input: ExperimentalSchedulePauseInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalSchedulePauseOutput }>(
            {
              method: "POST",
              path: `/api/experimental/schedule/${encodeURIComponent(input.scheduleID)}/pause`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        resume: (input: ExperimentalScheduleResumeInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalScheduleResumeOutput }>(
            {
              method: "POST",
              path: `/api/experimental/schedule/${encodeURIComponent(input.scheduleID)}/resume`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        delete: (input: ExperimentalScheduleDeleteInput, requestOptions?: RequestOptions) =>
          request<ExperimentalScheduleDeleteOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/schedule/${encodeURIComponent(input.scheduleID)}`,
              successStatus: 204,
              declaredStatuses: [400, 401, 403, 404],
              empty: true,
            },
            requestOptions,
          ),
      },
      artifacts: {
        providers: (input?: ExperimentalArtifactsProvidersInput, requestOptions?: RequestOptions) =>
          request<ExperimentalArtifactsProvidersOutput>(
            {
              method: "GET",
              path: `/api/experimental/artifacts/providers`,
              query: { location: input?.["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: false,
            },
            requestOptions,
          ),
        list: (input?: ExperimentalArtifactsListInput, requestOptions?: RequestOptions) =>
          request<ExperimentalArtifactsListOutput>(
            {
              method: "GET",
              path: `/api/experimental/artifacts`,
              query: { location: input?.["location"], sessionID: input?.["sessionID"], provider: input?.["provider"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: false,
            },
            requestOptions,
          ),
        create: (input: ExperimentalArtifactsCreateInput, requestOptions?: RequestOptions) =>
          request<ExperimentalArtifactsCreateOutput>(
            {
              method: "POST",
              path: `/api/experimental/artifacts`,
              query: { location: input["location"] },
              body: {
                title: input["title"],
                files: input["files"],
                entry: input["entry"],
                provider: input["provider"],
                sessionID: input["sessionID"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: false,
            },
            requestOptions,
          ),
        get: (input: ExperimentalArtifactsGetInput, requestOptions?: RequestOptions) =>
          request<ExperimentalArtifactsGetOutput>(
            {
              method: "GET",
              path: `/api/experimental/artifacts/${encodeURIComponent(input.artifactID)}`,
              query: { location: input["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: false,
            },
            requestOptions,
          ),
        update: (input: ExperimentalArtifactsUpdateInput, requestOptions?: RequestOptions) =>
          request<ExperimentalArtifactsUpdateOutput>(
            {
              method: "PATCH",
              path: `/api/experimental/artifacts/${encodeURIComponent(input.artifactID)}`,
              query: { location: input["location"] },
              body: {
                title: input["title"],
                files: input["files"],
                entry: input["entry"],
                sessionID: input["sessionID"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: false,
            },
            requestOptions,
          ),
        delete: (input: ExperimentalArtifactsDeleteInput, requestOptions?: RequestOptions) =>
          request<ExperimentalArtifactsDeleteOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/artifacts/${encodeURIComponent(input.artifactID)}`,
              query: { location: input["location"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: true,
            },
            requestOptions,
          ),
        view: (input: ExperimentalArtifactsViewInput, requestOptions?: RequestOptions) =>
          request<ExperimentalArtifactsViewOutput>(
            {
              method: "GET",
              path: `/api/experimental/artifacts/${encodeURIComponent(input.artifactID)}/view/${encodePath(input.path)}`,
              query: { location: input["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 503],
              empty: false,
              binary: true,
            },
            requestOptions,
          ),
      },
      job: {
        list: (input?: ExperimentalJobListInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: ExperimentalJobListOutput }>(
            {
              method: "GET",
              path: `/api/experimental/job`,
              query: {
                sessionID: input?.["sessionID"],
                kind: input?.["kind"],
                status: input?.["status"],
                descendants: input?.["descendants"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
      },
      graph: {
        find: (input?: ExperimentalGraphFindInput, requestOptions?: RequestOptions) =>
          request<ExperimentalGraphFindOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/entities`,
              query: {
                type: input?.["type"],
                match: input?.["match"],
                as_of: input?.["as_of"],
                limit: input?.["limit"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        entity: (input: ExperimentalGraphEntityInput, requestOptions?: RequestOptions) =>
          request<ExperimentalGraphEntityOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/entities/${encodeURIComponent(input.id)}`,
              query: { as_of: input["as_of"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        neighbors: (input: ExperimentalGraphNeighborsInput, requestOptions?: RequestOptions) =>
          request<ExperimentalGraphNeighborsOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/entities/${encodeURIComponent(input.id)}/neighbors`,
              query: {
                direction: input["direction"],
                type: input["type"],
                as_of: input["as_of"],
                limit: input["limit"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        history: (input: ExperimentalGraphHistoryInput, requestOptions?: RequestOptions) =>
          request<ExperimentalGraphHistoryOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/entities/${encodeURIComponent(input.id)}/history`,
              query: { since: input["since"], until: input["until"], limit: input["limit"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        changes: (input?: ExperimentalGraphChangesInput, requestOptions?: RequestOptions) =>
          request<ExperimentalGraphChangesOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/changes`,
              query: {
                since: input?.["since"],
                until: input?.["until"],
                type: input?.["type"],
                limit: input?.["limit"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        diff: (input: ExperimentalGraphDiffInput, requestOptions?: RequestOptions) =>
          request<ExperimentalGraphDiffOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/diff`,
              query: { from: input["from"], to: input["to"], type: input["type"], limit: input["limit"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        schema: (requestOptions?: RequestOptions) =>
          request<ExperimentalGraphSchemaOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/schema`,
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        status: (requestOptions?: RequestOptions) =>
          request<ExperimentalGraphStatusOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/status`,
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        lenses: (requestOptions?: RequestOptions) =>
          request<ExperimentalGraphLensesOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/lenses`,
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        slice: (input: ExperimentalGraphSliceInput, requestOptions?: RequestOptions) =>
          request<ExperimentalGraphSliceOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/slice`,
              query: {
                lens: input["lens"],
                entity: input["entity"],
                target: input["target"],
                target_type: input["target_type"],
                collapse_rules: input["collapse_rules"],
                depth: input["depth"],
                limit: input["limit"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        intelStatus: (requestOptions?: RequestOptions) =>
          request<ExperimentalGraphIntelStatusOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/intel/status`,
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
        overlay: (
          input?: ExperimentalGraphOverlayInput,
          requestOptions?: RequestOptions,
        ): AsyncIterable<ExperimentalGraphOverlayOutput> =>
          sse<ExperimentalGraphOverlayOutput>(
            {
              method: "GET",
              path: `/api/experimental/graph/overlay`,
              query: { replay: input?.["replay"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 503],
              empty: false,
            },
            requestOptions,
          ),
      },
      connectors: {
        status: (requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsStatusOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/status`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        catalog: (requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsCatalogOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/catalog`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        listConnections: (requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsListConnectionsOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/connections`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        createConnection: (input: ExperimentalConnectorsCreateConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsCreateConnectionOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connections`,
              body: {
                alias: input["alias"],
                connectorId: input["connectorId"],
                authConfigId: input["authConfigId"],
                method: input["method"],
                params: input["params"],
                credential: input["credential"],
                intervalSec: input["intervalSec"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        getConnection: (input: ExperimentalConnectorsGetConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsGetConnectionOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        updateConnection: (input: ExperimentalConnectorsUpdateConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsUpdateConnectionOutput>(
            {
              method: "PATCH",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}`,
              body: {
                alias: input["alias"],
                intervalSec: input["intervalSec"],
                allowAgentLiveReads: input["allowAgentLiveReads"],
                selection: input["selection"],
                rotationIntervalDays: input["rotationIntervalDays"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        deleteConnection: (input: ExperimentalConnectorsDeleteConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsDeleteConnectionOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        testConnection: (input: ExperimentalConnectorsTestConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsTestConnectionOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/test`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        syncConnection: (input: ExperimentalConnectorsSyncConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsSyncConnectionOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/sync`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        pauseConnection: (input: ExperimentalConnectorsPauseConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsPauseConnectionOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/pause`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        resumeConnection: (input: ExperimentalConnectorsResumeConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsResumeConnectionOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/resume`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        reconnectConnection: (input: ExperimentalConnectorsReconnectConnectionInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsReconnectConnectionOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/reconnect`,
              body: { credential: input["credential"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        rotateCredential: (input: ExperimentalConnectorsRotateCredentialInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsRotateCredentialOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/rotate`,
              body: { credential: input["credential"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        listAudit: (input: ExperimentalConnectorsListAuditInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsListAuditOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/audit`,
              query: { cursor: input["cursor"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        listAuthConfigs: (input: ExperimentalConnectorsListAuthConfigsInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsListAuthConfigsOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/connectors/${encodeURIComponent(input.cid)}/auth-configs`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        createAuthConfig: (input: ExperimentalConnectorsCreateAuthConfigInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsCreateAuthConfigOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/connectors/${encodeURIComponent(input.cid)}/auth-configs`,
              body: {
                name: input["name"],
                method: input["method"],
                scopes: input["scopes"],
                settings: input["settings"],
                secrets: input["secrets"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        deleteAuthConfig: (input: ExperimentalConnectorsDeleteAuthConfigInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsDeleteAuthConfigOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/connectors/auth-configs/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        awsSetup: (input?: ExperimentalConnectorsAwsSetupInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsAwsSetupOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/aws/setup`,
              body: { alias: input?.["alias"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        listGithubRepos: (input: ExperimentalConnectorsListGithubReposInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsListGithubReposOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/github/repos`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        listScopeOptions: (input: ExperimentalConnectorsListScopeOptionsInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsListScopeOptionsOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/connections/${encodeURIComponent(input.id)}/scope-options`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        startDeviceAuthorization: (
          input: ExperimentalConnectorsStartDeviceAuthorizationInput,
          requestOptions?: RequestOptions,
        ) =>
          request<ExperimentalConnectorsStartDeviceAuthorizationOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/device-authorizations`,
              body: { connectorId: input["connectorId"], alias: input["alias"], reconnectId: input["reconnectId"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        getDeviceAuthorization: (
          input: ExperimentalConnectorsGetDeviceAuthorizationInput,
          requestOptions?: RequestOptions,
        ) =>
          request<ExperimentalConnectorsGetDeviceAuthorizationOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/device-authorizations/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        cancelDeviceAuthorization: (
          input: ExperimentalConnectorsCancelDeviceAuthorizationInput,
          requestOptions?: RequestOptions,
        ) =>
          request<ExperimentalConnectorsCancelDeviceAuthorizationOutput>(
            {
              method: "DELETE",
              path: `/api/experimental/connectors/device-authorizations/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        getScope: (input: ExperimentalConnectorsGetScopeInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsGetScopeOutput>(
            {
              method: "GET",
              path: `/api/experimental/connectors/scopes/${encodeURIComponent(input.principal)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        putScope: (input: ExperimentalConnectorsPutScopeInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsPutScopeOutput>(
            {
              method: "PUT",
              path: `/api/experimental/connectors/scopes/${encodeURIComponent(input.principal)}`,
              body: {
                connectors: input["connectors"],
                connections: input["connections"],
                operations: input["operations"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        unlockVault: (input: ExperimentalConnectorsUnlockVaultInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsUnlockVaultOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/vault/unlock`,
              body: { passphrase: input["passphrase"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        rotateMasterKey: (requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsRotateMasterKeyOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/vault/rotate`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
        forgetAll: (requestOptions?: RequestOptions) =>
          request<ExperimentalConnectorsForgetAllOutput>(
            {
              method: "POST",
              path: `/api/experimental/connectors/vault/forget`,
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404, 409, 413, 503],
              empty: false,
            },
            requestOptions,
          ),
      },
      overview: {
        categories: (requestOptions?: RequestOptions) =>
          request<ExperimentalOverviewCategoriesOutput>(
            {
              method: "GET",
              path: `/api/experimental/overview/categories`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500, 503],
              empty: false,
            },
            requestOptions,
          ),
      },
      findings: {
        list: (input?: ExperimentalFindingsListInput, requestOptions?: RequestOptions) =>
          request<ExperimentalFindingsListOutput>(
            {
              method: "GET",
              path: `/api/experimental/findings`,
              query: {
                category: input?.["category"],
                severity: input?.["severity"],
                status: input?.["status"],
                type: input?.["type"],
                asset: input?.["asset"],
                source: input?.["source"],
                from: input?.["from"],
                to: input?.["to"],
                sort: input?.["sort"],
                limit: input?.["limit"],
                cursor: input?.["cursor"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
        get: (input: ExperimentalFindingsGetInput, requestOptions?: RequestOptions) =>
          request<ExperimentalFindingsGetOutput>(
            {
              method: "GET",
              path: `/api/experimental/findings/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
        setStatus: (input: ExperimentalFindingsSetStatusInput, requestOptions?: RequestOptions) =>
          request<ExperimentalFindingsSetStatusOutput>(
            {
              method: "POST",
              path: `/api/experimental/findings/${encodeURIComponent(input.id)}/status`,
              body: { status: input["status"], reason: input["reason"], until: input["until"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
      },
      scans: {
        enqueue: (input: ExperimentalScansEnqueueInput, requestOptions?: RequestOptions) =>
          request<ExperimentalScansEnqueueOutput>(
            {
              method: "POST",
              path: `/api/experimental/scans`,
              body: { kind: input["kind"], targetType: input["targetType"], targetId: input["targetId"] },
              successStatus: 202,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
        list: (input?: ExperimentalScansListInput, requestOptions?: RequestOptions) =>
          request<ExperimentalScansListOutput>(
            {
              method: "GET",
              path: `/api/experimental/scans`,
              query: { status: input?.["status"], kind: input?.["kind"], limit: input?.["limit"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
        scanners: (requestOptions?: RequestOptions) =>
          request<ExperimentalScansScannersOutput>(
            {
              method: "GET",
              path: `/api/experimental/scans/scanners`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
        get: (input: ExperimentalScansGetInput, requestOptions?: RequestOptions) =>
          request<ExperimentalScansGetOutput>(
            {
              method: "GET",
              path: `/api/experimental/scans/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
        cancel: (input: ExperimentalScansCancelInput, requestOptions?: RequestOptions) =>
          request<ExperimentalScansCancelOutput>(
            {
              method: "POST",
              path: `/api/experimental/scans/${encodeURIComponent(input.id)}/cancel`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
        schedule: (input: ExperimentalScansScheduleInput, requestOptions?: RequestOptions) =>
          request<ExperimentalScansScheduleOutput>(
            {
              method: "PUT",
              path: `/api/experimental/scans/schedules/${encodeURIComponent(input.id)}`,
              body: {
                kind: input["kind"],
                targetType: input["targetType"],
                intervalSeconds: input["intervalSeconds"],
                enabled: input["enabled"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409, 500],
              empty: false,
            },
            requestOptions,
          ),
      },
      sbom: {
        list: (requestOptions?: RequestOptions) =>
          request<ExperimentalSbomListOutput>(
            {
              method: "GET",
              path: `/api/experimental/sbom`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        get: (input: ExperimentalSbomGetInput, requestOptions?: RequestOptions) =>
          request<ExperimentalSbomGetOutput>(
            {
              method: "GET",
              path: `/api/experimental/sbom/${encodeURIComponent(input.assetId)}`,
              query: { limit: input["limit"], cursor: input["cursor"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        export: (input: ExperimentalSbomExportInput, requestOptions?: RequestOptions) =>
          request<ExperimentalSbomExportOutput>(
            {
              method: "GET",
              path: `/api/experimental/sbom/${encodeURIComponent(input.assetId)}/export`,
              query: { format: input["format"], version: input["version"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
              binary: true,
            },
            requestOptions,
          ),
      },
      cve: {
        lookup: (input?: ExperimentalCveLookupInput, requestOptions?: RequestOptions) =>
          request<ExperimentalCveLookupOutput>(
            {
              method: "GET",
              path: `/api/experimental/cve/lookup`,
              query: {
                id: input?.["id"],
                purl: input?.["purl"],
                version: input?.["version"],
                cpe: input?.["cpe"],
                mode: input?.["mode"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        graph: (input?: ExperimentalCveGraphInput, requestOptions?: RequestOptions) =>
          request<ExperimentalCveGraphOutput>(
            {
              method: "GET",
              path: `/api/experimental/cve/graph`,
              query: {
                id: input?.["id"],
                relTypes: input?.["relTypes"],
                nodeTypes: input?.["nodeTypes"],
                depth: input?.["depth"],
                limit: input?.["limit"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        status: (requestOptions?: RequestOptions) =>
          request<ExperimentalCveStatusOutput>(
            {
              method: "GET",
              path: `/api/experimental/cve/status`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        setMode: (input: ExperimentalCveSetModeInput, requestOptions?: RequestOptions) =>
          request<ExperimentalCveSetModeOutput>(
            {
              method: "PUT",
              path: `/api/experimental/cve/mode`,
              body: { mode: input["mode"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        get: (input: ExperimentalCveGetInput, requestOptions?: RequestOptions) =>
          request<ExperimentalCveGetOutput>(
            {
              method: "GET",
              path: `/api/experimental/cve/${encodeURIComponent(input.id)}`,
              query: { mode: input["mode"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
      },
      identity: {
        paths: (input: ExperimentalIdentityPathsInput, requestOptions?: RequestOptions) =>
          request<ExperimentalIdentityPathsOutput>(
            {
              method: "GET",
              path: `/api/experimental/identity/paths`,
              query: { from: input["from"], to: input["to"], max_hops: input["max_hops"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 504],
              empty: false,
            },
            requestOptions,
          ),
      },
      bom: {
        sbomList: (requestOptions?: RequestOptions) =>
          request<ExperimentalBomSbomListOutput>(
            {
              method: "GET",
              path: `/api/experimental/bom/sbom`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        sbomExport: (input: ExperimentalBomSbomExportInput, requestOptions?: RequestOptions) =>
          request<ExperimentalBomSbomExportOutput>(
            {
              method: "GET",
              path: `/api/experimental/bom/sbom/${encodeURIComponent(input.assetId)}/export`,
              query: { format: input["format"], version: input["version"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
              binary: true,
            },
            requestOptions,
          ),
        ai: (requestOptions?: RequestOptions) =>
          request<ExperimentalBomAiOutput>(
            {
              method: "GET",
              path: `/api/experimental/bom/ai`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        aiExport: (input?: ExperimentalBomAiExportInput, requestOptions?: RequestOptions) =>
          request<ExperimentalBomAiExportOutput>(
            {
              method: "GET",
              path: `/api/experimental/bom/ai/export`,
              query: { format: input?.["format"], version: input?.["version"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
              binary: true,
            },
            requestOptions,
          ),
        cloud: (requestOptions?: RequestOptions) =>
          request<ExperimentalBomCloudOutput>(
            {
              method: "GET",
              path: `/api/experimental/bom/cloud`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        cloudExport: (input?: ExperimentalBomCloudExportInput, requestOptions?: RequestOptions) =>
          request<ExperimentalBomCloudExportOutput>(
            {
              method: "GET",
              path: `/api/experimental/bom/cloud/export`,
              query: { format: input?.["format"], version: input?.["version"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
              binary: true,
            },
            requestOptions,
          ),
      },
      ai: {
        entities: (input?: ExperimentalAiEntitiesInput, requestOptions?: RequestOptions) =>
          request<ExperimentalAiEntitiesOutput>(
            {
              method: "GET",
              path: `/api/experimental/ai/entities`,
              query: { kind: input?.["kind"], limit: input?.["limit"], cursor: input?.["cursor"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        summary: (requestOptions?: RequestOptions) =>
          request<ExperimentalAiSummaryOutput>(
            {
              method: "GET",
              path: `/api/experimental/ai/summary`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
      },
      runtime: {
        status: (requestOptions?: RequestOptions) =>
          request<ExperimentalRuntimeStatusOutput>(
            {
              method: "GET",
              path: `/api/experimental/runtime/status`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        events: (input?: ExperimentalRuntimeEventsInput, requestOptions?: RequestOptions) =>
          request<ExperimentalRuntimeEventsOutput>(
            {
              method: "GET",
              path: `/api/experimental/runtime/events`,
              query: { type: input?.["type"], limit: input?.["limit"], cursor: input?.["cursor"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        ingest: (input: ExperimentalRuntimeIngestInput, requestOptions?: RequestOptions) =>
          request<ExperimentalRuntimeIngestOutput>(
            {
              method: "POST",
              path: `/api/experimental/runtime/ingest`,
              body: {
                ts: input["ts"],
                type: input["type"],
                node: input["node"],
                namespace: input["namespace"],
                pod: input["pod"],
                container_id: input["container_id"],
                process_path: input["process_path"],
                args: input["args"],
                user: input["user"],
                unavailable: input["unavailable"],
              },
              successStatus: 204,
              declaredStatuses: [400, 401, 403, 404, 500],
              empty: true,
            },
            requestOptions,
          ),
      },
      issues: {
        list: (input?: ExperimentalIssuesListInput, requestOptions?: RequestOptions) =>
          request<ExperimentalIssuesListOutput>(
            {
              method: "GET",
              path: `/api/experimental/issues`,
              query: {
                category: input?.["category"],
                severity: input?.["severity"],
                status: input?.["status"],
                asset: input?.["asset"],
                sort: input?.["sort"],
                limit: input?.["limit"],
                cursor: input?.["cursor"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        get: (input: ExperimentalIssuesGetInput, requestOptions?: RequestOptions) =>
          request<ExperimentalIssuesGetOutput>(
            {
              method: "GET",
              path: `/api/experimental/issues/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        setStatus: (input: ExperimentalIssuesSetStatusInput, requestOptions?: RequestOptions) =>
          request<ExperimentalIssuesSetStatusOutput>(
            {
              method: "POST",
              path: `/api/experimental/issues/${encodeURIComponent(input.id)}/status`,
              body: { status: input["status"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
      },
      rules: {
        packs: (requestOptions?: RequestOptions) =>
          request<ExperimentalRulesPacksOutput>(
            {
              method: "GET",
              path: `/api/experimental/rules/packs`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        packRules: (input: ExperimentalRulesPackRulesInput, requestOptions?: RequestOptions) =>
          request<ExperimentalRulesPackRulesOutput>(
            {
              method: "GET",
              path: `/api/experimental/rules/packs/${encodeURIComponent(input.id)}/rules`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        override: (input: ExperimentalRulesOverrideInput, requestOptions?: RequestOptions) =>
          request<ExperimentalRulesOverrideOutput>(
            {
              method: "PUT",
              path: `/api/experimental/rules/overrides`,
              body: {
                packId: input["packId"],
                ruleId: input["ruleId"],
                enabled: input["enabled"],
                severity: input["severity"],
              },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        compliance: (input?: ExperimentalRulesComplianceInput, requestOptions?: RequestOptions) =>
          request<ExperimentalRulesComplianceOutput>(
            {
              method: "GET",
              path: `/api/experimental/rules/compliance`,
              query: { benchmark: input?.["benchmark"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
      },
      data: {
        stores: (input?: ExperimentalDataStoresInput, requestOptions?: RequestOptions) =>
          request<ExperimentalDataStoresOutput>(
            {
              method: "GET",
              path: `/api/experimental/data/stores`,
              query: { limit: input?.["limit"], cursor: input?.["cursor"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
        store: (input: ExperimentalDataStoreInput, requestOptions?: RequestOptions) =>
          request<ExperimentalDataStoreOutput>(
            {
              method: "GET",
              path: `/api/experimental/data/stores/${encodeURIComponent(input.id)}`,
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 500],
              empty: false,
            },
            requestOptions,
          ),
      },
      migration: {
        v1: {
          status: (requestOptions?: RequestOptions) =>
            request<ExperimentalMigrationV1StatusOutput>(
              {
                method: "GET",
                path: `/api/experimental/migration/v1`,
                successStatus: 200,
                declaredStatuses: [400, 401],
                empty: false,
              },
              requestOptions,
            ),
        },
      },
      usage: {
        limits: (input?: ExperimentalUsageLimitsInput, requestOptions?: RequestOptions) =>
          request<ExperimentalUsageLimitsOutput>(
            {
              method: "GET",
              path: `/api/experimental/usage/limits`,
              query: { location: input?.["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 503],
              empty: false,
            },
            requestOptions,
          ),
      },
      config: {
        update: (input: ExperimentalConfigUpdateInput, requestOptions?: RequestOptions) =>
          request<ExperimentalConfigUpdateOutput>(
            {
              method: "PATCH",
              path: `/api/experimental/config`,
              body: { shell: input["shell"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
      },
    },
    message: {
      list: (input: MessageListInput, requestOptions?: RequestOptions) =>
        request<MessageListOutput>(
          {
            method: "GET",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/message`,
            query: { limit: input["limit"], order: input["order"], cursor: input["cursor"], type: input["type"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 500],
            empty: false,
          },
          requestOptions,
        ),
    },
    model: {
      list: (input?: ModelListInput, requestOptions?: RequestOptions) =>
        request<ModelListOutput>(
          {
            method: "GET",
            path: `/api/model`,
            query: { location: input?.["location"], types: input?.["types"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
      default: (input?: ModelDefaultInput, requestOptions?: RequestOptions) =>
        request<ModelDefaultOutput>(
          {
            method: "GET",
            path: `/api/model/default`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
    },
    provider: {
      list: (input?: ProviderListInput, requestOptions?: RequestOptions) =>
        request<ProviderListOutput>(
          {
            method: "GET",
            path: `/api/provider`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
      get: (input: ProviderGetInput, requestOptions?: RequestOptions) =>
        request<ProviderGetOutput>(
          {
            method: "GET",
            path: `/api/provider/${encodeURIComponent(input.providerID)}`,
            query: { location: input["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
    },
    integration: {
      list: (input?: IntegrationListInput, requestOptions?: RequestOptions) =>
        request<IntegrationListOutput>(
          {
            method: "GET",
            path: `/api/integration`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      get: (input: IntegrationGetInput, requestOptions?: RequestOptions) =>
        request<IntegrationGetOutput>(
          {
            method: "GET",
            path: `/api/integration/${encodeURIComponent(input.integrationID)}`,
            query: { location: input["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      connect: {
        key: (input: IntegrationConnectKeyInput, requestOptions?: RequestOptions) =>
          request<IntegrationConnectKeyOutput>(
            {
              method: "POST",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/key`,
              query: { location: input["location"] },
              body: { key: input["key"], answer: input["answer"], label: input["label"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        external: (input: IntegrationConnectExternalInput, requestOptions?: RequestOptions) =>
          request<IntegrationConnectExternalOutput>(
            {
              method: "POST",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/external`,
              query: { location: input["location"] },
              body: { methodID: input["methodID"], answer: input["answer"], label: input["label"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
      },
      oauth: {
        connect: (input: IntegrationOauthConnectInput, requestOptions?: RequestOptions) =>
          request<IntegrationOauthConnectOutput>(
            {
              method: "POST",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/oauth`,
              query: { location: input["location"] },
              body: { methodID: input["methodID"], answer: input["answer"], label: input["label"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
        status: (input: IntegrationOauthStatusInput, requestOptions?: RequestOptions) =>
          request<IntegrationOauthStatusOutput>(
            {
              method: "GET",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/oauth/${encodeURIComponent(input.attemptID)}`,
              query: { location: input["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
        complete: (input: IntegrationOauthCompleteInput, requestOptions?: RequestOptions) =>
          request<IntegrationOauthCompleteOutput>(
            {
              method: "POST",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/oauth/${encodeURIComponent(input.attemptID)}/complete`,
              query: { location: input["location"] },
              body: { code: input["code"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
        cancel: (input: IntegrationOauthCancelInput, requestOptions?: RequestOptions) =>
          request<IntegrationOauthCancelOutput>(
            {
              method: "DELETE",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/oauth/${encodeURIComponent(input.attemptID)}`,
              query: { location: input["location"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
      },
      command: {
        connect: (input: IntegrationCommandConnectInput, requestOptions?: RequestOptions) =>
          request<IntegrationCommandConnectOutput>(
            {
              method: "POST",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/command`,
              query: { location: input["location"] },
              body: { methodID: input["methodID"], label: input["label"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
        status: (input: IntegrationCommandStatusInput, requestOptions?: RequestOptions) =>
          request<IntegrationCommandStatusOutput>(
            {
              method: "GET",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/command/${encodeURIComponent(input.attemptID)}`,
              query: { location: input["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
        cancel: (input: IntegrationCommandCancelInput, requestOptions?: RequestOptions) =>
          request<IntegrationCommandCancelOutput>(
            {
              method: "DELETE",
              path: `/api/integration/${encodeURIComponent(input.integrationID)}/connect/command/${encodeURIComponent(input.attemptID)}`,
              query: { location: input["location"] },
              successStatus: 204,
              declaredStatuses: [400, 401, 404],
              empty: true,
            },
            requestOptions,
          ),
      },
    },
    mcp: {
      list: (input?: McpListInput, requestOptions?: RequestOptions) =>
        request<McpListOutput>(
          {
            method: "GET",
            path: `/api/mcp`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      resource: {
        catalog: (input?: McpResourceCatalogInput, requestOptions?: RequestOptions) =>
          request<McpResourceCatalogOutput>(
            {
              method: "GET",
              path: `/api/mcp/resource`,
              query: { location: input?.["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
      },
    },
    credential: {
      list: (requestOptions?: RequestOptions) =>
        request<{ readonly data: CredentialListOutput }>(
          { method: "GET", path: `/api/credential`, successStatus: 200, declaredStatuses: [400, 401], empty: false },
          requestOptions,
        ).then((value) => value.data),
      create: (input: CredentialCreateInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: CredentialCreateOutput }>(
          {
            method: "POST",
            path: `/api/credential`,
            body: {
              id: input["id"],
              integrationID: input["integrationID"],
              label: input["label"],
              value: input["value"],
              activate: input["activate"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 409],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      update: (input: CredentialUpdateInput, requestOptions?: RequestOptions) =>
        request<CredentialUpdateOutput>(
          {
            method: "PATCH",
            path: `/api/credential/${encodeURIComponent(input.credentialID)}`,
            body: { label: input["label"] },
            successStatus: 204,
            declaredStatuses: [400, 401],
            empty: true,
          },
          requestOptions,
        ),
      activate: (input: CredentialActivateInput, requestOptions?: RequestOptions) =>
        request<CredentialActivateOutput>(
          {
            method: "POST",
            path: `/api/credential/${encodeURIComponent(input.credentialID)}/activate`,
            successStatus: 204,
            declaredStatuses: [400, 401],
            empty: true,
          },
          requestOptions,
        ),
      remove: (input: CredentialRemoveInput, requestOptions?: RequestOptions) =>
        request<CredentialRemoveOutput>(
          {
            method: "DELETE",
            path: `/api/credential/${encodeURIComponent(input.credentialID)}`,
            successStatus: 204,
            declaredStatuses: [400, 401],
            empty: true,
          },
          requestOptions,
        ),
    },
    project: {
      list: (input?: ProjectListInput, requestOptions?: RequestOptions) =>
        request<ProjectListOutput>(
          {
            method: "GET",
            path: `/api/project`,
            query: { archived: input?.["archived"] },
            successStatus: 200,
            declaredStatuses: [400, 401],
            empty: false,
          },
          requestOptions,
        ),
      update: (input: ProjectUpdateInput, requestOptions?: RequestOptions) =>
        request<ProjectUpdateOutput>(
          {
            method: "PATCH",
            path: `/api/project/${encodeURIComponent(input.projectID)}`,
            body: {
              canonical: input["canonical"],
              name: input["name"],
              icon: input["icon"],
              commands: input["commands"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
    form: {
      list: (input?: FormListInput, requestOptions?: RequestOptions) =>
        request<FormListOutput>(
          {
            method: "GET",
            path: `/api/form`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
    permission: {
      request: {
        list: (input?: PermissionRequestListInput, requestOptions?: RequestOptions) =>
          request<PermissionRequestListOutput>(
            {
              method: "GET",
              path: `/api/permission/request`,
              query: { location: input?.["location"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
      },
      saved: {
        list: (input?: PermissionSavedListInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: PermissionSavedListOutput }>(
            {
              method: "GET",
              path: `/api/permission/saved`,
              query: { projectID: input?.["projectID"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        update: (input: PermissionSavedUpdateInput, requestOptions?: RequestOptions) =>
          request<{ readonly data: PermissionSavedUpdateOutput }>(
            {
              method: "PATCH",
              path: `/api/permission/saved/${encodeURIComponent(input.id)}`,
              body: { action: input["action"], resource: input["resource"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404, 409],
              empty: false,
            },
            requestOptions,
          ).then((value) => value.data),
        remove: (input: PermissionSavedRemoveInput, requestOptions?: RequestOptions) =>
          request<PermissionSavedRemoveOutput>(
            {
              method: "DELETE",
              path: `/api/permission/saved/${encodeURIComponent(input.id)}`,
              successStatus: 204,
              declaredStatuses: [400, 401],
              empty: true,
            },
            requestOptions,
          ),
      },
      create: (input: PermissionCreateInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: PermissionCreateOutput }>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/permission`,
            body: {
              id: input["id"],
              action: input["action"],
              resources: input["resources"],
              save: input["save"],
              metadata: input["metadata"],
              source: input["source"],
              agent: input["agent"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      list: (input: PermissionListInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: PermissionListOutput }>(
          {
            method: "GET",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/permission`,
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      get: (input: PermissionGetInput, requestOptions?: RequestOptions) =>
        request<{ readonly data: PermissionGetOutput }>(
          {
            method: "GET",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/permission/${encodeURIComponent(input.requestID)}`,
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ).then((value) => value.data),
      reply: (input: PermissionReplyInput, requestOptions?: RequestOptions) =>
        request<PermissionReplyOutput>(
          {
            method: "POST",
            path: `/api/session/${encodeURIComponent(input.sessionID)}/permission/${encodeURIComponent(input.requestID)}/reply`,
            body: { decision: input["decision"], message: input["message"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
    },
    file: {
      read: (input: FileReadInput, requestOptions?: RequestOptions) =>
        request<FileReadOutput>(
          {
            method: "GET",
            path: `/api/fs/read/${encodePath(input.path)}`,
            query: { location: input["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
            binary: true,
          },
          requestOptions,
        ),
      list: (input?: FileListInput, requestOptions?: RequestOptions) =>
        request<FileListOutput>(
          {
            method: "GET",
            path: `/api/fs/list`,
            query: { location: input?.["location"], path: input?.["path"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      find: (input: FileFindInput, requestOptions?: RequestOptions) =>
        request<FileFindOutput>(
          {
            method: "GET",
            path: `/api/fs/find`,
            query: { location: input["location"], query: input["query"], type: input["type"], limit: input["limit"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
    command: {
      list: (input?: CommandListInput, requestOptions?: RequestOptions) =>
        request<CommandListOutput>(
          {
            method: "GET",
            path: `/api/command`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
    skill: {
      list: (input?: SkillListInput, requestOptions?: RequestOptions) =>
        request<SkillListOutput>(
          {
            method: "GET",
            path: `/api/skill`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
    rpc: {
      call: (input: RpcCallInput, requestOptions?: RequestOptions) =>
        request<RpcCallOutput>(
          {
            method: "POST",
            path: `/api/rpc/${encodeURIComponent(input.rpcID)}/${encodeURIComponent(input.method)}`,
            query: { location: input["location"] },
            body: { input: input["input"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 500],
            empty: false,
          },
          requestOptions,
        ),
    },
    event: {
      subscribe: (input?: EventSubscribeInput, requestOptions?: RequestOptions): AsyncIterable<EventSubscribeOutput> =>
        sse<EventSubscribeOutput>(
          {
            method: "GET",
            path: `/api/event`,
            query: { types: input?.["types"] },
            successStatus: 200,
            declaredStatuses: [400, 401],
            empty: false,
          },
          requestOptions,
        ),
    },
    pty: {
      list: (input?: PtyListInput, requestOptions?: RequestOptions) =>
        request<PtyListOutput>(
          {
            method: "GET",
            path: `/api/pty`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      create: (input?: PtyCreateInput, requestOptions?: RequestOptions) =>
        request<PtyCreateOutput>(
          {
            method: "POST",
            path: `/api/pty`,
            query: { location: input?.["location"] },
            body: {
              command: input?.["command"],
              args: input?.["args"],
              cwd: input?.["cwd"],
              title: input?.["title"],
              env: input?.["env"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      get: (input: PtyGetInput, requestOptions?: RequestOptions) =>
        request<PtyGetOutput>(
          {
            method: "GET",
            path: `/api/pty/${encodeURIComponent(input.ptyID)}`,
            query: { location: input["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      update: (input: PtyUpdateInput, requestOptions?: RequestOptions) =>
        request<PtyUpdateOutput>(
          {
            method: "PUT",
            path: `/api/pty/${encodeURIComponent(input.ptyID)}`,
            query: { location: input["location"] },
            body: { title: input["title"], size: input["size"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      remove: (input: PtyRemoveInput, requestOptions?: RequestOptions) =>
        request<PtyRemoveOutput>(
          {
            method: "DELETE",
            path: `/api/pty/${encodeURIComponent(input.ptyID)}`,
            query: { location: input["location"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      connect: {
        token: (input: PtyConnectTokenInput, requestOptions?: RequestOptions) =>
          request<PtyConnectTokenOutput>(
            {
              method: "POST",
              path: `/api/pty/${encodeURIComponent(input.ptyID)}/connect-token`,
              query: { location: input["location"] },
              headers: { "x-bellucode-ticket": input["x-bellucode-ticket"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 403, 404],
              empty: false,
            },
            requestOptions,
          ),
      },
    },
    shell: {
      list: (input?: ShellListInput, requestOptions?: RequestOptions) =>
        request<ShellListOutput>(
          {
            method: "GET",
            path: `/api/shell`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      create: (input: ShellCreateInput, requestOptions?: RequestOptions) =>
        request<ShellCreateOutput>(
          {
            method: "POST",
            path: `/api/shell`,
            query: { location: input["location"] },
            body: {
              command: input["command"],
              cwd: input["cwd"],
              timeout: input["timeout"],
              metadata: input["metadata"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      get: (input: ShellGetInput, requestOptions?: RequestOptions) =>
        request<ShellGetOutput>(
          {
            method: "GET",
            path: `/api/shell/${encodeURIComponent(input.id)}`,
            query: { location: input["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      output: (input: ShellOutputInput, requestOptions?: RequestOptions) =>
        request<ShellOutputOutput>(
          {
            method: "GET",
            path: `/api/shell/${encodeURIComponent(input.id)}/output`,
            query: { location: input["location"], cursor: input["cursor"], limit: input["limit"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      remove: (input: ShellRemoveInput, requestOptions?: RequestOptions) =>
        request<ShellRemoveOutput>(
          {
            method: "DELETE",
            path: `/api/shell/${encodeURIComponent(input.id)}`,
            query: { location: input["location"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
    },
    reference: {
      list: (input?: ReferenceListInput, requestOptions?: RequestOptions) =>
        request<ReferenceListOutput>(
          {
            method: "GET",
            path: `/api/reference`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
    worktree: {
      list: (input: WorktreeListInput, requestOptions?: RequestOptions) =>
        request<WorktreeListOutput>(
          {
            method: "GET",
            path: `/api/worktree`,
            query: { projectID: input["projectID"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      create: (input: WorktreeCreateInput, requestOptions?: RequestOptions) =>
        request<WorktreeCreateOutput>(
          {
            method: "POST",
            path: `/api/worktree`,
            body: {
              projectID: input["projectID"],
              from: input["from"],
              branch: input["branch"],
              directory: input["directory"],
              name: input["name"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      remove: (input: WorktreeRemoveInput, requestOptions?: RequestOptions) =>
        request<WorktreeRemoveOutput>(
          {
            method: "DELETE",
            path: `/api/worktree`,
            body: { projectID: input["projectID"], directory: input["directory"], force: input["force"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
      refresh: (input: WorktreeRefreshInput, requestOptions?: RequestOptions) =>
        request<WorktreeRefreshOutput>(
          {
            method: "POST",
            path: `/api/worktree/refresh`,
            body: { projectID: input["projectID"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404],
            empty: true,
          },
          requestOptions,
        ),
    },
    vcs: {
      init: (input?: VcsInitInput, requestOptions?: RequestOptions) =>
        request<VcsInitOutput>(
          {
            method: "POST",
            path: `/api/vcs/init`,
            query: { location: input?.["location"], provider: input?.["provider"] },
            successStatus: 204,
            declaredStatuses: [400, 401, 404, 409, 501, 503],
            empty: true,
          },
          requestOptions,
        ),
      get: (input?: VcsGetInput, requestOptions?: RequestOptions) =>
        request<VcsGetOutput>(
          {
            method: "GET",
            path: `/api/vcs`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      base: (input?: VcsBaseInput, requestOptions?: RequestOptions) =>
        request<VcsBaseOutput>(
          {
            method: "GET",
            path: `/api/vcs/base`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
      status: (input?: VcsStatusInput, requestOptions?: RequestOptions) =>
        request<VcsStatusOutput>(
          {
            method: "GET",
            path: `/api/vcs/status`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      branch: {
        list: (input?: VcsBranchListInput, requestOptions?: RequestOptions) =>
          request<VcsBranchListOutput>(
            {
              method: "GET",
              path: `/api/vcs/branch`,
              query: { location: input?.["location"], search: input?.["search"], limit: input?.["limit"] },
              successStatus: 200,
              declaredStatuses: [400, 401, 404],
              empty: false,
            },
            requestOptions,
          ),
      },
      diff: (input: VcsDiffInput, requestOptions?: RequestOptions) =>
        request<VcsDiffOutput>(
          {
            method: "GET",
            path: `/api/vcs/diff`,
            query: {
              location: input["location"],
              mode: input["mode"],
              base: input["base"],
              context: input["context"],
              untracked: input["untracked"],
            },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
    },
    debug: {
      heapDump: (input?: DebugHeapDumpInput, requestOptions?: RequestOptions) =>
        request<DebugHeapDumpOutput>(
          {
            method: "POST",
            path: `/api/debug/heap-dump`,
            query: { directory: input?.["directory"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 500],
            empty: false,
          },
          requestOptions,
        ),
      location: {
        list: (requestOptions?: RequestOptions) =>
          request<DebugLocationListOutput>(
            {
              method: "GET",
              path: `/api/debug/location`,
              successStatus: 200,
              declaredStatuses: [400, 401],
              empty: false,
            },
            requestOptions,
          ),
        evict: (input?: DebugLocationEvictInput, requestOptions?: RequestOptions) =>
          request<DebugLocationEvictOutput>(
            {
              method: "DELETE",
              path: `/api/debug/location`,
              query: { location: input?.["location"] },
              successStatus: 204,
              declaredStatuses: [400, 401],
              empty: true,
            },
            requestOptions,
          ),
      },
    },
    websearch: {
      providers: (input?: WebsearchProvidersInput, requestOptions?: RequestOptions) =>
        request<WebsearchProvidersOutput>(
          {
            method: "GET",
            path: `/api/websearch/provider`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
      query: (input: WebsearchQueryInput, requestOptions?: RequestOptions) =>
        request<WebsearchQueryOutput>(
          {
            method: "POST",
            path: `/api/websearch`,
            query: { location: input["location"] },
            body: { query: input["query"], providerID: input["providerID"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404, 503],
            empty: false,
          },
          requestOptions,
        ),
    },
    config: {
      get: (input?: ConfigGetInput, requestOptions?: RequestOptions) =>
        request<ConfigGetOutput>(
          {
            method: "GET",
            path: `/api/config`,
            query: { location: input?.["location"] },
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
      shells: (requestOptions?: RequestOptions) =>
        request<ConfigShellsOutput>(
          {
            method: "GET",
            path: `/api/config/shell`,
            successStatus: 200,
            declaredStatuses: [400, 401, 404],
            empty: false,
          },
          requestOptions,
        ),
    },
  }
  return {
    ...client,
    session: {
      ...client.session,
      /** @deprecated Use `client.experimental.session.stats`. Removed in the next minor. */
      stats: client.experimental.session.stats,
      /** @deprecated Use `client.experimental.session.import`. Removed in the next minor. */
      import: client.experimental.session.import,
      /** @deprecated Use `client.experimental.session.export`. Removed in the next minor. */
      export: client.experimental.session.export,
      /** @deprecated Use `client.experimental.session.skill`. Removed in the next minor. */
      skill: client.experimental.session.skill,
      /** @deprecated Use `client.experimental.session.wait`. Removed in the next minor. */
      wait: client.experimental.session.wait,
      /** @deprecated Use `client.experimental.session.instructions`. Removed in the next minor. */
      instructions: {
        /** @deprecated Use `client.experimental.session.instructions.entry`. Removed in the next minor. */
        entry: {
          /** @deprecated Use `client.experimental.session.instructions.entry.list`. Removed in the next minor. */
          list: client.experimental.session.instructions.entry.list,
          /** @deprecated Use `client.experimental.session.instructions.entry.put`. Removed in the next minor. */
          put: client.experimental.session.instructions.entry.put,
          /** @deprecated Use `client.experimental.session.instructions.entry.remove`. Removed in the next minor. */
          remove: client.experimental.session.instructions.entry.remove,
        },
      },
      /** @deprecated Use `client.experimental.session.log`. Removed in the next minor. */
      log: client.experimental.session.log,
    },
    /** @deprecated Use `client.experimental.generate`. Removed in the next minor. */
    generate: {
      /** @deprecated Use `client.experimental.generate.text`. Removed in the next minor. */
      text: client.experimental.generate.text,
      /** @deprecated Use `client.experimental.generate.image`. Removed in the next minor. */
      image: client.experimental.generate.image,
      /** @deprecated Use `client.experimental.generate.decisions`. Removed in the next minor. */
      decisions: client.experimental.generate.decisions,
    },
    /** @deprecated Use `client.experimental.voice`. Removed in the next minor. */
    voice: {
      /** @deprecated Use `client.experimental.voice.models`. Removed in the next minor. */
      models: client.experimental.voice.models,
      /** @deprecated Use `client.experimental.voice.session`. Removed in the next minor. */
      session: client.experimental.voice.session,
    },
    integration: {
      ...client.integration,
      /** @deprecated Use `client.experimental.integration.wellknown`. Removed in the next minor. */
      wellknown: {
        /** @deprecated Use `client.experimental.integration.wellknown.add`. Removed in the next minor. */
        add: client.experimental.integration.wellknown.add,
      },
    },
    mcp: {
      ...client.mcp,
      /** @deprecated Use `client.experimental.mcp.add`. Removed in the next minor. */
      add: client.experimental.mcp.add,
      /** @deprecated Use `client.experimental.mcp.remove`. Removed in the next minor. */
      remove: client.experimental.mcp.remove,
      /** @deprecated Use `client.experimental.mcp.connect`. Removed in the next minor. */
      connect: client.experimental.mcp.connect,
      /** @deprecated Use `client.experimental.mcp.disconnect`. Removed in the next minor. */
      disconnect: client.experimental.mcp.disconnect,
      /** @deprecated Use `client.experimental.mcp.client`. Removed in the next minor. */
      client: {
        /** @deprecated Use `client.experimental.mcp.client.token`. Removed in the next minor. */
        token: client.experimental.mcp.client.token,
      },
    },
    file: {
      ...client.file,
      /** @deprecated Use `client.experimental.file.write`. Removed in the next minor. */
      write: client.experimental.file.write,
      /** @deprecated Use `client.experimental.file.watch`. Removed in the next minor. */
      watch: client.experimental.file.watch,
      /** @deprecated Use `client.experimental.file.unwatch`. Removed in the next minor. */
      unwatch: client.experimental.file.unwatch,
    },
    /** @deprecated Use `client.experimental.graph`. Removed in the next minor. */
    graph: {
      /** @deprecated Use `client.experimental.graph.find`. Removed in the next minor. */
      find: client.experimental.graph.find,
      /** @deprecated Use `client.experimental.graph.entity`. Removed in the next minor. */
      entity: client.experimental.graph.entity,
      /** @deprecated Use `client.experimental.graph.neighbors`. Removed in the next minor. */
      neighbors: client.experimental.graph.neighbors,
      /** @deprecated Use `client.experimental.graph.history`. Removed in the next minor. */
      history: client.experimental.graph.history,
      /** @deprecated Use `client.experimental.graph.changes`. Removed in the next minor. */
      changes: client.experimental.graph.changes,
      /** @deprecated Use `client.experimental.graph.diff`. Removed in the next minor. */
      diff: client.experimental.graph.diff,
      /** @deprecated Use `client.experimental.graph.schema`. Removed in the next minor. */
      schema: client.experimental.graph.schema,
      /** @deprecated Use `client.experimental.graph.status`. Removed in the next minor. */
      status: client.experimental.graph.status,
      /** @deprecated Use `client.experimental.graph.lenses`. Removed in the next minor. */
      lenses: client.experimental.graph.lenses,
      /** @deprecated Use `client.experimental.graph.slice`. Removed in the next minor. */
      slice: client.experimental.graph.slice,
      /** @deprecated Use `client.experimental.graph.intelStatus`. Removed in the next minor. */
      intelStatus: client.experimental.graph.intelStatus,
      /** @deprecated Use `client.experimental.graph.overlay`. Removed in the next minor. */
      overlay: client.experimental.graph.overlay,
    },
    /** @deprecated Use `client.experimental.connectors`. Removed in the next minor. */
    connectors: {
      /** @deprecated Use `client.experimental.connectors.status`. Removed in the next minor. */
      status: client.experimental.connectors.status,
      /** @deprecated Use `client.experimental.connectors.catalog`. Removed in the next minor. */
      catalog: client.experimental.connectors.catalog,
      /** @deprecated Use `client.experimental.connectors.listConnections`. Removed in the next minor. */
      listConnections: client.experimental.connectors.listConnections,
      /** @deprecated Use `client.experimental.connectors.createConnection`. Removed in the next minor. */
      createConnection: client.experimental.connectors.createConnection,
      /** @deprecated Use `client.experimental.connectors.getConnection`. Removed in the next minor. */
      getConnection: client.experimental.connectors.getConnection,
      /** @deprecated Use `client.experimental.connectors.updateConnection`. Removed in the next minor. */
      updateConnection: client.experimental.connectors.updateConnection,
      /** @deprecated Use `client.experimental.connectors.deleteConnection`. Removed in the next minor. */
      deleteConnection: client.experimental.connectors.deleteConnection,
      /** @deprecated Use `client.experimental.connectors.testConnection`. Removed in the next minor. */
      testConnection: client.experimental.connectors.testConnection,
      /** @deprecated Use `client.experimental.connectors.syncConnection`. Removed in the next minor. */
      syncConnection: client.experimental.connectors.syncConnection,
      /** @deprecated Use `client.experimental.connectors.pauseConnection`. Removed in the next minor. */
      pauseConnection: client.experimental.connectors.pauseConnection,
      /** @deprecated Use `client.experimental.connectors.resumeConnection`. Removed in the next minor. */
      resumeConnection: client.experimental.connectors.resumeConnection,
      /** @deprecated Use `client.experimental.connectors.reconnectConnection`. Removed in the next minor. */
      reconnectConnection: client.experimental.connectors.reconnectConnection,
      /** @deprecated Use `client.experimental.connectors.rotateCredential`. Removed in the next minor. */
      rotateCredential: client.experimental.connectors.rotateCredential,
      /** @deprecated Use `client.experimental.connectors.listAudit`. Removed in the next minor. */
      listAudit: client.experimental.connectors.listAudit,
      /** @deprecated Use `client.experimental.connectors.listAuthConfigs`. Removed in the next minor. */
      listAuthConfigs: client.experimental.connectors.listAuthConfigs,
      /** @deprecated Use `client.experimental.connectors.createAuthConfig`. Removed in the next minor. */
      createAuthConfig: client.experimental.connectors.createAuthConfig,
      /** @deprecated Use `client.experimental.connectors.deleteAuthConfig`. Removed in the next minor. */
      deleteAuthConfig: client.experimental.connectors.deleteAuthConfig,
      /** @deprecated Use `client.experimental.connectors.awsSetup`. Removed in the next minor. */
      awsSetup: client.experimental.connectors.awsSetup,
      /** @deprecated Use `client.experimental.connectors.listGithubRepos`. Removed in the next minor. */
      listGithubRepos: client.experimental.connectors.listGithubRepos,
      /** @deprecated Use `client.experimental.connectors.listScopeOptions`. Removed in the next minor. */
      listScopeOptions: client.experimental.connectors.listScopeOptions,
      /** @deprecated Use `client.experimental.connectors.startDeviceAuthorization`. Removed in the next minor. */
      startDeviceAuthorization: client.experimental.connectors.startDeviceAuthorization,
      /** @deprecated Use `client.experimental.connectors.getDeviceAuthorization`. Removed in the next minor. */
      getDeviceAuthorization: client.experimental.connectors.getDeviceAuthorization,
      /** @deprecated Use `client.experimental.connectors.cancelDeviceAuthorization`. Removed in the next minor. */
      cancelDeviceAuthorization: client.experimental.connectors.cancelDeviceAuthorization,
      /** @deprecated Use `client.experimental.connectors.getScope`. Removed in the next minor. */
      getScope: client.experimental.connectors.getScope,
      /** @deprecated Use `client.experimental.connectors.putScope`. Removed in the next minor. */
      putScope: client.experimental.connectors.putScope,
      /** @deprecated Use `client.experimental.connectors.unlockVault`. Removed in the next minor. */
      unlockVault: client.experimental.connectors.unlockVault,
      /** @deprecated Use `client.experimental.connectors.rotateMasterKey`. Removed in the next minor. */
      rotateMasterKey: client.experimental.connectors.rotateMasterKey,
      /** @deprecated Use `client.experimental.connectors.forgetAll`. Removed in the next minor. */
      forgetAll: client.experimental.connectors.forgetAll,
    },
    /** @deprecated Use `client.experimental.overview`. Removed in the next minor. */
    overview: {
      /** @deprecated Use `client.experimental.overview.categories`. Removed in the next minor. */
      categories: client.experimental.overview.categories,
    },
    /** @deprecated Use `client.experimental.findings`. Removed in the next minor. */
    findings: {
      /** @deprecated Use `client.experimental.findings.list`. Removed in the next minor. */
      list: client.experimental.findings.list,
      /** @deprecated Use `client.experimental.findings.get`. Removed in the next minor. */
      get: client.experimental.findings.get,
      /** @deprecated Use `client.experimental.findings.setStatus`. Removed in the next minor. */
      setStatus: client.experimental.findings.setStatus,
    },
    /** @deprecated Use `client.experimental.scans`. Removed in the next minor. */
    scans: {
      /** @deprecated Use `client.experimental.scans.enqueue`. Removed in the next minor. */
      enqueue: client.experimental.scans.enqueue,
      /** @deprecated Use `client.experimental.scans.list`. Removed in the next minor. */
      list: client.experimental.scans.list,
      /** @deprecated Use `client.experimental.scans.scanners`. Removed in the next minor. */
      scanners: client.experimental.scans.scanners,
      /** @deprecated Use `client.experimental.scans.get`. Removed in the next minor. */
      get: client.experimental.scans.get,
      /** @deprecated Use `client.experimental.scans.cancel`. Removed in the next minor. */
      cancel: client.experimental.scans.cancel,
      /** @deprecated Use `client.experimental.scans.schedule`. Removed in the next minor. */
      schedule: client.experimental.scans.schedule,
    },
    /** @deprecated Use `client.experimental.sbom`. Removed in the next minor. */
    sbom: {
      /** @deprecated Use `client.experimental.sbom.list`. Removed in the next minor. */
      list: client.experimental.sbom.list,
      /** @deprecated Use `client.experimental.sbom.get`. Removed in the next minor. */
      get: client.experimental.sbom.get,
      /** @deprecated Use `client.experimental.sbom.export`. Removed in the next minor. */
      export: client.experimental.sbom.export,
    },
    /** @deprecated Use `client.experimental.cve`. Removed in the next minor. */
    cve: {
      /** @deprecated Use `client.experimental.cve.lookup`. Removed in the next minor. */
      lookup: client.experimental.cve.lookup,
      /** @deprecated Use `client.experimental.cve.graph`. Removed in the next minor. */
      graph: client.experimental.cve.graph,
      /** @deprecated Use `client.experimental.cve.status`. Removed in the next minor. */
      status: client.experimental.cve.status,
      /** @deprecated Use `client.experimental.cve.setMode`. Removed in the next minor. */
      setMode: client.experimental.cve.setMode,
      /** @deprecated Use `client.experimental.cve.get`. Removed in the next minor. */
      get: client.experimental.cve.get,
    },
    /** @deprecated Use `client.experimental.identity`. Removed in the next minor. */
    identity: {
      /** @deprecated Use `client.experimental.identity.paths`. Removed in the next minor. */
      paths: client.experimental.identity.paths,
    },
    /** @deprecated Use `client.experimental.bom`. Removed in the next minor. */
    bom: {
      /** @deprecated Use `client.experimental.bom.sbomList`. Removed in the next minor. */
      sbomList: client.experimental.bom.sbomList,
      /** @deprecated Use `client.experimental.bom.sbomExport`. Removed in the next minor. */
      sbomExport: client.experimental.bom.sbomExport,
      /** @deprecated Use `client.experimental.bom.ai`. Removed in the next minor. */
      ai: client.experimental.bom.ai,
      /** @deprecated Use `client.experimental.bom.aiExport`. Removed in the next minor. */
      aiExport: client.experimental.bom.aiExport,
      /** @deprecated Use `client.experimental.bom.cloud`. Removed in the next minor. */
      cloud: client.experimental.bom.cloud,
      /** @deprecated Use `client.experimental.bom.cloudExport`. Removed in the next minor. */
      cloudExport: client.experimental.bom.cloudExport,
    },
    /** @deprecated Use `client.experimental.ai`. Removed in the next minor. */
    ai: {
      /** @deprecated Use `client.experimental.ai.entities`. Removed in the next minor. */
      entities: client.experimental.ai.entities,
      /** @deprecated Use `client.experimental.ai.summary`. Removed in the next minor. */
      summary: client.experimental.ai.summary,
    },
    /** @deprecated Use `client.experimental.runtime`. Removed in the next minor. */
    runtime: {
      /** @deprecated Use `client.experimental.runtime.status`. Removed in the next minor. */
      status: client.experimental.runtime.status,
      /** @deprecated Use `client.experimental.runtime.events`. Removed in the next minor. */
      events: client.experimental.runtime.events,
      /** @deprecated Use `client.experimental.runtime.ingest`. Removed in the next minor. */
      ingest: client.experimental.runtime.ingest,
    },
    /** @deprecated Use `client.experimental.issues`. Removed in the next minor. */
    issues: {
      /** @deprecated Use `client.experimental.issues.list`. Removed in the next minor. */
      list: client.experimental.issues.list,
      /** @deprecated Use `client.experimental.issues.get`. Removed in the next minor. */
      get: client.experimental.issues.get,
      /** @deprecated Use `client.experimental.issues.setStatus`. Removed in the next minor. */
      setStatus: client.experimental.issues.setStatus,
    },
    /** @deprecated Use `client.experimental.rules`. Removed in the next minor. */
    rules: {
      /** @deprecated Use `client.experimental.rules.packs`. Removed in the next minor. */
      packs: client.experimental.rules.packs,
      /** @deprecated Use `client.experimental.rules.packRules`. Removed in the next minor. */
      packRules: client.experimental.rules.packRules,
      /** @deprecated Use `client.experimental.rules.override`. Removed in the next minor. */
      override: client.experimental.rules.override,
      /** @deprecated Use `client.experimental.rules.compliance`. Removed in the next minor. */
      compliance: client.experimental.rules.compliance,
    },
    /** @deprecated Use `client.experimental.data`. Removed in the next minor. */
    data: {
      /** @deprecated Use `client.experimental.data.stores`. Removed in the next minor. */
      stores: client.experimental.data.stores,
      /** @deprecated Use `client.experimental.data.store`. Removed in the next minor. */
      store: client.experimental.data.store,
    },
    /** @deprecated Use `client.experimental.migration`. Removed in the next minor. */
    migration: {
      /** @deprecated Use `client.experimental.migration.v1`. Removed in the next minor. */
      v1: {
        /** @deprecated Use `client.experimental.migration.v1.status`. Removed in the next minor. */
        status: client.experimental.migration.v1.status,
      },
    },
    /** @deprecated Use `client.experimental.usage`. Removed in the next minor. */
    usage: {
      /** @deprecated Use `client.experimental.usage.limits`. Removed in the next minor. */
      limits: client.experimental.usage.limits,
    },
    config: {
      ...client.config,
      /** @deprecated Use `client.experimental.config.update`. Removed in the next minor. */
      update: client.experimental.config.update,
    },
  }
}

function encodePath(value: string): string {
  return value.split("/").map(encodeURIComponent).join("/")
}

function appendQuery(params: URLSearchParams, key: string, value: unknown): void {
  if (value === undefined) return
  if (value === null) {
    params.append(key, "null")
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) appendQuery(params, key, item)
    return
  }
  if (typeof value === "object") {
    for (const [child, item] of Object.entries(value)) appendQuery(params, `${key}[${child}]`, item)
    return
  }
  params.append(key, String(value))
}

async function json(response: Response): Promise<unknown> {
  if (!isContentType(response, "application/json") && !response.headers.get("content-type")?.includes("+json")) {
    try {
      await response.body?.cancel()
    } catch {}
    throw new ClientError("UnsupportedContentType", { detail: response.headers.get("content-type") })
  }
  let text: string
  try {
    text = await response.text()
  } catch (cause) {
    throw new ClientError("Transport", { cause })
  }
  if (text === "") throw new ClientError("MalformedResponse")
  try {
    return JSON.parse(text)
  } catch (cause) {
    throw new ClientError("MalformedResponse", { cause })
  }
}

type DeclaredErrorBody = {
  readonly _tag?: string
  readonly message?: string
  readonly data?: { readonly message?: string }
}

/** Throw declared error bodies as Errors. The body's fields stay on the error, so narrowing on `_tag` or `name` still works. */
function declared(body: DeclaredErrorBody) {
  const error = Object.assign(new Error(body.message ?? body.data?.message), body)
  if (body._tag) error.name = body._tag
  return error
}

function isContentType(response: Response, expected: string) {
  return response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() === expected
}
