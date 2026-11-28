import type { SourcePanelConfig } from "../source-panel"
import type { SourceDescriptor } from "../wizard/descriptor"
/** Method ids are the connection methods the service accepts. */
export const AZURE_SIGNIN_METHOD = "device"
/** Declared but disabled by the manifest: the broker has no client_credentials kind yet. */
export const AZURE_SERVICE_PRINCIPAL_METHOD = "service-principal"
export const AZURE_DOCS_URL = "https://github.com/dhana0123/bellu-code/blob/bellu-graph-native/docs/connectors/azure.md"
const docsLabelKey = "settings.connectors.wizard.docs"
const stepKeys = {
  choose: "settings.connectors.azure.wizard.step.choose",
  paste: "settings.connectors.azure.wizard.step.authorize",
  scope: "settings.connectors.azure.wizard.step.subscriptions",
}
/**
 * Microsoft Azure on the shared Wizard.
 *
 * - Sign in with Microsoft (Entra device sign-in, needs BELLUCODE_AZURE_CLIENT_ID on the service): choose,
 *   authorize (device prompt), scope (subscriptions), done
 * - Service principal: choose, paste (tenant, client id, secret), scope (subscriptions), done. Not selectable
 *   until the service enables it.
 */
export const AZURE_DESCRIPTOR: SourceDescriptor = {
  id: "azure",
  stepsLabelKey: "settings.connectors.wizard.label",
  choose: { instructionKey: "settings.connectors.azure.wizard.choose", docsUrl: AZURE_DOCS_URL, docsLabelKey },
  methods: [
    {
      id: AZURE_SIGNIN_METHOD,
      kind: "signin",
      titleKey: "settings.connectors.azure.wizard.signin.title",
      descriptionKey: "settings.connectors.azure.wizard.signin.text",
      steps: ["scope"],
      guides: {},
      stepKeys,
      actionKeys: { scope: "settings.connectors.action.save" },
    },
    {
      id: AZURE_SERVICE_PRINCIPAL_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.azure.wizard.sp.title",
      descriptionKey: "settings.connectors.azure.wizard.sp.text",
      steps: ["paste", "scope"],
      guides: {
        paste: { instructionKey: "settings.connectors.azure.wizard.sp.guide", docsUrl: AZURE_DOCS_URL, docsLabelKey },
      },
      fields: [
        { id: "tenant_id", labelKey: "settings.connectors.azure.tenant", secret: false, multiline: false },
        { id: "client_id", labelKey: "settings.connectors.azure.client", secret: false, multiline: false },
        {
          id: "client_secret",
          labelKey: "settings.connectors.azure.secret",
          secret: true,
          multiline: false,
          descriptionKey: "settings.connectors.azure.secret.help",
        },
      ],
      stepKeys,
      actionKeys: { paste: "settings.connectors.action.connect", scope: "settings.connectors.action.save" },
    },
  ],
}
export const AZURE_SOURCE: SourcePanelConfig = {
  descriptor: AZURE_DESCRIPTOR,
  connectorId: "azure",
  serviceName: "Microsoft",
  credential: (values) => ({
    tenant_id: values.tenant_id ?? "",
    client_id: values.client_id ?? "",
    client_secret: values.client_secret ?? "",
  }),
}
