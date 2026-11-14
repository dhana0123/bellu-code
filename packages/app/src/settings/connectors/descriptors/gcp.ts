import type { SourcePanelConfig } from "../source-panel"
import type { SourceDescriptor } from "../wizard/descriptor"
/** The connection method the service accepts. */
export const GCP_METHOD = "service_account"
export const GCP_DOCS_URL = "https://github.com/dhana0123/bellu-code/blob/bellu-graph-native/docs/connectors/gcp.md"
const docsLabelKey = "settings.connectors.wizard.docs"
/** Google Cloud on the shared Wizard: choose, paste (service-account JSON key), scope (projects), done. */
export const GCP_DESCRIPTOR: SourceDescriptor = {
  id: "gcp",
  stepsLabelKey: "settings.connectors.wizard.label",
  hideSigninNote: true,
  choose: { instructionKey: "settings.connectors.gcp.wizard.choose", docsUrl: GCP_DOCS_URL, docsLabelKey },
  methods: [
    {
      id: GCP_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.gcp.wizard.key.title",
      descriptionKey: "settings.connectors.gcp.wizard.key.text",
      steps: ["paste", "scope"],
      guides: {
        paste: { instructionKey: "settings.connectors.gcp.wizard.key.guide", docsUrl: GCP_DOCS_URL, docsLabelKey },
      },
      fields: [
        {
          id: "key_json",
          labelKey: "settings.connectors.gcp.key",
          secret: true,
          multiline: true,
          descriptionKey: "settings.connectors.gcp.key.help",
        },
      ],
      copyBlocks: [
        {
          id: "roles",
          labelKey: "settings.connectors.gcp.roles",
          content: "roles/viewer\nroles/iam.securityReviewer",
        },
      ],
      stepKeys: {
        choose: "settings.connectors.gcp.wizard.step.choose",
        paste: "settings.connectors.gcp.wizard.step.authorize",
        scope: "settings.connectors.gcp.wizard.step.projects",
      },
      actionKeys: { paste: "settings.connectors.action.connect", scope: "settings.connectors.action.save" },
    },
  ],
}
export const GCP_SOURCE: SourcePanelConfig = {
  descriptor: GCP_DESCRIPTOR,
  connectorId: "gcp",
  serviceName: "Google Cloud",
  credential: (values) => ({ key_json: values.key_json ?? "" }),
}
