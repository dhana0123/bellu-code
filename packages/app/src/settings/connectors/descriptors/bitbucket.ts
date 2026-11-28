import type { SourcePanelConfig } from "../source-panel"
import type { SourceDescriptor } from "../wizard/descriptor"
/** The connection method the service accepts. */
export const BITBUCKET_METHOD = "api_token"
export const BITBUCKET_DOCS_URL = "https://github.com/dhana0123/bellu-code/blob/bellu-graph-native/docs/connectors/bitbucket.md"
const docsLabelKey = "settings.connectors.wizard.docs"
/** Bitbucket on the shared Wizard: choose, paste (email and Atlassian API token), scope (repositories), done. */
export const BITBUCKET_DESCRIPTOR: SourceDescriptor = {
  id: "bitbucket",
  stepsLabelKey: "settings.connectors.wizard.label",
  hideSigninNote: true,
  choose: { instructionKey: "settings.connectors.bitbucket.wizard.choose", docsUrl: BITBUCKET_DOCS_URL, docsLabelKey },
  methods: [
    {
      id: BITBUCKET_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.bitbucket.wizard.token.title",
      descriptionKey: "settings.connectors.bitbucket.wizard.token.text",
      steps: ["paste", "scope"],
      guides: {
        paste: {
          instructionKey: "settings.connectors.bitbucket.wizard.token.guide",
          docsUrl: BITBUCKET_DOCS_URL,
          docsLabelKey,
        },
      },
      fields: [
        {
          id: "email",
          labelKey: "settings.connectors.bitbucket.email",
          secret: false,
          multiline: false,
        },
        {
          id: "api_token",
          labelKey: "settings.connectors.bitbucket.token",
          secret: true,
          multiline: false,
          descriptionKey: "settings.connectors.bitbucket.token.help",
        },
      ],
      stepKeys: {
        choose: "settings.connectors.bitbucket.wizard.step.choose",
        paste: "settings.connectors.bitbucket.wizard.step.authorize",
        scope: "settings.connectors.bitbucket.wizard.step.repositories",
      },
      actionKeys: { paste: "settings.connectors.action.connect", scope: "settings.connectors.action.save" },
    },
  ],
}
export const BITBUCKET_SOURCE: SourcePanelConfig = {
  descriptor: BITBUCKET_DESCRIPTOR,
  connectorId: "bitbucket",
  serviceName: "Bitbucket",
  credential: (values) => ({ email: values.email ?? "", api_token: values.api_token ?? "" }),
}
