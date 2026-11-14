import type { SourcePanelConfig } from "../source-panel"
import type { SourceDescriptor } from "../wizard/descriptor"
/** The connection method the service accepts. */
export const CLOUDFLARE_METHOD = "token"
export const CLOUDFLARE_DOCS_URL = "https://github.com/dhana0123/bellu-code/blob/bellu-graph-native/docs/connectors/cloudflare.md"
const docsLabelKey = "settings.connectors.wizard.docs"
/** Cloudflare on the shared Wizard: choose, paste (API token, sent as a Bearer token), scope (accounts), done. */
export const CLOUDFLARE_DESCRIPTOR: SourceDescriptor = {
  id: "cloudflare",
  stepsLabelKey: "settings.connectors.wizard.label",
  hideSigninNote: true,
  choose: { instructionKey: "settings.connectors.cloudflare.wizard.choose", docsUrl: CLOUDFLARE_DOCS_URL, docsLabelKey },
  methods: [
    {
      id: CLOUDFLARE_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.cloudflare.wizard.token.title",
      descriptionKey: "settings.connectors.cloudflare.wizard.token.text",
      steps: ["paste", "scope"],
      guides: {
        paste: {
          instructionKey: "settings.connectors.cloudflare.wizard.token.guide",
          docsUrl: CLOUDFLARE_DOCS_URL,
          docsLabelKey,
        },
      },
      fields: [
        {
          id: "token",
          labelKey: "settings.connectors.cloudflare.token",
          secret: true,
          multiline: false,
          descriptionKey: "settings.connectors.cloudflare.token.help",
        },
      ],
      stepKeys: {
        choose: "settings.connectors.cloudflare.wizard.step.choose",
        paste: "settings.connectors.cloudflare.wizard.step.authorize",
        scope: "settings.connectors.cloudflare.wizard.step.accounts",
      },
      actionKeys: { paste: "settings.connectors.action.connect", scope: "settings.connectors.action.save" },
    },
  ],
}
export const CLOUDFLARE_SOURCE: SourcePanelConfig = {
  descriptor: CLOUDFLARE_DESCRIPTOR,
  connectorId: "cloudflare",
  serviceName: "Cloudflare",
  credential: (values) => ({ token: values.token ?? "" }),
}
