import type { SourcePanelConfig } from "../source-panel"
import type { SourceDescriptor } from "../wizard/descriptor"
/** Method ids are the connection methods the service accepts. */
export const GITLAB_SIGNIN_METHOD = "device"
export const GITLAB_PAT_METHOD = "pat"
export const GITLAB_DOCS_URL = "https://github.com/dhana0123/bellu-code/blob/bellu-graph-native/docs/connectors/gitlab.md"
const docsLabelKey = "settings.connectors.wizard.docs"
const stepKeys = {
  choose: "settings.connectors.gitlab.wizard.step.choose",
  paste: "settings.connectors.gitlab.wizard.step.authorize",
  scope: "settings.connectors.gitlab.wizard.step.projects",
}
/**
 * GitLab on the shared Wizard.
 *
 * - Sign in with GitLab: choose, authorize (device prompt), scope (projects), done
 * - Personal access token: choose, paste (token and optional host), scope (projects), done
 */
export const GITLAB_DESCRIPTOR: SourceDescriptor = {
  id: "gitlab",
  stepsLabelKey: "settings.connectors.wizard.label",
  choose: { instructionKey: "settings.connectors.gitlab.wizard.choose", docsUrl: GITLAB_DOCS_URL, docsLabelKey },
  methods: [
    {
      id: GITLAB_SIGNIN_METHOD,
      kind: "signin",
      titleKey: "settings.connectors.gitlab.wizard.signin.title",
      descriptionKey: "settings.connectors.gitlab.wizard.signin.text",
      steps: ["scope"],
      guides: {},
      stepKeys,
      actionKeys: { scope: "settings.connectors.action.save" },
    },
    {
      id: GITLAB_PAT_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.gitlab.wizard.pat.title",
      descriptionKey: "settings.connectors.gitlab.wizard.pat.text",
      steps: ["paste", "scope"],
      guides: {
        paste: { instructionKey: "settings.connectors.gitlab.wizard.pat.guide", docsUrl: GITLAB_DOCS_URL, docsLabelKey },
      },
      fields: [
        {
          id: "token",
          labelKey: "settings.connectors.gitlab.token",
          secret: true,
          multiline: false,
          descriptionKey: "settings.connectors.gitlab.token.help",
        },
        {
          id: "host",
          labelKey: "settings.connectors.gitlab.host",
          secret: false,
          multiline: false,
          optional: true,
          descriptionKey: "settings.connectors.gitlab.host.help",
        },
      ],
      stepKeys,
      actionKeys: { paste: "settings.connectors.action.connect", scope: "settings.connectors.action.save" },
    },
  ],
}
export const GITLAB_SOURCE: SourcePanelConfig = {
  descriptor: GITLAB_DESCRIPTOR,
  connectorId: "gitlab",
  serviceName: "GitLab",
  credential: (values) => ({ token: values.token ?? "" }),
  params: (values) => (values.host?.trim() ? { host: values.host.trim() } : undefined),
}
