import type { SourceDescriptor } from "../wizard/descriptor"

/** Method ids are the connection methods the service accepts. */
export const GITHUB_SIGNIN_METHOD = "device"
export const GITHUB_PAT_METHOD = "pat"

/**
 * GitHub on the shared Wizard.
 *
 * - Sign in with GitHub: choose, authorize (device prompt on `choose` while authorizing), scope (repositories), done
 * - Personal access token: choose, paste (token and optional host), scope (repositories), done
 */
export const GITHUB_DESCRIPTOR: SourceDescriptor = {
  id: "github",
  stepsLabelKey: "settings.connectors.github.wizard.label",
  signinUnavailableKey: "settings.connectors.github.signin.unavailable",
  connected: {
    titleKey: "settings.connectors.github.connected.title",
    accountKey: "settings.connectors.github.connected.account",
    noteKey: "settings.connectors.github.connected.repositories",
  },
  methods: [
    {
      id: GITHUB_SIGNIN_METHOD,
      kind: "signin",
      titleKey: "settings.connectors.github.wizard.signin.title",
      descriptionKey: "settings.connectors.github.wizard.signin.text",
      steps: ["scope"],
      guides: {},
      stepKeys: {
        choose: "settings.connectors.github.wizard.step.choose",
        scope: "settings.connectors.github.wizard.step.repositories",
      },
      actionKeys: { scope: "settings.connectors.action.save" },
    },
    {
      id: GITHUB_PAT_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.github.wizard.pat.title",
      descriptionKey: "settings.connectors.github.wizard.pat.text",
      steps: ["paste", "scope"],
      guides: {},
      fields: [
        {
          id: "token",
          labelKey: "settings.connectors.github.token",
          secret: true,
          multiline: false,
          descriptionKey: "settings.connectors.github.token.help",
        },
        {
          id: "host",
          labelKey: "settings.connectors.github.host",
          secret: false,
          multiline: false,
          optional: true,
          descriptionKey: "settings.connectors.github.host.help",
        },
      ],
      stepKeys: {
        choose: "settings.connectors.github.wizard.step.choose",
        paste: "settings.connectors.github.wizard.step.authorize",
        scope: "settings.connectors.github.wizard.step.repositories",
      },
      actionKeys: { paste: "settings.connectors.action.connect", scope: "settings.connectors.action.save" },
    },
  ],
}
