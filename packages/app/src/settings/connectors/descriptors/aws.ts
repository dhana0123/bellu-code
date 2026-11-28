import type { SourceDescriptor } from "../wizard/descriptor"
export const AWS_DOCS_URL = "https://github.com/dhana0123/bellu-code/blob/bellu-graph-native/docs/connectors/aws/README.md"
export const AWS_TERRAFORM_DOCS_URL = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs"
const docsLabelKey = "settings.connectors.aws.wizard.docs"
/**
 * AWS on the shared Wizard. The `create` step content (CloudFormation and Terraform tabs, External ID) comes from the
 * service's setup response, so the panel supplies it through the Wizard's `create` slot; the regions are the `scope` slot.
 * Method ids are the connection methods the service accepts.
 */
export const AWS_DESCRIPTOR: SourceDescriptor = {
  id: "aws",
  stepsLabelKey: "settings.connectors.aws.wizard.label",
  methodsLabelKey: "settings.connectors.aws.methods.label",
  hideSigninNote: true,
  hideRecommendedBadge: true,
  choose: { instructionKey: "settings.connectors.aws.wizard.choose", docsUrl: AWS_DOCS_URL, docsLabelKey },
  connected: {
    titleKey: "settings.connectors.aws.connected.title",
    accountKey: "settings.connectors.aws.connected.account",
    noteKey: "settings.connectors.aws.connected.note",
  },
  methods: [
    {
      id: "assume_role",
      kind: "paste",
      titleKey: "settings.connectors.aws.wizard.role.title",
      descriptionKey: "settings.connectors.aws.wizard.role.text",
      steps: ["create", "paste", "scope"],
      guides: {
        create: { instructionKey: "settings.connectors.aws.wizard.intro", docsUrl: AWS_DOCS_URL, docsLabelKey },
        paste: { instructionKey: "settings.connectors.aws.wizard.arn.hint", docsUrl: AWS_DOCS_URL, docsLabelKey },
      },
      fields: [
        {
          id: "roleArn",
          labelKey: "settings.connectors.aws.roleArn",
          secret: false,
          multiline: false,
          placeholder: "arn:aws:iam::123456789012:role/BelluReadOnly",
        },
      ],
      stepKeys: {
        create: "settings.connectors.aws.wizard.step.role",
        paste: "settings.connectors.aws.wizard.step.arn",
        scope: "settings.connectors.aws.wizard.step.regions",
      },
      // The ARN is checked together with the regions, so the paste step only continues.
      actionKeys: { paste: "settings.connectors.aws.wizard.continue", scope: "settings.connectors.aws.wizard.verify" },
    },
    {
      id: "static_keys",
      kind: "paste",
      titleKey: "settings.connectors.aws.wizard.keys.title",
      descriptionKey: "settings.connectors.aws.wizard.keys.text",
      steps: ["paste", "scope"],
      guides: {
        paste: { instructionKey: "settings.connectors.aws.wizard.keys.text", docsUrl: AWS_DOCS_URL, docsLabelKey },
      },
      fields: [
        { id: "accessKeyId", labelKey: "settings.connectors.aws.accessKeyId", secret: true, multiline: false },
        { id: "secretAccessKey", labelKey: "settings.connectors.aws.secretAccessKey", secret: true, multiline: false },
        {
          id: "sessionToken",
          labelKey: "settings.connectors.aws.sessionToken",
          secret: true,
          multiline: false,
          optional: true,
        },
      ],
      stepKeys: {
        paste: "settings.connectors.aws.wizard.step.keys",
        scope: "settings.connectors.aws.wizard.step.regions",
      },
      actionKeys: { paste: "settings.connectors.aws.wizard.continue", scope: "settings.connectors.action.connect" },
    },
  ],
}
