import type { SourcePanelConfig } from "../source-panel"
import type { SourceDescriptor } from "../wizard/descriptor"
/** Method ids are the connection methods the service accepts. */
export const KUBERNETES_TOKEN_METHOD = "service_account_token"
export const KUBERNETES_KUBECONFIG_METHOD = "kubeconfig"
export const KUBERNETES_DOCS_URL = "https://github.com/dhana0123/bellu-code/blob/bellu-graph-native/docs/connectors/kubernetes.md"
const docsLabelKey = "settings.connectors.wizard.docs"
/** Mirrors `kubernetes.SetupYAML` in services/bellud/internal/connectors/kubernetes/manifest.go. Keep them in sync. */
export const KUBERNETES_SETUP_YAML = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: bellu-code
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bellu-code-view
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: ServiceAccount
    name: bellu-code
    namespace: kube-system
---
apiVersion: v1
kind: Secret
metadata:
  name: bellu-code-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: bellu-code
type: kubernetes.io/service-account-token
# Token: kubectl -n kube-system get secret bellu-code-token -o jsonpath='{.data.token}' | base64 -d
# CA:    kubectl -n kube-system get secret bellu-code-token -o jsonpath='{.data.ca\\.crt}' | base64 -d
`
const stepKeys = {
  choose: "settings.connectors.kubernetes.wizard.step.choose",
  paste: "settings.connectors.kubernetes.wizard.step.authorize",
  scope: "settings.connectors.kubernetes.wizard.step.namespaces",
}
const actionKeys = { paste: "settings.connectors.action.connect", scope: "settings.connectors.action.save" } as const
/**
 * Kubernetes on the shared Wizard.
 *
 * - ServiceAccount token: choose, paste (server URL, token, CA), scope (namespaces), done
 * - Kubeconfig: choose, paste (kubeconfig; the service extracts the three values), scope (namespaces), done
 */
export const KUBERNETES_DESCRIPTOR: SourceDescriptor = {
  id: "kubernetes",
  stepsLabelKey: "settings.connectors.wizard.label",
  hideSigninNote: true,
  choose: { instructionKey: "settings.connectors.kubernetes.wizard.choose", docsUrl: KUBERNETES_DOCS_URL, docsLabelKey },
  methods: [
    {
      id: KUBERNETES_TOKEN_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.kubernetes.wizard.token.title",
      descriptionKey: "settings.connectors.kubernetes.wizard.token.text",
      steps: ["paste", "scope"],
      guides: {
        paste: {
          instructionKey: "settings.connectors.kubernetes.wizard.token.guide",
          docsUrl: KUBERNETES_DOCS_URL,
          docsLabelKey,
        },
      },
      fields: [
        {
          id: "server",
          labelKey: "settings.connectors.kubernetes.server",
          secret: false,
          multiline: false,
          placeholder: "https://203.0.113.10:6443",
          descriptionKey: "settings.connectors.kubernetes.server.help",
        },
        {
          id: "token",
          labelKey: "settings.connectors.kubernetes.token",
          secret: true,
          multiline: false,
          descriptionKey: "settings.connectors.kubernetes.token.help",
        },
        {
          id: "ca",
          labelKey: "settings.connectors.kubernetes.ca",
          secret: false,
          multiline: true,
          descriptionKey: "settings.connectors.kubernetes.ca.help",
        },
      ],
      copyBlocks: [{ id: "setup", labelKey: "settings.connectors.kubernetes.setup", content: KUBERNETES_SETUP_YAML }],
      stepKeys,
      actionKeys,
    },
    {
      id: KUBERNETES_KUBECONFIG_METHOD,
      kind: "paste",
      titleKey: "settings.connectors.kubernetes.wizard.kubeconfig.title",
      descriptionKey: "settings.connectors.kubernetes.wizard.kubeconfig.text",
      steps: ["paste", "scope"],
      guides: {
        paste: {
          instructionKey: "settings.connectors.kubernetes.wizard.kubeconfig.guide",
          docsUrl: KUBERNETES_DOCS_URL,
          docsLabelKey,
        },
      },
      fields: [
        {
          id: "kubeconfig",
          labelKey: "settings.connectors.kubernetes.kubeconfig",
          secret: true,
          multiline: true,
          descriptionKey: "settings.connectors.kubernetes.kubeconfig.help",
        },
      ],
      stepKeys,
      actionKeys,
    },
  ],
}
export const KUBERNETES_SOURCE: SourcePanelConfig = {
  descriptor: KUBERNETES_DESCRIPTOR,
  connectorId: "kubernetes",
  serviceName: "Kubernetes",
  // The service reads server/token/ca or kubeconfig depending on the method, so send only the filled fields.
  credential: (values) =>
    Object.fromEntries(
      ["server", "token", "ca", "kubeconfig"].flatMap((id) => (values[id] ? [[id, values[id]]] : [])),
    ),
}
