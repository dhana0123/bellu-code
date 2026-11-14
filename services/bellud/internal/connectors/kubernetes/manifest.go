// Package kubernetes is the Kubernetes connector: a pasted API server URL,
// ServiceAccount token and CA certificate. The broker pins TLS to the pasted CA.
package kubernetes

import (
	"encoding/json"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

// ConnectorID is the id of the built-in Kubernetes connector.
const ConnectorID = "kubernetes"

// Auth method ids.
const (
	// MethodToken is a pasted JSON document {server, token, ca}.
	MethodToken = "service_account_token"
	// MethodKubeconfig is a pasted kubeconfig, converted to the same document.
	MethodKubeconfig = "kubeconfig"
)

// CASlot is the connection vault slot holding the PEM CA bundle.
const CASlot = "ca"

// hostPlaceholder is filled by the policy with Descriptor.Host: the host name
// of the connection's API server (without port).
const hostPlaceholder = "{host}"

// Operation names and paths.
const (
	opVersion    = "GET /version"
	opNamespaces = "GET /api/v1/namespaces"
	opRulesQuery = "POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
)

// Manifest returns the built-in Kubernetes manifest. Every operation is a GET
// read, except SelfSubjectRulesReview: a POST read query restricted by
// IsSelfSubjectRulesReviewBody.
func Manifest() manifest.Manifest {
	return manifest.Manifest{
		ID: ConnectorID, Version: "1.0.0", Name: "Kubernetes", Icon: "kubernetes", Builtin: true,
		AuthMethods: []manifest.AuthMethod{
			{ID: MethodToken, Name: "ServiceAccount token", Enabled: true},
			{ID: MethodKubeconfig, Name: "Kubeconfig", Enabled: true},
		},
		Permissions: []manifest.Permission{
			{Name: "view", Description: "Read most namespaced resources (built-in view ClusterRole)", ReadOnly: true},
		},
		Operations: []manifest.Operation{
			{Name: opVersion, Class: manifest.ClassRead, Method: "GET", Host: hostPlaceholder, Path: "/version"},
			{Name: opNamespaces, Class: manifest.ClassRead, Method: "GET", Host: hostPlaceholder, Path: "/api/v1/namespaces"},
			{Name: opRulesQuery, Class: manifest.ClassRead, Method: "POST", Query: true,
				Host: hostPlaceholder, Path: rulesReviewPath, MaxBytes: 16 << 10},
		},
		Egress:   []string{hostPlaceholder},
		Entities: []string{},
	}
}

// IsSelfSubjectRulesReviewBody reports whether body is a SelfSubjectRulesReview
// request: kind SelfSubjectRulesReview, an optional apiVersion of
// authorization.k8s.io/v1, an empty or absent metadata and a spec holding only
// a string namespace. Wire it as broker.Config.QueryValidators["kubernetes"].
func IsSelfSubjectRulesReviewBody(body []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	for k := range m {
		switch k {
		case "apiVersion", "kind", "metadata", "spec":
		default:
			return false
		}
	}
	var kind, version string
	if json.Unmarshal(m["kind"], &kind) != nil || kind != "SelfSubjectRulesReview" {
		return false
	}
	if raw, ok := m["apiVersion"]; ok && (json.Unmarshal(raw, &version) != nil || version != "authorization.k8s.io/v1") {
		return false
	}
	if raw, ok := m["metadata"]; ok {
		var meta map[string]json.RawMessage
		if json.Unmarshal(raw, &meta) != nil || len(meta) != 0 {
			return false
		}
	}
	var spec map[string]json.RawMessage
	if json.Unmarshal(m["spec"], &spec) != nil || len(spec) != 1 {
		return false
	}
	var ns string
	return json.Unmarshal(spec["namespace"], &ns) == nil
}

// SetupYAML is the kubectl manifest shown in the connect wizard: a ServiceAccount
// bound to the built-in read-only "view" ClusterRole, with a long-lived token
// Secret. Read the token and CA with the commands in the comments.
const SetupYAML = `apiVersion: v1
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
# CA:    kubectl -n kube-system get secret bellu-code-token -o jsonpath='{.data.ca\.crt}' | base64 -d
`

const rulesReviewPath = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
