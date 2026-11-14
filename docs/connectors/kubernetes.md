# Connect Kubernetes to Bellu Code

Bellu Code reads a cluster with a read-only ServiceAccount. You create the ServiceAccount once, then paste the API server URL, token and CA certificate.

## Auth methods

- **ServiceAccount token.** Paste the API server URL, the token and the cluster CA certificate (PEM).
- **Kubeconfig.** Paste a kubeconfig. Bellu Code converts it to the same three values. The current context must use a cluster with inline `certificate-authority-data` and a user with a static `token`. File paths, exec plugins, auth providers, `tokenFile` and client certificates are not supported.

Bellu Code trusts only the CA you paste when it talks to the API server.

## Permissions to grant

Bind the ServiceAccount to the built-in `view` ClusterRole. It reads most namespaced resources and cannot change anything. Bellu Code calls `/version`, lists namespaces and runs a SelfSubjectRulesReview to warn if the account can write (create, update, patch, delete or `*`).

## Setup YAML

Apply this with `kubectl apply -f`:

```yaml
apiVersion: v1
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
```

Then read the token and CA:

```sh
kubectl -n kube-system get secret bellu-code-token -o jsonpath='{.data.token}' | base64 -d
kubectl -n kube-system get secret bellu-code-token -o jsonpath='{.data.ca\.crt}' | base64 -d
```

The API server URL must be `https` with a DNS host name, for example `https://k8s.example.com:6443`. An IP address is not accepted.

## Private networks

Connections to private IP ranges are blocked unless the connection is allowed to use them. The blocked ranges are RFC 1918 (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10) and IPv6 unique local addresses. If your API server resolves to one of these, the connection fails until private ranges are allowed for it. Allow them only for a cluster you control.

## Troubleshooting

**Field `server` must be an https URL with a DNS host name.** Use a URL like `https://k8s.example.com:6443`, not an IP.

**Field `ca` must be a PEM encoded CA certificate.** Paste the decoded `ca.crt`, including the BEGIN and END lines.

**Kubeconfig: `certificate-authority-data` is required.** Inline the CA, or use the ServiceAccount token method.

**Kubeconfig: user field `token` is required.** Exec, auth-provider and client-certificate users are not supported. Use the ServiceAccount token method.

**Token is invalid, revoked or expired.** Re-read the token from the Secret. Tokens from `kubectl create token` expire.

**Token lacks the required read permissions.** Check the ClusterRoleBinding to `view`.

**The connection cannot reach the server.** If the API server is on a private address, see Private networks. Also check the CA matches the cluster.
