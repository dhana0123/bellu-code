// Package k8sschema declares the kinds and relations that the Kubernetes
// source owns. It imports only the standard library and schema.
//
// Secret and ConfigMap entities are references by name only: no kind declares
// an attribute that can hold a value (Requirement 14.6).
package k8sschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// CatWorkloads is the category of workload kinds.
const CatWorkloads = "workloads"

// Kind names.
const (
	KindCluster        = "k8s_cluster"
	KindNamespace      = "k8s_namespace"
	KindWorkload       = "k8s_workload"
	KindPod            = "k8s_pod"
	KindNode           = "k8s_node"
	KindService        = "k8s_service"
	KindIngress        = "k8s_ingress"
	KindNetPol         = "k8s_netpol"
	KindServiceAccount = "k8s_serviceaccount"
	KindRole           = "k8s_role"
	KindBinding        = "k8s_binding"
	KindSecretRef      = "k8s_secret_ref"
	KindConfigMapRef   = "k8s_configmap_ref"
)

// DiscriminatorWorkloadKind selects the workload type.
const DiscriminatorWorkloadKind = "workload_kind"

// Workload kind values.
const (
	TypeDeployment  = "Deployment"
	TypeStatefulSet = "StatefulSet"
	TypeDaemonSet   = "DaemonSet"
	TypeReplicaSet  = "ReplicaSet"
	TypeJob         = "Job"
	TypeCronJob     = "CronJob"
)

// Relation names. Each edge carries the attributes evidence, confidence and
// observed_at.
const (
	RelInNamespace = "k8s_in_namespace"
	RelRunsAsSA    = "k8s_runs_as_sa"
	RelBoundTo     = "k8s_bound_to"
	RelExposes     = "k8s_exposes"
	RelUsesImage   = "k8s_uses_image"
)

var scoped = []string{"connection", "cluster", "uid"}

func kind(name string, ov schema.OverviewCategory, desc string, identity ...string) schema.KindDeclaration {
	if identity == nil {
		identity = scoped
	}
	return schema.KindDeclaration{Name: name, Identity: identity, Overview: ov, Description: desc}
}

func workloadType(name string) schema.TypeDeclaration {
	return schema.TypeDeclaration{Name: name, Category: CatWorkloads, Description: "A Kubernetes " + name + "."}
}

func rel(name string, d schema.Direction, desc string, from, to []string) schema.RelationDeclaration {
	return schema.RelationDeclaration{Name: name, Direction: d, Confidence: schema.Extracted, Description: desc, From: from, To: to}
}

// Declaration returns the Kubernetes source declaration. Identity comes from
// the API server uid, so a rename keeps the entity id.
func Declaration() schema.SourceDeclaration {
	wl := kind(KindWorkload, schema.OvRuntime, "A Kubernetes workload controller. The workload_kind attribute says which type it is.")
	wl.Discriminator = DiscriminatorWorkloadKind
	for _, t := range []string{TypeDeployment, TypeStatefulSet, TypeDaemonSet, TypeReplicaSet, TypeJob, TypeCronJob} {
		wl.Types = append(wl.Types, workloadType(t))
	}
	return schema.SourceDeclaration{
		Source: schema.SourceK8s,
		Prefix: "k8s_",
		Kinds: []schema.KindDeclaration{
			kind(KindCluster, schema.OvCloud, "A Kubernetes cluster that a connection reads.", "connection", "uid"),
			kind(KindNamespace, schema.OvCloud, "A namespace in a cluster."),
			wl,
			kind(KindPod, schema.OvRuntime, "A pod in a namespace."),
			kind(KindNode, schema.OvCloud, "A cluster node."),
			kind(KindService, schema.OvNetwork, "A Service. Its type (ClusterIP, NodePort, LoadBalancer) drives exposure."),
			kind(KindIngress, schema.OvNetwork, "An Ingress that routes external traffic to Services."),
			kind(KindNetPol, schema.OvNetwork, "A NetworkPolicy that limits pod traffic."),
			kind(KindServiceAccount, schema.OvIdentity, "A service account that pods run as."),
			kind(KindRole, schema.OvIdentity, "A Role or ClusterRole with its rules."),
			kind(KindBinding, schema.OvIdentity, "A RoleBinding or ClusterRoleBinding."),
			kind(KindSecretRef, schema.OvSecrets, "A reference to a Secret by name. Only metadata is read; no value is stored."),
			kind(KindConfigMapRef, schema.OvSecrets, "A reference to a ConfigMap by name. Only metadata is read; no value is stored."),
		},
		Categories: []schema.CategoryDeclaration{
			{ID: CatWorkloads, Name: "Workloads", Status: schema.Implemented},
		},
		Relations: []schema.RelationDeclaration{
			rel(RelInNamespace, schema.Reverse, "The object is contained in the namespace.",
				[]string{KindWorkload, KindPod, KindService, KindIngress, KindNetPol, KindServiceAccount, KindRole, KindBinding, KindSecretRef, KindConfigMapRef}, []string{KindNamespace}),
			rel(RelRunsAsSA, schema.Forward, "Compromise of the pod or workload yields the service account's permissions.",
				[]string{KindPod, KindWorkload}, []string{KindServiceAccount}),
			rel(RelBoundTo, schema.Forward, "The subject holds the role's permissions through the binding.",
				[]string{KindServiceAccount}, []string{KindRole}),
			rel(RelExposes, schema.Forward, "The service or ingress gives traffic a path to its target.",
				[]string{KindService, KindIngress}, []string{KindWorkload, KindPod, KindService}),
			rel(RelUsesImage, schema.Reverse, "The pod or workload depends on its container image. Joins to the core image kind by digest.",
				[]string{KindPod, KindWorkload}, []string{"image"}),
		},
	}
}
