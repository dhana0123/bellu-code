// Package gcpschema declares the kinds, resource types, and relations that the
// gcp source owns. It imports only the standard library and schema.
package gcpschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// Kind names.
const (
	KindProject    = "gcp_project"
	KindResource   = "gcp_resource"
	KindIAMBinding = "gcp_iam_binding"
)

// DiscriminatorType is the gcp_resource attribute that selects the type.
const DiscriminatorType = "gcp_type"

// Category ids.
const (
	CatOwnership = "ownership"
	CatNetwork   = "network"
	CatCompute   = "compute"
	CatData      = "data"
	CatIdentity  = "identity"
)

// gcp_resource type names.
const (
	TypeNetwork        = "compute.googleapis.com/Network"
	TypeSubnetwork     = "compute.googleapis.com/Subnetwork"
	TypeFirewall       = "compute.googleapis.com/Firewall"
	TypeInstance       = "compute.googleapis.com/Instance"
	TypeGKECluster     = "container.googleapis.com/Cluster"
	TypeBucket         = "storage.googleapis.com/Bucket"
	TypeSQLInstance    = "sqladmin.googleapis.com/Instance"
	TypeServiceAccount = "iam.googleapis.com/ServiceAccount"
)

const edgeAttrs = " Edge attributes: evidence (string), confidence (extracted or inferred), observed_at (RFC 3339 time)."

const resourceAttrs = " Scalar attributes: gcp_type (string, one of the declared types); location (string, a region or zone); internet_exposed (string: true, partial, or false); truncated (string: true, set only when collection was cut short)."

func typ(name, category, desc string, ov schema.OverviewCategory) schema.TypeDeclaration {
	return schema.TypeDeclaration{Name: name, Category: category, Description: desc, Overview: ov}
}

func rel(name string, dir schema.Direction, conf schema.Confidence, desc string, from, to []string) schema.RelationDeclaration {
	return schema.RelationDeclaration{Name: name, Direction: dir, Confidence: conf, Description: desc + edgeAttrs, From: from, To: to}
}

// Declaration returns the gcp source declaration.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{
		Source: schema.SourceGCP,
		Prefix: "gcp_",
		Kinds: []schema.KindDeclaration{
			{
				Name:        KindProject,
				Overview:    schema.OvCloud,
				Identity:    []string{"connection", "project_id"},
				Description: "A Google Cloud project that a connection reads. Attribute truncated (string: true) marks a cut-short collection.",
			},
			{
				Name:          KindResource,
				Overview:      schema.OvCloud,
				Identity:      []string{"connection", "resource_name"},
				Description:   "A Google Cloud resource identified by its full resource name. The gcp_type attribute says which type it is." + resourceAttrs,
				Discriminator: DiscriminatorType,
				Types: []schema.TypeDeclaration{
					typ(TypeNetwork, CatNetwork, "A VPC network.", ""),
					typ(TypeSubnetwork, CatNetwork, "A VPC subnetwork.", ""),
					typ(TypeFirewall, CatNetwork, "A VPC firewall rule.", schema.OvNetwork),
					typ(TypeInstance, CatCompute, "A Compute Engine instance.", ""),
					typ(TypeGKECluster, CatCompute, "A Google Kubernetes Engine cluster.", ""),
					typ(TypeBucket, CatData, "A Cloud Storage bucket.", schema.OvData),
					typ(TypeSQLInstance, CatData, "A Cloud SQL instance.", schema.OvData),
					typ(TypeServiceAccount, CatIdentity, "An IAM service account.", schema.OvIdentity),
				},
			},
			{
				Name:        KindIAMBinding,
				Overview:    schema.OvIdentity,
				Identity:    []string{"connection", "scope", "role", "member"},
				Description: "One IAM policy binding of a member to a role on a scope. scope is the project or resource name; role is the role name; member is the principal. Conditions are kept as a condition_title string.",
			},
		},
		Relations: []schema.RelationDeclaration{
			rel("gcp_in_project", schema.Reverse, schema.Extracted, "The resource is contained in the project.",
				[]string{KindResource}, []string{KindProject}),
			rel("gcp_in_network", schema.Reverse, schema.Extracted, "The subnetwork, firewall, instance or cluster is contained in the VPC network.",
				[]string{TypeSubnetwork, TypeFirewall, TypeInstance, TypeGKECluster}, []string{TypeNetwork}),
			rel("gcp_in_subnet", schema.Reverse, schema.Extracted, "The instance or cluster has its interface in the subnetwork.",
				[]string{TypeInstance, TypeGKECluster}, []string{TypeSubnetwork}),
			rel("gcp_firewall_applies_to", schema.Forward, schema.Inferred, "The firewall rule filters traffic to the target instance. Inferred from target tags and service accounts.",
				[]string{TypeFirewall}, []string{TypeInstance}),
			rel("gcp_runs_as", schema.Forward, schema.Extracted, "Compromise of the workload yields the service account credentials.",
				[]string{TypeInstance, TypeGKECluster}, []string{TypeServiceAccount}),
			rel("gcp_binding_on", schema.Reverse, schema.Extracted, "The binding is part of the policy of its scope; a scope change impacts the binding.",
				[]string{KindIAMBinding}, []string{KindProject, KindResource}),
			rel("gcp_binding_grants", schema.Forward, schema.Extracted, "The binding grants its role on the scope to the member service account, so the member gains the role's permissions.",
				[]string{KindIAMBinding}, []string{TypeServiceAccount}),
			rel("gcp_encrypted_by", schema.Reverse, schema.Extracted, "The resource depends on its customer-managed key for confidentiality and availability.",
				[]string{KindResource}, []string{KindResource}),
		},
		Categories: []schema.CategoryDeclaration{
			{ID: CatOwnership, Name: "Ownership", Status: schema.RegisteredOnly, ReadOps: []string{"cloudresourcemanager.projects.get"}},
			{ID: CatNetwork, Name: "Network", Status: schema.RegisteredOnly, ReadOps: []string{"compute.networks.list", "compute.subnetworks.list", "compute.firewalls.list"}},
			{ID: CatCompute, Name: "Compute", Status: schema.RegisteredOnly, ReadOps: []string{"compute.instances.list", "container.clusters.list"}},
			{ID: CatData, Name: "Data", Status: schema.RegisteredOnly, ReadOps: []string{"storage.buckets.list", "sql.instances.list"}},
			{ID: CatIdentity, Name: "Identity", Status: schema.RegisteredOnly, ReadOps: []string{"iam.serviceAccounts.list", "cloudresourcemanager.projects.getIamPolicy"}},
		},
	}
}
