package bellu.cis_k8s.cluster_admin_binding
import rego.v1

# Binding grants cluster-admin. Unknown or missing values never violate.
violation contains {"evidence": {"role_ref": input.attributes.role_ref}} if {
	input.attributes.role_ref == "cluster-admin"
}
