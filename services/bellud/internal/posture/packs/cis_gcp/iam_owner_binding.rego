package bellu.cis_gcp.iam_owner_binding
import rego.v1

# IAM binding grants roles/owner. Unknown or missing values never violate.
violation contains {"evidence": {"role": input.attributes.role}} if {
	input.attributes.role == "roles/owner"
}
