package bellu.cis_gcp.gcs_public_access
import rego.v1

# Cloud Storage bucket is publicly accessible. Unknown or missing values never violate.
violation contains {"evidence": {"public_access": input.attributes.public_access}} if {
	input.attributes.gcp_type == "storage.googleapis.com/Bucket"
	input.attributes.public_access == "enabled"
}
