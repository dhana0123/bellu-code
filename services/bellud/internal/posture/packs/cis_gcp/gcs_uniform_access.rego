package bellu.cis_gcp.gcs_uniform_access
import rego.v1

# Cloud Storage bucket lacks uniform bucket-level access. Unknown or missing values never violate.
violation contains {"evidence": {"uniform_bucket_level_access": input.attributes.uniform_bucket_level_access}} if {
	input.attributes.gcp_type == "storage.googleapis.com/Bucket"
	input.attributes.uniform_bucket_level_access == "disabled"
}
