package bellu.cis_gcp.sql_not_public
import rego.v1

# Cloud SQL instance is publicly accessible. Unknown or missing values never violate.
violation contains {"evidence": {"public_access": input.attributes.public_access}} if {
	input.attributes.gcp_type == "sqladmin.googleapis.com/Instance"
	input.attributes.public_access == "enabled"
}
