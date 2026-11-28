package bellu.cis_gcp.sql_ssl_required
import rego.v1

# Cloud SQL instance does not require SSL. Unknown or missing values never violate.
violation contains {"evidence": {"ssl_required": input.attributes.ssl_required}} if {
	input.attributes.gcp_type == "sqladmin.googleapis.com/Instance"
	input.attributes.ssl_required == "disabled"
}
