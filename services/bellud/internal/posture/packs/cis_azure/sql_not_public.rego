package bellu.cis_azure.sql_not_public
import rego.v1

# SQL database is publicly accessible. Unknown or missing values never violate.
violation contains {"evidence": {"public_access": input.attributes.public_access}} if {
	input.attributes.azure_type == "azure:sql-database"
	input.attributes.public_access == "enabled"
}
