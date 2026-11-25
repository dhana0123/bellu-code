package bellu.cis_azure.storage_public_access
import rego.v1

# Storage account allows public access. Unknown or missing values never violate.
violation contains {"evidence": {"public_access": input.attributes.public_access}} if {
	input.attributes.azure_type == "azure:storage-account"
	input.attributes.public_access == "enabled"
}
