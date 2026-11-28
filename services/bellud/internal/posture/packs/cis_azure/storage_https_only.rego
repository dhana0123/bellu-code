package bellu.cis_azure.storage_https_only
import rego.v1

# Storage account allows unencrypted transport. Unknown or missing values never violate.
violation contains {"evidence": {"https_only": input.attributes.https_only}} if {
	input.attributes.azure_type == "azure:storage-account"
	input.attributes.https_only == "disabled"
}
