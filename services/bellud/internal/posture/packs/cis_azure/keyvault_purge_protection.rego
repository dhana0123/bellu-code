package bellu.cis_azure.keyvault_purge_protection
import rego.v1

# Key Vault has no purge protection. Unknown or missing values never violate.
violation contains {"evidence": {"purge_protection": input.attributes.purge_protection}} if {
	input.attributes.azure_type == "azure:key-vault"
	input.attributes.purge_protection == "disabled"
}
