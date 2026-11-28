package bellu.bellu.data_exposure

import rego.v1

# A data store holding a sensitive data class that is public or unencrypted.
#
# PLACEHOLDER INPUT: classes come from the data_classification table. The
# engine input has no such field yet, so the rule reads, in order,
# input.data.classifications[input.id] and input.attributes.data_classes (both
# lists of class names). With neither present the rule never fires.
sensitive := {"pii", "phi", "pci", "credentials", "secrets", "financial"}

classes := input.data.classifications[input.id]

classes := input.attributes.data_classes if not input.data.classifications[input.id]

sensitive_found := {lower(c) | some c in classes; lower(c) in sensitive}

exposed contains "public_access" if input.attributes.public_access == "enabled"

exposed contains "encryption_at_rest" if input.attributes.encryption_at_rest == "disabled"

violation contains {"discriminator": reason, "evidence": {"reason": reason, "classes": concat(",", sensitive_found)}} if {
	count(sensitive_found) > 0
	some reason in exposed
}
