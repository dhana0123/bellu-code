package bellu.bellu.toxic_public_sensitive_bucket

import rego.v1

# Toxic combination (c): a public storage bucket that holds a sensitive data
# class. Both facts are attributes of the bucket (public_access and
# data_classes), so the path is the bucket itself.

sensitive := {"pii", "phi", "pci", "credentials", "secrets", "financial"}

found := {lower(c) | some c in input.attributes.data_classes; lower(c) in sensitive}

violation contains {
	"evidence": {"bucket": input.id, "classes": concat(",", found)},
	"path": [{"entity": input.id, "relation": ""}],
} if {
	input.attributes.resource_type == "s3:bucket"
	input.attributes.public_access == "enabled"
	count(found) > 0
}
