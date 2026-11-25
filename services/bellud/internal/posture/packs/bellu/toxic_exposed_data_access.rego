package bellu.bellu.toxic_exposed_data_access

import rego.v1

# Toxic combination (b): an internet-exposed workload whose execution role can
# read a data store holding a sensitive data class.
#
# Path: workload -aws_exec_role-> role -aws_can_access-> data store.
# aws_can_access is derived by Authorization_Analysis; the issue builder keeps
# only confirmed relations.

sensitive := {"pii", "phi", "pci", "credentials", "secrets", "financial"}

targets(id, rel) := {e.to | some e in bellu.neighbors(id, rel); e.from == id}

classes(attrs) := {lower(c) | some c in attrs.data_classes; lower(c) in sensitive}

violation contains {
	"discriminator": store,
	"evidence": {"role": role, "data_store": store, "classes": concat(",", classes(s.attributes))},
	"path": [
		{"entity": input.id, "relation": ""},
		{"entity": role, "relation": "aws_exec_role"},
		{"entity": store, "relation": "aws_can_access"},
	],
} if {
	input.attributes.internet_exposed == "true"
	some role in targets(input.id, "aws_exec_role")
	some store in targets(role, "aws_can_access")
	s := bellu.entity(store)
	count(classes(s.attributes)) > 0
}
