package bellu.bellu.toxic_secret_reachable

import rego.v1

# Toxic combination (d): a workload with a leaked secret that can reach the
# secret's target over the network.
#
# Anchored on a `finding` of finding_type "secret" and status "open". The
# finding `affects` the workload. PLACEHOLDER: the secret's target is read from
# the finding attribute `target_id` (an Entity_ID); the secret scanner does not
# write it yet, so until it does the rule never fires. Reachability is the
# confirmed relation aws_allows_egress_to from the workload to the target.
#
# Path: finding -affects-> workload -aws_allows_egress_to-> target.

targets(id, rel) := {e.to | some e in bellu.neighbors(id, rel); e.from == id}

violation contains {
	"discriminator": target,
	"evidence": {"workload": workload, "target": target},
	"path": [
		{"entity": input.id, "relation": ""},
		{"entity": workload, "relation": "affects"},
		{"entity": target, "relation": "aws_allows_egress_to"},
	],
} if {
	input.attributes.finding_type == "secret"
	input.attributes.status == "open"
	target := input.attributes.target_id
	some workload in targets(input.id, "affects")
	target in targets(workload, "aws_allows_egress_to")
}
