package bellu.cis_aws.iam_admin_policy

import rego.v1

# Allow statement granting "*" actions on "*" resources. actions and resources
# may be a string or a list. Missing attributes (statements are not collected
# yet) never violate.
items(x) := x if is_array(x)
items(x) := [x] if is_string(x)

violation contains {"evidence": {"policy": object.get(input.attributes, "policy", "")}} if {
	input.attributes.effect == "Allow"
	"*" in items(input.attributes.actions)
	"*" in items(input.attributes.resources)
}
