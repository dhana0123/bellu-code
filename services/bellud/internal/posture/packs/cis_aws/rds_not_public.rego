package bellu.cis_aws.rds_not_public

import rego.v1

# RDS instance is publicly accessible. Unknown or missing public_access never violates.
violation contains {"evidence": {"public_access": input.attributes.public_access, "resource_type": "rds:instance"}} if {
	input.attributes.resource_type == "rds:instance"
	input.attributes.public_access == "enabled"
}
