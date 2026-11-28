package bellu.cis_aws.rds_encrypted

import rego.v1

# RDS instance is not encrypted. Unknown or missing encryption_at_rest never violates.
violation contains {"evidence": {"encryption_at_rest": input.attributes.encryption_at_rest, "resource_type": "rds:instance"}} if {
	input.attributes.resource_type == "rds:instance"
	input.attributes.encryption_at_rest == "disabled"
}
