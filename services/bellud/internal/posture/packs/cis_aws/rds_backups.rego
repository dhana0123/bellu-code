package bellu.cis_aws.rds_backups

import rego.v1

# RDS instance has no automated backups. Unknown or missing backup never violates.
violation contains {"evidence": {"backup": input.attributes.backup, "resource_type": "rds:instance"}} if {
	input.attributes.resource_type == "rds:instance"
	input.attributes.backup == "disabled"
}
