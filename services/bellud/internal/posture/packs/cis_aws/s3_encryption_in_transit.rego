package bellu.cis_aws.s3_encryption_in_transit

import rego.v1

# S3 bucket allows unencrypted transport. Unknown or missing encryption_in_transit never violates.
violation contains {"evidence": {"encryption_in_transit": input.attributes.encryption_in_transit, "resource_type": "s3:bucket"}} if {
	input.attributes.resource_type == "s3:bucket"
	input.attributes.encryption_in_transit == "disabled"
}
