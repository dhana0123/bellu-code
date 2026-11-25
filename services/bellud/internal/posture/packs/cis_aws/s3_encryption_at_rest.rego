package bellu.cis_aws.s3_encryption_at_rest

import rego.v1

# S3 bucket is not encrypted at rest. Unknown or missing encryption_at_rest never violates.
violation contains {"evidence": {"encryption_at_rest": input.attributes.encryption_at_rest, "resource_type": "s3:bucket"}} if {
	input.attributes.resource_type == "s3:bucket"
	input.attributes.encryption_at_rest == "disabled"
}
