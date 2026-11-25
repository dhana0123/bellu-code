package bellu.cis_aws.s3_public_access

import rego.v1

# S3 bucket allows public access. Unknown or missing public_access never violates.
violation contains {"evidence": {"public_access": input.attributes.public_access, "resource_type": "s3:bucket"}} if {
	input.attributes.resource_type == "s3:bucket"
	input.attributes.public_access == "enabled"
}
