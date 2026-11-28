package bellu.cis_aws.s3_logging

import rego.v1

# S3 bucket access logging is disabled. Unknown or missing logging never violates.
violation contains {"evidence": {"logging": input.attributes.logging, "resource_type": "s3:bucket"}} if {
	input.attributes.resource_type == "s3:bucket"
	input.attributes.logging == "disabled"
}
