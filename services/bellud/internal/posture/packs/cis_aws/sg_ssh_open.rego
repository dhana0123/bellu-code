package bellu.cis_aws.sg_ssh_open

import rego.v1

# Ingress rule open to the internet that covers port 22. A rule without
# ports covers every port. Unknown internet_open or direction never violates.
covers if not input.attributes.from_port
covers if {
	input.attributes.from_port <= 22
	input.attributes.to_port >= 22
}

violation contains {"evidence": {"sg": input.attributes.sg, "port": "22"}} if {
	input.attributes.direction == "ingress"
	input.attributes.internet_open == "true"
	covers
}
