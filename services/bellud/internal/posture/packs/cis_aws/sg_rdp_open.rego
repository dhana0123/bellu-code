package bellu.cis_aws.sg_rdp_open

import rego.v1

# Ingress rule open to the internet that covers port 3389. A rule without
# ports covers every port. Unknown internet_open or direction never violates.
covers if not input.attributes.from_port
covers if {
	input.attributes.from_port <= 3389
	input.attributes.to_port >= 3389
}

violation contains {"evidence": {"sg": input.attributes.sg, "port": "3389"}} if {
	input.attributes.direction == "ingress"
	input.attributes.internet_open == "true"
	covers
}
