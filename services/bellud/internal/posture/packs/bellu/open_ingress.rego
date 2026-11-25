package bellu.bellu.open_ingress

import rego.v1

# Internet-open ingress on a port outside the allowed list.
#
# The allowed ports come from input.data.allowed_ports (a list of numbers,
# network.allowed_ports). When it is not configured the default list applies.
default_allowed := [80, 443]

allowed := input.data.allowed_ports

allowed := default_allowed if not input.data.allowed_ports

port_allowed if {
	input.attributes.from_port == input.attributes.to_port
	input.attributes.from_port in allowed
}

violation contains {"evidence": {"sg": input.attributes.sg, "from_port": sprintf("%v", [object.get(input.attributes, "from_port", "all")])}} if {
	input.attributes.direction == "ingress"
	input.attributes.internet_open == "true"
	not port_allowed
}
