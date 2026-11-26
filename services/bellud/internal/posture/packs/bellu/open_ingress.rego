package bellu.bellu.open_ingress

import rego.v1

# Internet-open ingress on a port outside the allowed list. Applies to AWS
# security group rules, GCP firewalls, Azure NSGs and Kubernetes services that
# carry direction, internet_open, from_port and to_port.
#
# The allowed ports come from input.data.allowed_ports (a list of numbers,
# network.allowed_ports). When it is not configured the default list applies.
# A missing port range means every port. One violation is produced per rule,
# listing the ports of the range that are outside the allowed list.
default_allowed := [80, 443]

allowed := input.data.allowed_ports

allowed := default_allowed if not input.data.allowed_ports

from_port := object.get(input.attributes, "from_port", 0)

to_port := object.get(input.attributes, "to_port", 65535)

# Allowed ports inside the rule's range, ascending.
inside := sort([p | some p in allowed; p >= from_port; p <= to_port])

# Gap boundaries: sentinels around the allowed ports inside the range.
bounds := array.concat(array.concat([from_port - 1], inside), [to_port + 1])

_fmt(lo, hi) := sprintf("%d", [lo]) if lo == hi

_fmt(lo, hi) := sprintf("%d-%d", [lo, hi]) if lo != hi

# Offending ranges ordered by their start port.
offending := [r |
	some i, next in bounds
	i > 0
	lo := bounds[i - 1] + 1
	hi := next - 1
	lo <= hi
	r := _fmt(lo, hi)
]

violation contains {"evidence": {"rule": input.id, "ports": concat(",", offending)}} if {
	input.attributes.direction == "ingress"
	input.attributes.internet_open == "true"
	count(offending) > 0
}
