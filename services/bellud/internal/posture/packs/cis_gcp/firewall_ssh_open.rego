package bellu.cis_gcp.firewall_ssh_open
import rego.v1

# Firewall allows 0.0.0.0/0 to SSH (22). Unknown or missing values never violate.
covers if not input.attributes.from_port
covers if {
	input.attributes.from_port <= 22
	input.attributes.to_port >= 22
}
violation contains {"evidence": {"rule": input.id, "port": "22"}} if {
	input.attributes.direction == "ingress"
	input.attributes.internet_open == "true"
	covers
}
