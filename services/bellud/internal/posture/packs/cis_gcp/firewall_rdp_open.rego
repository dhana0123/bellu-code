package bellu.cis_gcp.firewall_rdp_open
import rego.v1

# Firewall allows 0.0.0.0/0 to RDP (3389). Unknown or missing values never violate.
covers if not input.attributes.from_port
covers if {
	input.attributes.from_port <= 3389
	input.attributes.to_port >= 3389
}
violation contains {"evidence": {"rule": input.id, "port": "3389"}} if {
	input.attributes.direction == "ingress"
	input.attributes.internet_open == "true"
	covers
}
