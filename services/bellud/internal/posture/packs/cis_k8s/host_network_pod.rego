package bellu.cis_k8s.host_network_pod
import rego.v1

# Pod uses the host network. Unknown or missing values never violate.
violation contains {"evidence": {"host_network": input.attributes.host_network}} if {
	input.attributes.host_network == "true"
}
