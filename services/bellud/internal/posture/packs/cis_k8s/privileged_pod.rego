package bellu.cis_k8s.privileged_pod
import rego.v1

# Pod runs a privileged container. Unknown or missing values never violate.
violation contains {"evidence": {"privileged": input.attributes.privileged}} if {
	input.attributes.privileged == "true"
}
