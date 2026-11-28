package bellu.cis_k8s.run_as_root_pod
import rego.v1

# Pod runs as root. Unknown or missing values never violate.
violation contains {"evidence": {"run_as_root": input.attributes.run_as_root}} if {
	input.attributes.run_as_root == "true"
}
