package bellu.bellu.toxic_k8s_privileged_admin

import rego.v1

# Toxic combination (e): a Kubernetes pod with a privileged container whose
# service account is bound to cluster-admin.
#
# NOT ACTIVE YET: the k8s kinds arrive with Phase 7 (k8sschema). Until pods are
# in the graph, no entity of type k8s_pod is evaluated, so this rule compiles
# and never matches. Kind and relation names follow the design (k8s_pod,
# k8s_serviceaccount, k8s_binding, k8s_runs_as_sa, k8s_bound_to). PLACEHOLDERS
# for attributes the collector will define: pod `privileged` ("true") and
# binding `role_ref` ("cluster-admin"). Bindings are read in either direction.
#
# Path: pod -k8s_runs_as_sa-> service account -k8s_bound_to- binding.

targets(id, rel) := {e.to | some e in bellu.neighbors(id, rel); e.from == id}

adjacent(id, rel) := {x | some e in bellu.neighbors(id, rel); some x in [e.from, e.to]; x != id}

violation contains {
	"discriminator": binding,
	"evidence": {"service_account": sa, "binding": binding},
	"path": [
		{"entity": input.id, "relation": ""},
		{"entity": sa, "relation": "k8s_runs_as_sa"},
		{"entity": binding, "relation": "k8s_bound_to"},
	],
} if {
	input.attributes.privileged == "true"
	some sa in targets(input.id, "k8s_runs_as_sa")
	some binding in adjacent(sa, "k8s_bound_to")
	b := bellu.entity(binding)
	b.type == "k8s_binding"
	b.attributes.role_ref == "cluster-admin"
}
