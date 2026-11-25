package bellu.bellu.toxic_exposed_vuln

import rego.v1

# Toxic combination (a): an internet-exposed workload that runs an image with a
# package affected by a vulnerability that is KEV-listed or has EPSS >= 0.5.
#
# Path (each hop names the relation used to arrive at its entity; "" for the
# start): workload -aws_uses_image-> image <-contained_in- package
# -affected_by-> vulnerability.
#
# Edges are read as stored (from -> to). Only the graph's edges are walked; the
# issue builder drops paths that use inferred relations.

targets(id, rel) := {e.to | some e in bellu.neighbors(id, rel); e.from == id}

sources(id, rel) := {e.from | some e in bellu.neighbors(id, rel); e.to == id}

flag(v) if v == true

flag(v) if v == "true"

hot(attrs) if flag(attrs.kev)

hot(attrs) if {
	is_number(attrs.epss)
	attrs.epss >= 0.5
}

violation contains {
	"discriminator": vuln,
	"evidence": {"vulnerability": vuln, "kev": sprintf("%v", [object.get(v.attributes, "kev", false)]), "epss": sprintf("%v", [object.get(v.attributes, "epss", 0)])},
	"path": [
		{"entity": input.id, "relation": ""},
		{"entity": img, "relation": "aws_uses_image"},
		{"entity": pkg, "relation": "contained_in"},
		{"entity": vuln, "relation": "affected_by"},
	],
} if {
	input.attributes.internet_exposed == "true"
	some img in targets(input.id, "aws_uses_image")
	some pkg in sources(img, "contained_in")
	some vuln in targets(pkg, "affected_by")
	v := bellu.entity(vuln)
	hot(v.attributes)
}
