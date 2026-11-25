package bellu.bellu.toxic_ai_agent_write_external

import rego.v1

# Toxic combination (f): an AI agent with a write tool and an external input
# source that is not validated.
#
# NOT ACTIVE YET: the AI kinds arrive with Phase 9 (aischema). Until agents are
# in the graph, no ai_agent entity is evaluated, so this rule compiles and
# never matches. Names follow the design (ai_agent, ai_tool, ai_has_tool,
# ai_reads_input_from). PLACEHOLDERS for attributes the AI scanner will define:
# tool `can_write` ("true"), input source `external` ("true") and `validated`
# ("true" when input is validated).
#
# Path: agent -ai_has_tool-> tool, and agent -ai_reads_input_from-> source.

targets(id, rel) := {e.to | some e in bellu.neighbors(id, rel); e.from == id}

violation contains {
	"discriminator": concat("|", [tool, src]),
	"evidence": {"tool": tool, "input_source": src},
	"path": [
		{"entity": input.id, "relation": ""},
		{"entity": tool, "relation": "ai_has_tool"},
		{"entity": input.id, "relation": ""},
		{"entity": src, "relation": "ai_reads_input_from"},
	],
} if {
	some tool in targets(input.id, "ai_has_tool")
	bellu.entity(tool).attributes.can_write == "true"
	some src in targets(input.id, "ai_reads_input_from")
	s := bellu.entity(src)
	s.attributes.external == "true"
	not s.attributes.validated == "true"
}
