package bellu.bellu.ai_agent_write_tool_external_input

import rego.v1

# An AI agent that holds a write-capable tool and reads external input that is
# not validated. Attribute names (set by the aiinv scanner on ai_agent):
#   has_write_tool = "true"   the agent has at least one tool that can write
#   external_input = "true"   the agent reads input from an external source
#   input_validated = "true"  the external input is validated (suppresses)
# The graph-path variant is toxic_ai_agent_write_external.
violation contains {"evidence": {"rule": input.id}} if {
	input.attributes.has_write_tool == "true"
	input.attributes.external_input == "true"
	not input.attributes.input_validated == "true"
}
