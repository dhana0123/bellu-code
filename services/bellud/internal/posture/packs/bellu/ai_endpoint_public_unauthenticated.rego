package bellu.bellu.ai_endpoint_public_unauthenticated

import rego.v1

# A model or agent endpoint reachable from the internet without sign-in.
# Attributes on ai_service / ai_agent / ai_model:
#   public_access  = "enabled"           the endpoint is internet reachable
#   authentication = "none" | "disabled" no sign-in is required
violation contains {"evidence": {"rule": input.id, "authentication": input.attributes.authentication}} if {
	input.attributes.public_access == "enabled"
	input.attributes.authentication in {"none", "disabled"}
}
