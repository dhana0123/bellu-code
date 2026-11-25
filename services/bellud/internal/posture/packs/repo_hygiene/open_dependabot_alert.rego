package bellu.repo_hygiene.open_dependabot_alert

import rego.v1

violation contains {"evidence": {"repo": object.get(input.attributes, "repo", "")}} if {
	input.attributes.alert_type == "dependabot"
	input.attributes.state == "open"
}
