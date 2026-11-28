package bellu.repo_hygiene.open_secret_scanning_alert

import rego.v1

violation contains {"evidence": {"repo": object.get(input.attributes, "repo", "")}} if {
	input.attributes.alert_type == "secret_scanning"
	input.attributes.state == "open"
}
