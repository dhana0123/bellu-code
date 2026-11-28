package bellu.repo_hygiene.repo_public

import rego.v1

violation contains {"evidence": {"visibility": "public"}} if input.attributes.visibility == "public"
