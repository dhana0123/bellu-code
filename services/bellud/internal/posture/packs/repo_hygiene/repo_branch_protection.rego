package bellu.repo_hygiene.repo_branch_protection

import rego.v1

violation contains {"evidence": {"default_branch": input.attributes.default_branch}} if input.attributes.default_branch_protected == false
