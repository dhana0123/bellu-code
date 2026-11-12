package redact

import "regexp"

// ValueRule detects secret material inside string values. Rule ids are stable.
type ValueRule struct {
	ID string
	Re *regexp.Regexp
}

// ValueRules is hand-written; order decides which rule id wins.
var ValueRules = []ValueRule{
	{ID: "value_aws_access_key", Re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{ID: "value_private_key_header", Re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)},
	{ID: "value_github_token", Re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`)},
	{ID: "value_bearer_token", Re: regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}`)},
	{ID: "value_slack_token", Re: regexp.MustCompile(`\bxox[abprs]-[0-9A-Za-z-]{10,}`)},
	{ID: "value_google_api_key", Re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
}
