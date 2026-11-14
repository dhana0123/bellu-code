package aws

import (
	"net/url"
	"strings"
)

// AWSTemplateURL is the https S3 URL of the hosted parameterized template
// (docs/connectors/aws/bellu-code-role.yaml). Empty disables quick-create.
const AWSTemplateURL = ""

// Environment overrides.
const (
	EnvTemplateURL = "BELLUCODE_AWS_TEMPLATE_URL"
	EnvRegion      = "BELLUCODE_AWS_REGION"
	envAWSRegion   = "AWS_REGION"
	defaultRegion  = "us-east-1"
	// QuickCreateStackName is the stack name prefilled in the console.
	QuickCreateStackName = "BelluCodeReadOnly"
)

// EffectiveTemplateURL returns the environment override when it is an https
// URL on an amazonaws.com host, else the compiled AWSTemplateURL (validated
// the same way). Empty means quick-create is unavailable.
func EffectiveTemplateURL(getenv func(string) string) string {
	if v := strings.TrimSpace(getenv(EnvTemplateURL)); validTemplateURL(v) {
		return v
	}
	if validTemplateURL(AWSTemplateURL) {
		return AWSTemplateURL
	}
	return ""
}

func validTemplateURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "amazonaws.com" || strings.HasSuffix(h, ".amazonaws.com")
}

// EffectiveRegion returns BELLUCODE_AWS_REGION, else AWS_REGION, else us-east-1.
func EffectiveRegion(getenv func(string) string) string {
	for _, k := range []string{EnvRegion, envAWSRegion} {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
	}
	return defaultRegion
}

// QuickCreateURL builds the CloudFormation console quick-create link. It
// returns "" when templateURL is empty.
func QuickCreateURL(region, templateURL, principal, externalID string) string {
	if templateURL == "" {
		return ""
	}
	q := "templateURL=" + url.QueryEscape(templateURL) +
		"&stackName=" + url.QueryEscape(QuickCreateStackName) +
		"&param_TrustedPrincipalArn=" + url.QueryEscape(principal) +
		"&param_ExternalId=" + url.QueryEscape(externalID)
	return "https://console.aws.amazon.com/cloudformation/home?region=" + url.QueryEscape(region) +
		"#/stacks/quickcreate?" + q
}
