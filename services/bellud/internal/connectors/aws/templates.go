package aws

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ExternalIDPrefix prefixes every generated AssumeRole external ID.
const ExternalIDPrefix = "BELLU-"

const externalIDRandomBytes = 32

var (
	roleNameRe   = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	principalRe  = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:(root|role/[A-Za-z0-9+=,.@_/-]+|user/[A-Za-z0-9+=,.@_/-]+)$`)
	externalIDRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/_-]{2,1000}$`)
)

// GenerateExternalID returns a fresh external ID: BELLU- followed by the
// unpadded base32 encoding of 32 bytes from crypto/rand (58 characters).
func GenerateExternalID() (string, error) {
	b := make([]byte, externalIDRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate external id: %w", err)
	}
	return ExternalIDPrefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TrustParams are the inputs for the role trust templates.
type TrustParams struct {
	RoleName   string // name of the role to create
	Principal  string // ARN trusted to assume the role (Bellu's principal)
	ExternalID string // sts:ExternalId condition value
}

// Validate rejects values that could break out of the generated templates.
func (p TrustParams) Validate() error {
	switch {
	case !roleNameRe.MatchString(p.RoleName):
		return errors.New("invalid role name")
	case !principalRe.MatchString(p.Principal):
		return errors.New("invalid trust principal ARN")
	case !externalIDRe.MatchString(p.ExternalID):
		return errors.New("invalid external id")
	}
	return nil
}

// CloudFormationTemplate renders a CloudFormation YAML template creating a
// read-only role trusted by the principal with the external ID condition.
func CloudFormationTemplate(p TrustParams) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	r := strings.NewReplacer(
		"{{ROLE}}", p.RoleName,
		"{{PRINCIPAL}}", p.Principal,
		"{{EXTERNAL_ID}}", p.ExternalID,
	)
	return r.Replace(cfnTemplate), nil
}

// TerraformSnippet renders the equivalent Terraform (HCL) configuration.
func TerraformSnippet(p TrustParams) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	r := strings.NewReplacer(
		"{{ROLE}}", p.RoleName,
		"{{PRINCIPAL}}", p.Principal,
		"{{EXTERNAL_ID}}", p.ExternalID,
	)
	return r.Replace(tfTemplate), nil
}

const cfnTemplate = `AWSTemplateFormatVersion: "2010-09-09"
Description: Read-only role for Bellu cloud connector
Resources:
  BelluRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: "{{ROLE}}"
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: "{{PRINCIPAL}}"
            Action: "sts:AssumeRole"
            Condition:
              StringEquals:
                "sts:ExternalId": "{{EXTERNAL_ID}}"
      # ReadOnlyAccess and SecurityAudit grant read-only access. For least
      # privilege, replace them with a custom policy limited to the
      # operations Bellu uses (ec2/s3/iam/lambda/rds read and list calls).
      ManagedPolicyArns:
        - "arn:aws:iam::aws:policy/ReadOnlyAccess"
        - "arn:aws:iam::aws:policy/SecurityAudit"
      Policies:
        - PolicyName: BelluSimulateSelf
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: "iam:SimulatePrincipalPolicy"
                Resource: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/{{ROLE}}"
Outputs:
  RoleArn:
    Value: !GetAtt BelluRole.Arn
`

const tfTemplate = `data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_iam_role" "bellu" {
  name                 = "{{ROLE}}"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "{{PRINCIPAL}}" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "sts:ExternalId" = "{{EXTERNAL_ID}}" }
      }
    }]
  })
}

# ReadOnlyAccess and SecurityAudit grant read-only access. For least
# privilege, replace them with a custom policy limited to the operations
# Bellu uses (ec2/s3/iam/lambda/rds read and list calls).
resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.bellu.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.bellu.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy" "simulate_self" {
  name = "BelluSimulateSelf"
  role = aws_iam_role.bellu.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:SimulatePrincipalPolicy"
      Resource = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/{{ROLE}}"
    }]
  })
}
`
