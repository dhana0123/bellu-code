# Connect AWS to Bellu Code

Bellu Code reads your AWS account with a read-only IAM role. You create the role once, then paste its ARN.

## What the role grants

The role has two AWS managed policies: `ReadOnlyAccess` and `SecurityAudit`. Together they give read-only access to all AWS services, including EKS cluster metadata. They cannot change anything.

Kubernetes objects inside a cluster (pods, deployments) are not covered. To read them, optionally add an EKS access entry for the role with the `AmazonEKSViewPolicy` access policy.

## Option 1: CloudFormation

1. In Bellu Code, choose AWS, then IAM role, then Continue. Open the CloudFormation tab and click Copy.
2. Save the text as a `.yaml` file. In the AWS console, open CloudFormation and choose Create stack, then Upload a template file.
3. Acknowledge that the stack creates IAM resources, then choose Create.
4. When the stack is complete, copy the `RoleArn` value from its Outputs tab.
5. Paste it into the Role ARN field in Bellu Code.

## Option 2: Terraform

1. In Bellu Code, open the Terraform tab and click Copy.
2. Save it as `main.tf`, then run `terraform init` and `terraform apply`.
3. Copy the `role_arn` output and paste it into the Role ARN field.

If you create the role by hand, use the External ID shown in Bellu Code in the role's trust policy.

## Option 3: Access keys

Choose Access keys to paste the keys of a read-only IAM user (attach the same two policies). Keys are long-lived, so prefer the role. Bellu Code can remind you to rotate them after 90 days.

## Troubleshooting

**Bellu Code needs an AWS identity to assume the role: attach an IAM role with sts:AssumeRole to the machine running Bellu Code, or use access keys.**

## For operators: Launch stack button

`bellu-code-role.yaml` is a copy of `aws.CloudFormationTemplateParameterized()` in `services/bellud/internal/connectors/aws/templates.go`. Keep the two in sync. To show the "Launch stack in AWS" button, upload the file to S3 and set `BELLUCODE_AWS_TEMPLATE_URL` to its https URL (host must end in `amazonaws.com`). `BELLUCODE_AWS_REGION` sets the console region (default `us-east-1`).
