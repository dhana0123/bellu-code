# IaC fixtures

Each fixture has a sibling `.expected.json` listing the Trivy AVD check IDs it should trigger
(IDs verified against trivy-checks rego metadata).

| Fixture | Format | Misconfiguration |
|---|---|---|
| terraform.tf | Terraform | public-read S3 ACL, no encryption |
| cloudformation.yaml | CloudFormation | S3 bucket without access logging (AVD-AWS-0088 encryption check is deprecated in trivy-checks) |
| kubernetes.yaml | Kubernetes | privileged container, runs as root |
| helm/ | Helm | privileged pod template (expected: helm.expected.json) |
| Dockerfile | Dockerfile | `USER root`, no HEALTHCHECK |
| azure-arm.json | Azure ARM | storage account allows HTTP |
