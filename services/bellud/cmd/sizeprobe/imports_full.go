//go:build sizeprobe && !sizebase

package main

import (
	"github.com/anchore/grype/grype"
	"github.com/anchore/syft/syft"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	opa "github.com/open-policy-agent/opa/v1/rego"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// imports references real entry points so the linker keeps the reachable
// cataloging, matching, detection and evaluation code, not just package init.
func imports() int {
	fns := []any{
		syft.CreateSBOM,
		grype.LoadVulnerabilityDB,
		rego.LoadAndRegister, // links the embedded trivy-checks Rego bundle
		terraform.New,
		cloudformation.New,
		dockerfile.NewScanner,
		helm.New,
		kubernetes.NewScanner,
		arm.New,
		detect.NewDetector,
		opa.New,
	}
	return len(fns) + osvCount()
}
