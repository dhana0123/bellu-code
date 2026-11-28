package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIaCFixturesExist(t *testing.T) {
	files := map[string]string{
		"terraform.tf":            "terraform.tf.expected.json",
		"cloudformation.yaml":     "cloudformation.yaml.expected.json",
		"kubernetes.yaml":         "kubernetes.yaml.expected.json",
		"helm/Chart.yaml":         "helm.expected.json",
		"helm/templates/pod.yaml": "helm.expected.json",
		"Dockerfile":              "Dockerfile.expected.json",
		"azure-arm.json":          "azure-arm.json.expected.json",
	}
	for fx, exp := range files {
		dir := filepath.Join("testdata", "iac")
		if _, err := os.Stat(filepath.Join(dir, fx)); err != nil {
			t.Errorf("fixture %s: %v", fx, err)
		}
		b, err := os.ReadFile(filepath.Join(dir, exp))
		if err != nil {
			t.Errorf("expected %s: %v", exp, err)
			continue
		}
		var v struct {
			CheckIDs []string `json:"check_ids"`
		}
		if err := json.Unmarshal(b, &v); err != nil || len(v.CheckIDs) == 0 {
			t.Errorf("expected %s invalid: %v", exp, err)
		}
	}
}
