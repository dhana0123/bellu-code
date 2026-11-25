package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretsCorpusManifest(t *testing.T) {
	dir := filepath.Join("testdata", "secrets")
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string][]struct {
		Rule string `json:"rule"`
		Line int    `json:"line"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	clean := 0
	for f, hits := range m {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing corpus file %s: %v", f, err)
		}
		if len(hits) == 0 {
			clean++
		}
	}
	if clean < 10 {
		t.Errorf("want >=10 clean files, got %d", clean)
	}
}
