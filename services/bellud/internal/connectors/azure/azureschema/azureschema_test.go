package azureschema

import (
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

func TestDeclarationMerges(t *testing.T) {
	d := Declaration()
	if _, err := schema.Merge(d); err != nil {
		t.Fatal(err)
	}
	if len(d.Kinds) != 3 {
		t.Fatalf("got %d kinds", len(d.Kinds))
	}
	for _, k := range d.Kinds {
		if k.Overview == "" {
			t.Errorf("%s has no Overview", k.Name)
		}
	}
	if d.Kinds[1].Discriminator != "azure_type" {
		t.Error("azure_resource discriminator must be azure_type")
	}
	for _, r := range d.Relations {
		if !strings.Contains(r.Description, "evidence, confidence, observed_at") {
			t.Errorf("%s lacks edge attributes", r.Name)
		}
	}
}
