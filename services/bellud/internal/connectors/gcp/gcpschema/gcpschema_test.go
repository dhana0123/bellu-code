package gcpschema

import (
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

func TestDeclarationMerges(t *testing.T) {
	d := Declaration()
	if _, err := schema.Merge(d); err != nil {
		t.Fatalf("merge: %v", err)
	}
	for _, k := range d.Kinds {
		if k.Overview == "" {
			t.Errorf("%s has no Overview", k.Name)
		}
	}
	for _, r := range d.Relations {
		for _, a := range []string{"evidence", "confidence", "observed_at"} {
			if !strings.Contains(r.Description, a) {
				t.Errorf("%s does not document %s", r.Name, a)
			}
		}
	}
}
