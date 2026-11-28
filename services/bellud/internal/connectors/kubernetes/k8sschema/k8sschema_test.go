package k8sschema

import (
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/coreschema"
)

func TestDeclarationValid(t *testing.T) {
	d := Declaration()
	if _, err := schema.Merge(coreschema.Declaration(), d); err != nil {
		t.Fatal(err)
	}
	for _, k := range d.Kinds {
		if k.Overview == "" {
			t.Errorf("%s: no Overview", k.Name)
		}
		for _, a := range k.Identity {
			if schema.IsSecretName(a) {
				t.Errorf("%s: secret-like attribute %s", k.Name, a)
			}
		}
	}
	if len(d.Kinds) != 13 {
		t.Fatalf("kinds = %d, want 13", len(d.Kinds))
	}
	for _, r := range d.Relations {
		if r.Direction != schema.Forward && r.Direction != schema.Reverse {
			t.Errorf("%s: bad direction", r.Name)
		}
	}
}
