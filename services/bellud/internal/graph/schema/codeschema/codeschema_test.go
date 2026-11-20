package codeschema

import (
	"errors"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

func TestDeclarationShape(t *testing.T) {
	d := Declaration()
	if len(d.Kinds) != 4 || len(d.Relations) != 9 {
		t.Fatalf("got %d kinds, %d relations", len(d.Kinds), len(d.Relations))
	}
	for _, k := range d.Kinds {
		for _, a := range k.Identity {
			if schema.IsSecretName(a) || a == "data" {
				t.Errorf("%s: attribute %q is a redaction name", k.Name, a)
			}
		}
	}
	for _, r := range d.Relations {
		if (r.Name == RelReachableFrom || r.Name == RelSupersedes) != (r.Direction == schema.Forward) {
			t.Errorf("%s: unexpected direction %s", r.Name, r.Direction)
		}
	}
}

func TestSetConflictAndDirection(t *testing.T) {
	s := NewSet()
	k := kinds()[0]
	if err := s.RegisterKind(k); err != nil {
		t.Fatalf("identical re-registration: %v", err)
	}
	k.Identity = []string{"id"}
	if err := s.RegisterKind(k); !errors.Is(err, ErrNameConflict) {
		t.Fatalf("want ErrNameConflict, got %v", err)
	}
	if got := s.kinds[KindSymbol].Identity; len(got) != 3 {
		t.Fatalf("existing registration changed: %v", got)
	}
	r := relations()[0]
	r.Direction = schema.Forward
	if err := s.RegisterRelation(r); !errors.Is(err, ErrNameConflict) {
		t.Fatalf("want ErrNameConflict, got %v", err)
	}
	if err := s.CheckRelation(RelDefinedIn, KindSymbol, KindFile); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckRelation(RelDefinedIn, KindFile, KindSymbol); !errors.Is(err, ErrDirectionMismatch) {
		t.Fatalf("want ErrDirectionMismatch, got %v", err)
	}
}
