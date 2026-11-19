package ident

import (
	"errors"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

func TestDefaultConfidence(t *testing.T) {
	if c, ok := DefaultConfidence("likely_same_as"); !ok || c != "inferred" {
		t.Fatalf("likely_same_as = %q, %v", c, ok)
	}
	if c, ok := DefaultConfidence("runs_on"); !ok || c != "extracted" {
		t.Fatalf("runs_on = %q, %v", c, ok)
	}
	if c, ok := DefaultConfidence("no_such_relation"); ok || c != "extracted" {
		t.Fatalf("unregistered = %q, %v", c, ok)
	}
}

func TestCheckAndRegistryOnDefault(t *testing.T) {
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	if r, err := Registry(); err != nil || r == nil {
		t.Fatalf("Registry() = %v, %v", r, err)
	}
	if err := Use(nil); !errors.Is(err, errs.Validation) {
		t.Fatalf("Use(nil) = %v", err)
	}
	other, err := schema.Merge()
	if err == nil {
		if err := Use(other); !errors.Is(err, schema.ErrImmutable) {
			t.Fatalf("Use after resolve = %v", err)
		}
	}
}

// A failed merge makes every lookup behave as unregistered.
func TestFailedMergeBehavesAsUnregistered(t *testing.T) {
	regMu.Lock()
	saved := [3]any{regSet, reg, regErr}
	reg, regErr, regSet = nil, errors.New("boom one\nboom two"), true
	regMu.Unlock()
	t.Cleanup(func() {
		regMu.Lock()
		regSet, reg, regErr = saved[0].(bool), saved[1].(*schema.Registry), nil
		if e, ok := saved[2].(error); ok {
			regErr = e
		}
		regMu.Unlock()
	})

	if err := Check(); err == nil || err.Error() != "boom one\nboom two" {
		t.Fatalf("Check() = %v", err)
	}
	if _, err := Registry(); err == nil {
		t.Fatal("Registry() must fail")
	}
	if _, err := Hash("host", map[string]string{"hostname": "h"}); !errors.Is(err, errs.Validation) {
		t.Fatalf("Hash err = %v", err)
	}
	if len(Kinds()) != 0 || len(RelationTypes()) != 0 {
		t.Fatal("lists must be empty")
	}
	if _, ok := IdentityAttributes("host"); ok {
		t.Fatal("host must be unregistered")
	}
	if d, def := DirectionOf("found_in"); d != Reverse || !def {
		t.Fatalf("DirectionOf = %v, %v", d, def)
	}
	if c, ok := DefaultConfidence("runs_on"); ok || c != "extracted" {
		t.Fatalf("DefaultConfidence = %q, %v", c, ok)
	}
}
