package schemaall

import (
	"slices"
	"testing"
)

func TestDefaultMergesAndKeepsIdentityOrder(t *testing.T) {
	r, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if r2, _ := Default(); r2 != r {
		t.Fatal("Default must return the same registry")
	}
	k, ok := r.Kind("github_alert")
	if !ok || !slices.Equal(k.Identity, []string{"connection", "repo", "alert_type", "number"}) {
		t.Fatalf("github_alert = %+v, %v", k, ok)
	}
	if len(r.Kinds()) != 53 || len(r.Relations()) != 110 {
		t.Fatalf("got %d kinds, %d relations", len(r.Kinds()), len(r.Relations()))
	}
}
