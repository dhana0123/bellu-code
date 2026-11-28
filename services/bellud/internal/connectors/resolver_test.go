package connectors

import (
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

func TestResolverIDAliasAndAmbiguity(t *testing.T) {
	s := newSvc(t, t.TempDir(), &memSource{slots: map[string][]byte{}}, testEngine(t), ghTransport{})
	add := func(id, connector, alias string) {
		t.Helper()
		err := s.store.Update(func(st *store.State) error {
			st.Connections = append(st.Connections, store.Connection{
				ID: id, ConnectorID: connector, Alias: alias, Status: "ACTIVE", IntervalSec: 900, RotationIntervalDays: 90, CreatedAt: time.Now(),
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	add("c1", "github", "prod")
	add("c2", "github", "dev")
	add("c3", "aws", "dev")
	r := NewResolver(s)
	if got, ok := r.ResolveConnection("c1"); !ok || got.ID != "c1" {
		t.Fatalf("id: %v %v", got.ID, ok)
	}
	if got, ok := r.ResolveConnection("PROD"); !ok || got.ID != "c1" {
		t.Fatalf("alias: %v %v", got.ID, ok)
	}
	if _, ok := r.ResolveConnection("dev"); ok {
		t.Fatal("ambiguous alias must not resolve")
	}
	if _, ok := r.ResolveConnection("nope"); ok {
		t.Fatal("unknown must not resolve")
	}
	if _, ok := NewResolver(&Service{}).ResolveConnection("c1"); ok {
		t.Fatal("disabled must not resolve")
	}
}
