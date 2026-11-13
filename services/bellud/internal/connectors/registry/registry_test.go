package registry

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

func mf(id string, builtin bool) manifest.Manifest {
	return manifest.Manifest{
		ID: id, Version: "1.0.0", Name: id, Icon: id,
		AuthMethods: []manifest.AuthMethod{{ID: "token", Name: "Token", Enabled: true}},
		Permissions: []manifest.Permission{{Name: "read", ReadOnly: true}},
		Operations:  []manifest.Operation{{Name: "GET /x", Class: manifest.ClassRead, Method: "GET", Host: "api.example.com", Path: "/x"}},
		Egress:      []string{"api.example.com"},
		Entities:    []string{"thing"},
		Builtin:     builtin,
	}
}

func TestRegisterAndGet(t *testing.T) {
	r := New()
	if err := r.Register(mf("b", true)); err != nil {
		t.Fatal(err)
	}
	e, ok := r.Get("b")
	if !ok || e.Plugin || e.Manifest.ID != "b" {
		t.Fatalf("got %+v %v", e, ok)
	}
	if _, ok := r.Get("zz"); ok {
		t.Fatal("unexpected entry")
	}
}

func TestDuplicateID(t *testing.T) {
	r := New()
	if err := r.Register(mf("a", true)); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(mf("a", false)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("got %v", err)
	}
	if e, _ := r.Get("a"); e.Plugin {
		t.Fatal("original entry replaced")
	}
}

func TestInvalidManifest(t *testing.T) {
	r := New()
	m := mf("Bad ID", false)
	err := r.Register(m)
	var ie *InvalidError
	if !errors.Is(err, ErrInvalid) || !errors.As(err, &ie) || len(ie.Fields) == 0 {
		t.Fatalf("got %v", err)
	}
	if len(r.List()) != 0 {
		t.Fatal("invalid manifest registered")
	}
}

func TestSameShapeBuiltinAndPlugin(t *testing.T) {
	r := New()
	if err := r.Register(mf("a", true)); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(mf("p", false)); err != nil {
		t.Fatal(err)
	}
	l := r.List()
	if len(l) != 2 || l[0].Manifest.ID != "a" || l[1].Manifest.ID != "p" {
		t.Fatalf("list %+v", l)
	}
	if l[0].Plugin || !l[1].Plugin {
		t.Fatal("plugin flag wrong")
	}
	if reflect.TypeOf(l[0]) != reflect.TypeOf(l[1]) {
		t.Fatal("shape differs")
	}
	// Mutating a returned copy must not affect the registry.
	l[0].Manifest.Egress[0] = "evil.example.com"
	if e, _ := r.Get("a"); e.Manifest.Egress[0] != "api.example.com" {
		t.Fatal("registry state mutated")
	}
}
