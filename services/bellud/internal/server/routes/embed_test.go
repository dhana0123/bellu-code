package routes

import (
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite routes.yaml from testdata/operations.json")

func loadOperations(t *testing.T) []OperationInfo {
	t.Helper()
	data, err := os.ReadFile("testdata/operations.json")
	if err != nil {
		t.Fatal(err)
	}
	var infos []OperationInfo
	if err := json.Unmarshal(data, &infos); err != nil {
		t.Fatal(err)
	}
	return infos
}

// TestGenerate rewrites routes.yaml with -update; otherwise it is a no-op.
func TestGenerate(t *testing.T) {
	if !*update {
		t.Skip("pass -update to regenerate routes.yaml")
	}
	if err := os.WriteFile("routes.yaml", MarshalRoutes(GenerateRoutes(loadOperations(t))), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedCoversEveryOperation(t *testing.T) {
	infos := loadOperations(t)
	table := MustLoadEmbedded()
	if err := Validate(table.Routes(), Operations(infos)); err != nil {
		t.Fatal(err)
	}
	for _, o := range infos {
		r, ok := table.Lookup(o.Method, examplePath(o.Path))
		if !ok || r.Pattern != o.Path || r.Stream != o.Stream {
			t.Errorf("%s %s resolved to %+v (ok=%v), want exact pattern and stream=%v", o.Method, o.Path, r, ok, o.Stream)
		}
		if r.Owner != OwnerTS && r.Owner != OwnerGo {
			t.Errorf("%s %s has owner %q", o.Method, o.Path, r.Owner)
		}
	}
}

func TestEmbeddedShellRoutes(t *testing.T) {
	table := MustLoadEmbedded()
	cases := []struct {
		method, path string
		public       bool
	}{
		{"GET", "/", true},
		{"GET", "/session/abc", true},
		{"GET", "/_assets/x.js", true},
		{"GET", "/auth/connect/abc", true},
		{"GET", "/openapi.json", true},
		{"GET", "/api/info", false},
		{"POST", "/api/unlisted/thing", false},
		{"GET", "/api", false},
	}
	for _, c := range cases {
		r, ok := table.Lookup(c.method, c.path)
		if !ok || r.Public != c.public {
			t.Errorf("%s %s: got %+v ok=%v, want public=%v", c.method, c.path, r, ok, c.public)
		}
	}
}
