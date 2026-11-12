package rename

import (
	"strings"
	"testing"
)

func loadRepoMap(t *testing.T) *Map {
	t.Helper()
	m, err := LoadFile("../../script/rename.map.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestValidateRejectsReMatch(t *testing.T) {
	err := Validate([]Rule{
		{Kind: KindIdentifier, From: "toise", To: "xtoisex"},
	})
	if err == nil || !strings.Contains(err.Error(), "rule 1") {
		t.Fatalf("want rule 1 error, got %v", err)
	}
	err = Validate([]Rule{
		{Kind: KindEnv, From: "A_", To: "B_"},
		{Kind: KindEnv, From: "B_", To: "C_"},
	})
	if err == nil {
		t.Fatal("want chained-rule error")
	}
}

func TestShippedMapIsValidAndIdempotent(t *testing.T) {
	m := loadRepoMap(t)
	src := `package toise // import "github.com/toise-dev/toise/internal/store"
const Env = "TOISE_DIR"; var m = "toise_events_total"; var u = "toise://x"; var n = "Toise engine"
type ToiseClient struct{}; proto toise.v1; /usr/bin/toised`
	for _, p := range []string{"internal/store/a.go", "README.md", "Makefile"} {
		once := m.ApplyText(p, []byte(src))
		twice := m.ApplyText(p, once)
		if string(once) != string(twice) {
			t.Fatalf("%s not idempotent:\n%s\n%s", p, once, twice)
		}
		if strings.Contains(strings.ToLower(string(once)), "toise") {
			t.Fatalf("%s leftover:\n%s", p, once)
		}
	}
	out := string(m.ApplyText("a.go", []byte(src)))
	for _, want := range []string{
		"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/store",
		"BELLU_GRAPH_DIR", "bellu_graph_events_total", "bellugraph://x", `"Bellu Graph Engine engine"`,
		"BelluGraphClient", "bellugraph.v1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	p := m.ApplyPath("proto/toise/v1/toise.proto")
	if p != "proto/bellugraph/v1/bellugraph.proto" || m.ApplyPath(p) != p {
		t.Fatalf("path: %s", p)
	}
}
