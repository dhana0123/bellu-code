package agentcfg

import (
	"encoding/json"
	"errors"
	"testing"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBuildFresh(t *testing.T) {
	out, set, err := Build("", false, true, "http://127.0.0.1:1/x", "tok")
	if err != nil || !set {
		t.Fatal(err, set)
	}
	e := decode(t, out)["mcp"].(map[string]any)[ServerName].(map[string]any)
	if e["type"] != "remote" || e["url"] != "http://127.0.0.1:1/x" || e["oauth"] != false {
		t.Fatalf("%v", e)
	}
	if e["headers"].(map[string]any)["Authorization"] != "Bearer tok" {
		t.Fatalf("%v", e)
	}
}

func TestBuildMergePreserves(t *testing.T) {
	in := `{"theme":"x","mcp":{"other":{"type":"local","command":["a"]},"bellu-graph":{"type":"remote","url":"old"}}}`
	out, _, err := Build(in, true, true, "u", "t")
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	if m["theme"] != "x" {
		t.Fatal("lost key")
	}
	mcp := m["mcp"].(map[string]any)
	if _, ok := mcp["other"]; !ok {
		t.Fatal("lost mcp entry")
	}
	if mcp[ServerName].(map[string]any)["url"] != "u" {
		t.Fatal("not replaced")
	}
}

func TestBuildInvalid(t *testing.T) {
	for _, in := range []string{"", "nope", "[]", "null", "1", `{"mcp":[]}`, `{"a":1} x`} {
		if _, _, err := Build(in, true, true, "u", "t"); !errors.Is(err, ErrInvalidInbound) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestBuildDisabledPassthrough(t *testing.T) {
	out, set, err := Build("garbage", true, false, "u", "t")
	if err != nil || !set || out != "garbage" {
		t.Fatal(out, set, err)
	}
	if _, set, _ := Build("", false, false, "u", "t"); set {
		t.Fatal("should not set")
	}
}

func TestMCPURL(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0": "http://127.0.0.1:4096" + MCPPath,
		"::":      "http://127.0.0.1:4096" + MCPPath,
		"::1":     "http://[::1]:4096" + MCPPath,
		"h":       "http://h:4096" + MCPPath,
	} {
		if got := MCPURL(in, 4096); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}
