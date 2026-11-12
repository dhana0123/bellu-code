package graph

import "testing"

func TestBuildDefault(t *testing.T) {
	env := func(string) string { return "" }
	c, err := LoadConfigFrom(env)
	if err != nil || !c.Enabled {
		t.Fatalf("dev default should be on: %v %v", c.Enabled, err)
	}
	release = "true"
	defer func() { release = "" }()
	c, _ = LoadConfigFrom(env)
	if c.Enabled {
		t.Fatal("release default should be off")
	}
	c, _ = LoadConfigFrom(func(k string) string {
		if k == "BELLU_GRAPH_ENABLED" {
			return "true"
		}
		return ""
	})
	if !c.Enabled {
		t.Fatal("explicit value must win in release")
	}
}
