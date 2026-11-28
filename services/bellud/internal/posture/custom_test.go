package posture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePack(t *testing.T, root, name, id string, rules []map[string]any, rego map[string]string) {
	t.Helper()
	d := filepath.Join(root, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"id": id, "version": "1", "rules": rules})
	os.WriteFile(filepath.Join(d, "pack.json"), b, 0o644)
	for f, s := range rego {
		os.WriteFile(filepath.Join(d, f), []byte(s), 0o644)
	}
}

func customRule(id string) map[string]any {
	r := okRule()
	r["id"] = id
	r["rego"] = id + ".rego"
	return r
}

const publicRego = hdr + `violation contains {"discriminator": "d", "evidence": {"id": input.id}} if input.attributes.public`

func TestCustomValidPackFires(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "mine", "mine", []map[string]any{customRule("a")}, map[string]string{"a.rego": publicRego})
	packs, errs, err := LoadCustom(root)
	if err != nil || len(errs) != 0 || len(packs) != 1 {
		t.Fatalf("%v %v %v", packs, errs, err)
	}
	e, rerrs := NewEngine(t.Context(), packs, fakeReader{})
	m, _ := eval(e)
	if len(rerrs) != 0 || len(m) != 1 {
		t.Fatalf("%v %v", m, rerrs)
	}
}

func TestCustomBadSchemaNamesFile(t *testing.T) {
	root := t.TempDir()
	bad := customRule("a")
	bad["title"] = ""
	writePack(t, root, "mine", "mine", []map[string]any{bad}, map[string]string{"a.rego": publicRego})
	packs, errs, _ := LoadCustom(root)
	if len(packs[0].Rules) != 0 || len(errs) != 1 ||
		!strings.Contains(errs[0].Detail, filepath.Join(root, "mine", "pack.json")) || !strings.Contains(errs[0].Detail, "title:") {
		t.Fatalf("%v %v", packs, errs)
	}
}

func TestCustomBadRegoRejectedOthersLoad(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "mine", "mine", []map[string]any{customRule("a"), customRule("b")},
		map[string]string{"a.rego": publicRego, "b.rego": hdr + `violation contains {} if http.send({})`})
	packs, errs, _ := LoadCustom(root)
	if len(packs) != 1 || len(packs[0].Rules) != 1 || packs[0].Rules[0].ID != "a" ||
		len(errs) != 1 || errs[0].RuleID != "b" || errs[0].Check != "compile" || !strings.Contains(errs[0].Detail, "b.rego") {
		t.Fatalf("%v %v", packs, errs)
	}
}

func TestCustomMissingDir(t *testing.T) {
	if _, _, err := LoadCustom(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing dir accepted")
	}
	if b, _, err := LoadAll(Bundled()); err != nil || len(b) == 0 {
		t.Fatal("bundled packs must still load")
	}
}

func TestCustomIDCollisionRejected(t *testing.T) {
	bundled, _, _ := LoadAll(Bundled())
	root := t.TempDir()
	writePack(t, root, "other", bundled[0].ID, []map[string]any{customRule("a")}, map[string]string{"a.rego": publicRego})
	packs, errs, _ := LoadCustom(root)
	if len(packs) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Detail, "already in use") {
		t.Fatalf("%v %v", packs, errs)
	}
}
