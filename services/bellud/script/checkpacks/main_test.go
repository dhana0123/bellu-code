package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/bellu/bellucode/services/bellud/internal/posture"
)

func TestBundledPacksPass(t *testing.T) {
	f, _, _, err := run(posture.Bundled())
	if err != nil || len(f) != 0 {
		t.Fatalf("bundled packs: %v %v", f, err)
	}
}

func TestReportsBadRule(t *testing.T) {
	fsys := fstest.MapFS{"p/pack.json": {Data: []byte(`{"id":"p","version":"1","rules":[{"id":"r","severity":"urgent"}]}`)}}
	f, _, _, _ := run(fsys)
	if len(f) == 0 || !strings.HasPrefix(f[0], "p/r: ") {
		t.Fatalf("failures = %v", f)
	}
}

// TestCLIFailsOnBadRule runs the command against a temp pack dir and checks the
// exit code and that the output names the rule id and the failed checks.
func TestCLIFailsOnBadRule(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "p"), 0o755); err != nil {
		t.Fatal(err)
	}
	pack := `{"id":"p","version":"1","rules":[{"id":"r","severity":"urgent"}]}`
	if err := os.WriteFile(filepath.Join(dir, "p", "pack.json"), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", ".", dir).CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want non-zero exit, got err=%v\n%s", err, out)
	}
	for _, want := range []string{"p/r: schema: severity", "p/r: compile:"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
