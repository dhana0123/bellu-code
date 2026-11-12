package facade

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfigErrorsNameVariable(t *testing.T) {
	for k, v := range map[string]string{
		EnvEnabled: "maybe", EnvRetention: "soon", EnvOTLPListen: "nocolon", EnvLogLevel: "trace",
	} {
		_, err := LoadConfig(env(map[string]string{k: v}), true)
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%s: error %v should name the variable", k, v, err)
		}
	}
}

func TestLoadConfigDefaultsAndValues(t *testing.T) {
	c, err := LoadConfig(env(nil), true)
	if err != nil || !c.Enabled || c.OTLPListen != "" || c.Retention != 0 || !strings.HasSuffix(c.Dir, filepath.Join(".local", "share", "bellucode", "graph")) {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	c, err = LoadConfig(env(map[string]string{EnvEnabled: "false", EnvDir: "/x", EnvRetention: "24h", EnvOTLPListen: "127.0.0.1:4317", EnvLogLevel: "warn"}), true)
	if err != nil || c.Enabled || c.Dir != "/x" || c.Retention != 24*time.Hour || c.OTLPListen != "127.0.0.1:4317" {
		t.Fatalf("values: %+v %v", c, err)
	}
}

func testCfg(dir string, buf *bytes.Buffer) Config {
	return Config{Enabled: true, Dir: dir, Logger: slog.New(slog.NewTextHandler(buf, nil))}
}

func TestDisabledOpensNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "g")
	e, err := Open(context.Background(), Config{Enabled: false, Dir: dir})
	if err != nil || StateOf(e).Kind != StateDisabled {
		t.Fatalf("%v %v", err, StateOf(e))
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("disabled engine must not create the store")
	}
	rec := httptest.NewRecorder()
	e.MCPHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), CodeUnavailable) {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if _, err := e.Query().Entity(context.Background(), "x", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestOpenCreatesPrivateStoreAndOTLPOff(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "g")
	var buf bytes.Buffer
	e, err := Open(context.Background(), testCfg(dir, &buf))
	if err != nil || StateOf(e).Kind != StateReady {
		t.Fatalf("%v %v", err, StateOf(e))
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		fi, _ := d.Info()
		if d.IsDir() && fi.Mode().Perm() != 0o700 {
			t.Errorf("dir %s mode %o", p, fi.Mode().Perm())
		}
		if !d.IsDir() && fi.Mode().Perm() != 0o600 {
			t.Errorf("file %s mode %o", p, fi.Mode().Perm())
		}
		return nil
	})
}

func TestInsecureDirRefusedUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	e, err := Open(context.Background(), testCfg(dir, &buf))
	if !errors.Is(err, ErrInsecurePermissions) || StateOf(e).Kind != StateFailed {
		t.Fatalf("%v %v", err, StateOf(e))
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o750 {
		t.Fatalf("permissions changed to %o", fi.Mode().Perm())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatal("wrote into insecure dir")
	}
}

func TestLockedStoreLogsHolderOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "g")
	var b1 bytes.Buffer
	first, err := Open(context.Background(), testCfg(dir, &b1))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())

	var b2 bytes.Buffer
	start := time.Now()
	e, err := Open(context.Background(), testCfg(dir, &b2))
	if !errors.Is(err, ErrLocked) || StateOf(e).Kind != StateFailed {
		t.Fatalf("%v %v", err, StateOf(e))
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("too slow")
	}
	out := b2.String()
	if n := strings.Count(out, "level=ERROR"); n != 1 || !strings.Contains(out, filepath.Join(dir, "default", "LOCK")) {
		t.Fatalf("want one error entry with holder path, got:\n%s", out)
	}
}

func TestCorruptStoreLeftUntouched(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "g")
	var buf bytes.Buffer
	e, err := Open(context.Background(), testCfg(dir, &buf))
	if err != nil {
		t.Fatal(err)
	}
	e.Close(context.Background())
	tdir := filepath.Join(dir, "default")
	ents, _ := os.ReadDir(tdir)
	var manifest string
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), "MANIFEST-") {
			manifest = filepath.Join(tdir, en.Name())
		}
	}
	if manifest == "" {
		t.Fatal("no manifest")
	}
	if err := os.WriteFile(manifest, []byte("garbage-not-a-manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, dir)
	e, err = Open(context.Background(), testCfg(dir, &buf))
	if !errors.Is(err, ErrCorrupt) || StateOf(e).Kind != StateFailed {
		t.Fatalf("%v %v", err, StateOf(e))
	}
	after := snapshotDir(t, dir)
	if len(before) != len(after) {
		t.Fatalf("files changed: %v -> %v", keys(before), keys(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s modified", k)
		}
	}
}

func TestOTLPListenerOnlyWhenConfigured(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	cfg := testCfg(filepath.Join(t.TempDir(), "g"), &bytes.Buffer{})
	cfg.OTLPListen = addr
	e, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("listener not bound: %v", err)
	}
	c.Close()
}

func snapshotDir(t *testing.T, dir string) map[string]string {
	m := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if !d.IsDir() && filepath.Base(p) != "LOCK" {
			b, _ := os.ReadFile(p)
			m[p] = string(b)
		}
		return nil
	})
	return m
}

func keys(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}
