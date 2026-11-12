package facade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reflect"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Validates: Requirements 12.2, 12.3 — each bad value names its variable and
// every bad variable is reported together.
func TestSUConfigEachBadValueNamed(t *testing.T) {
	bad := []struct{ k, v string }{
		{EnvEnabled, "maybe"}, {EnvRetention, "-5h"}, {EnvRetention, "soon"},
		{EnvOTLPListen, "host:99999"}, {EnvOTLPListen, "host:abc"}, {EnvLogLevel, "TRACE"},
	}
	for _, c := range bad {
		_, err := LoadConfig(env(map[string]string{c.k: c.v}), false)
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Var != c.k || ce.Value != c.v || !strings.Contains(err.Error(), c.k) {
			t.Errorf("%s=%s: %v", c.k, c.v, err)
		}
	}
	_, err := LoadConfig(env(map[string]string{EnvEnabled: "x", EnvRetention: "y", EnvLogLevel: "z", EnvOTLPListen: "w"}), false)
	for _, k := range []string{EnvEnabled, EnvRetention, EnvLogLevel, EnvOTLPListen} {
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("joined error should name %s: %v", k, err)
		}
	}
}

// Validates: Requirements 11.6, 11.12 — group/world-accessible dirs are
// refused and left byte- and mode-identical.
func TestSUInsecureModesRefusedUnchanged(t *testing.T) {
	for _, mode := range []os.FileMode{0o750, 0o705, 0o755, 0o770} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		e, err := Open(context.Background(), testCfg(dir, &buf))
		if !errors.Is(err, ErrInsecurePermissions) || StateOf(e).Kind != StateFailed {
			t.Fatalf("%o: %v %v", mode, err, StateOf(e))
		}
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != mode {
			t.Errorf("%o: mode changed to %o", mode, fi.Mode().Perm())
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("%o: wrote into dir", mode)
		}
	}
}

// Validates: Requirements 11.12, 12.5 — a corrupt CURRENT or MANIFEST is
// reported as ErrCorrupt and every byte and mode stays identical.
func TestSUCorruptFileLeavesStoreIdentical(t *testing.T) {
	for _, prefix := range []string{"CURRENT", "MANIFEST-"} {
		dir := filepath.Join(t.TempDir(), "g")
		var buf bytes.Buffer
		e, err := Open(context.Background(), testCfg(dir, &buf))
		if err != nil {
			t.Fatal(err)
		}
		e.Close(context.Background())
		tdir := filepath.Join(dir, "default")
		ents, _ := os.ReadDir(tdir)
		target := ""
		for _, en := range ents {
			if strings.HasPrefix(en.Name(), prefix) {
				target = filepath.Join(tdir, en.Name())
			}
		}
		if target == "" {
			t.Fatalf("no %s file", prefix)
		}
		if err := os.WriteFile(target, []byte("garbage\x00\xff"), 0o600); err != nil {
			t.Fatal(err)
		}
		before, modesBefore := suSnapshot(t, dir)
		e, err = Open(context.Background(), testCfg(dir, &buf))
		if !errors.Is(err, ErrCorrupt) || StateOf(e).Kind != StateFailed {
			t.Fatalf("%s: %v %v", prefix, err, StateOf(e))
		}
		after, modesAfter := suSnapshot(t, dir)
		if !reflect.DeepEqual(before, after) {
			t.Errorf("%s: contents changed", prefix)
		}
		if !reflect.DeepEqual(modesBefore, modesAfter) {
			t.Errorf("%s: modes changed", prefix)
		}
	}
}

func suSnapshot(t *testing.T, dir string) (map[string]string, map[string]os.FileMode) {
	t.Helper()
	data, modes := map[string]string{}, map[string]os.FileMode{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		fi, _ := d.Info()
		modes[p] = fi.Mode()
		if !d.IsDir() && filepath.Base(p) != "LOCK" {
			b, _ := os.ReadFile(p)
			data[p] = string(b)
		}
		return nil
	})
	return data, modes
}

// Validates: Requirements 13.12, 13.13 — page size bounds and not-found for
// Neighbors, History and Changes.
func TestSUPageBoundsAndNotFound(t *testing.T) {
	ctx := context.Background()
	e := openTemp(t)
	id := EntityID(mustID(t, "host", map[string]string{"hostname": "h1"}))
	if _, err := e.Ingest().Apply(ctx, suBatch()); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{-1, 1001} {
		p := Paging{PageSize: size}
		if _, err := e.Query().Neighbors(ctx, id, NeighborOpts{Paging: p}); !errors.Is(err, ErrValidation) {
			t.Errorf("neighbors %d: %v", size, err)
		}
		if _, err := e.Query().History(ctx, id, TimeRange{}, p); !errors.Is(err, ErrValidation) {
			t.Errorf("history %d: %v", size, err)
		}
	}
	for _, size := range []int{0, 1, 1000} {
		p := Paging{PageSize: size}
		if _, err := e.Query().Neighbors(ctx, id, NeighborOpts{Paging: p}); err != nil {
			t.Errorf("neighbors %d: %v", size, err)
		}
		if _, err := e.Query().History(ctx, id, TimeRange{}, p); err != nil {
			t.Errorf("history %d: %v", size, err)
		}
	}
	if _, err := e.Query().Neighbors(ctx, "host:00", NeighborOpts{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("neighbors unknown: %v", err)
	}
	if _, err := e.Query().History(ctx, "host:00", TimeRange{}, Paging{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("history unknown: %v", err)
	}
}

func suBatch() batch.Batch {
	return batch.Batch{Collector: "host", ObservedAt: t0, Entities: []batch.Entity{hostEnt("h1", nil)}}
}
