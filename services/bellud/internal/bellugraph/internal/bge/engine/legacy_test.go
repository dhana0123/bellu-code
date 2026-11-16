package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Legacy_Data fixtures: two store directories written by the engine before the
// relation-attribute and registry changes, and the graph they must replay to.
//
//	testdata/legacy/log        Event_Log only, no Snapshot
//	testdata/legacy/snapshot   Snapshot at sequence legacySnapshotSeq plus the log tail
//	testdata/legacy/expected.json
//
// Regenerate on the unmodified engine only: go test ./internal/bellugraph/internal/bge/engine -run TestGenerateLegacyFixtures -update-legacy
var updateLegacy = flag.Bool("update-legacy", false, "regenerate testdata/legacy")

const (
	legacyRoot = "testdata/legacy"
	// legacySnapshotSeq is the sequence of the Snapshot in the snapshot fixture.
	// Batches 1 and 2 produce events 1..legacySnapshotSeq; batch 3 is the tail.
	legacySnapshotSeq = 7
)

// legacyExpected is the on-disk shape of expected.json.
type legacyExpected struct {
	Entities  []legacyEntity   `json:"entities"`
	Relations []legacyRelation `json:"relations"`
	// RelationAttributes counts attributes carried by relations; always zero in Legacy_Data.
	RelationAttributes int `json:"relation_attributes"`
}

type legacyEntity struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Identity   map[string]string `json:"identity"`
	Attributes map[string]any    `json:"attributes"`
}

type legacyRelation struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

func legacyBatches() []batch.Batch {
	t0 := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	ent := func(kind string, id map[string]string, attrs map[string]any) batch.Entity {
		return batch.Entity{Type: kind, Identity: id, Attributes: attrs}
	}
	host := map[string]string{"hostname": "legacy-host"}
	container := map[string]string{"id": "c-1"}
	image := map[string]string{"id": "img-1"}
	process := map[string]string{"host": "legacy-host", "pid": "42", "start_time": "1700000000"}
	repo := map[string]string{"path": "/srv/app"}
	dep := map[string]string{"repo": "/srv/app", "name": "left-pad", "range": "^1.0.0"}
	id := func(kind string, attrs map[string]string) string {
		h, err := ident.Hash(kind, attrs)
		if err != nil {
			panic(err)
		}
		return h
	}
	return []batch.Batch{
		{
			Collector: "legacy-docker", ObservedAt: t0,
			Entities: []batch.Entity{
				ent("host", host, map[string]any{"os": "linux", "cpus": int64(8)}),
				ent("container", container, map[string]any{"name": "web", "running": true}),
				ent("image", image, map[string]any{"tag": "web:1"}),
			},
			Relations: []batch.Relation{
				{Type: "runs_on", From: id("container", container), To: id("host", host)},
				{Type: "uses", From: id("container", container), To: id("image", image)},
			},
		},
		{
			Collector: "legacy-process", ObservedAt: t0.Add(time.Minute),
			Entities:  []batch.Entity{ent("process", process, map[string]any{"command": "web --serve"})},
			Relations: []batch.Relation{{Type: "runs_on", From: id("process", process), To: id("host", host)}},
		},
		{
			Collector: "legacy-repo", ObservedAt: t0.Add(2 * time.Minute),
			Entities: []batch.Entity{
				ent("repository", repo, map[string]any{"branch": "main"}),
				ent("dependency", dep, map[string]any{"ecosystem": "npm"}),
				ent("host", host, map[string]any{"os": "linux", "kernel": "6.1"}),
			},
			Relations: []batch.Relation{{Type: "depends_on", From: id("repository", repo), To: id("dependency", dep)}},
		},
	}
}

func quietOptions(clock func() time.Time) Options {
	return Options{Clock: clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestGenerateLegacyFixtures writes the fixtures. It does nothing unless -update-legacy is set.
func TestGenerateLegacyFixtures(t *testing.T) {
	if !*updateLegacy {
		t.Skip("run with -update-legacy to regenerate testdata/legacy")
	}
	clock := &stepClock{t: time.Date(2024, 1, 2, 4, 0, 0, 0, time.UTC)}
	var expected legacyExpected
	for _, name := range []string{"log", "snapshot"} {
		dir := filepath.Join(legacyRoot, name)
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		c, err := Open(dir, quietOptions(clock.now))
		if err != nil {
			t.Fatal(err)
		}
		for i, b := range legacyBatches() {
			if _, err := c.Apply(context.Background(), b, ModePartial); err != nil {
				t.Fatalf("batch %d: %v", i, err)
			}
			clock.t = clock.t.Add(time.Second)
			if i == 1 && name == "snapshot" {
				if err := c.writeSnapshot(); err != nil {
					t.Fatal(err)
				}
				if c.lastSnapSeq != legacySnapshotSeq {
					t.Fatalf("snapshot at %d, constant says %d", c.lastSnapSeq, legacySnapshotSeq)
				}
			}
		}
		expected = describeGraph(c.g)
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		// Close writes a final Snapshot; keep only the one the fixture wants.
		keep := uint64(legacySnapshotSeq)
		if name == "log" {
			keep = 0
		}
		dropSnapshotsExcept(t, dir, keep)
	}
	raw, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyRoot, "expected.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dropSnapshotsExcept(t *testing.T, dir string, keep uint64) {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := st.ListSnapshots()
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	var drop []uint64
	for _, h := range hs {
		if h.Seq != keep {
			drop = append(drop, h.Seq)
		}
	}
	if err := st.DeleteSnapshots(drop...); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

// describeGraph lists the live entities and relations of g in a stable order.
func describeGraph(g *graph.Graph) legacyExpected {
	out := legacyExpected{Entities: []legacyEntity{}, Relations: []legacyRelation{}}
	for _, id := range g.LiveIDs() {
		e, _ := g.Entity(id)
		attrs := map[string]any{}
		for k, v := range e.Attrs {
			attrs[k] = v.ToAny()
		}
		out.Entities = append(out.Entities, legacyEntity{ID: string(e.ID), Kind: e.Kind, Identity: e.Identity, Attributes: attrs})
	}
	sort.Slice(out.Entities, func(i, j int) bool { return out.Entities[i].ID < out.Entities[j].ID })
	for _, k := range g.AllRelations() {
		out.Relations = append(out.Relations, legacyRelation{Type: k.Type, From: string(k.From), To: string(k.To)})
	}
	return out
}

// normalized round-trips v through JSON so numbers compare the way they do in the file.
func normalized(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// treeDigest hashes every file name and content below dir.
func treeDigest(t *testing.T, dir string) [32]byte {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func readLegacyExpected(t *testing.T) legacyExpected {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(legacyRoot, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp legacyExpected
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}
	return exp
}

// TestLegacyReplay loads each fixture and compares the Projection with expected.json.
func TestLegacyReplay(t *testing.T) {
	exp := readLegacyExpected(t)
	if len(exp.Entities) == 0 || len(exp.Relations) == 0 {
		t.Fatal("expected.json is empty; regenerate with -update-legacy")
	}
	if exp.RelationAttributes != 0 {
		t.Fatalf("expected.json records %d relation attributes, want 0", exp.RelationAttributes)
	}
	for _, name := range []string{"log", "snapshot"} {
		t.Run(name, func(t *testing.T) {
			// Open writes to the directory, so replay a copy and leave the fixture alone.
			dir := filepath.Join(t.TempDir(), name)
			copyDir(t, filepath.Join(legacyRoot, name), dir)

			ro, err := store.OpenReadOnly(dir)
			if err != nil {
				t.Fatal(err)
			}
			hs, err := ro.ListSnapshots()
			ro.Close()
			if err != nil {
				t.Fatal(err)
			}
			if name == "log" && len(hs) != 0 {
				t.Fatalf("log fixture holds %d snapshots, want 0", len(hs))
			}
			if name == "snapshot" && (len(hs) != 1 || hs[0].Seq != legacySnapshotSeq) {
				t.Fatalf("snapshot fixture holds %+v, want one at %d", hs, legacySnapshotSeq)
			}

			c, err := Open(dir, quietOptions(time.Now))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer c.Close(context.Background())
			got := describeGraph(c.g)
			if !reflect.DeepEqual(normalized(t, got), normalized(t, exp)) {
				t.Fatalf("replayed graph differs from expected.json\n got: %s\nwant: %s", mustJSON(t, got), mustJSON(t, exp))
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestLegacyCorruptRecordAbortsOpen flips one byte in one event record of a copy
// of the log and checks that Open fails with a corruption error and writes nothing.
func TestLegacyCorruptRecordAbortsOpen(t *testing.T) {
	original := filepath.Join(legacyRoot, "log")
	before := treeDigest(t, original)

	dir := filepath.Join(t.TempDir(), "log")
	copyDir(t, original, dir)

	const seq = 3
	flipRecordByte(t, dir, seq)
	corrupted := treeDigest(t, dir)

	c, err := Open(dir, quietOptions(time.Now))
	if err == nil {
		c.Close(context.Background())
		t.Fatal("Open succeeded on a log with a damaged record")
	}
	if !errors.Is(err, errs.Corrupt) {
		t.Fatalf("Open error = %v, want errs.Corrupt", err)
	}
	// TODO(task 3.x): the engine reports "event CRC mismatch" without the
	// sequence. Once replay names the record, assert the message contains it.
	if !strings.Contains(err.Error(), "event") {
		t.Fatalf("Open error does not identify an event record: %v", err)
	}
	if treeDigest(t, dir) != corrupted {
		t.Fatal("failed Open modified the damaged directory")
	}
	if treeDigest(t, original) != before {
		t.Fatal("fixture directory changed")
	}
}

// flipRecordByte flips one bit in the middle of the stored envelope of event seq.
func flipRecordByte(t *testing.T, dir string, seq uint64) {
	t.Helper()
	db, err := pebble.Open(store.Path(dir), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	key := binary.BigEndian.AppendUint64([]byte("e/"), seq)
	val, closer, err := db.Get(key)
	if err != nil {
		db.Close()
		t.Fatalf("event %d: %v", seq, err)
	}
	damaged := bytes.Clone(val)
	closer.Close()
	damaged[len(damaged)/2] ^= 0x01
	if err := db.Set(key, damaged, pebble.Sync); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
