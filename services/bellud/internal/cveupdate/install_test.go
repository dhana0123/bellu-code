package cveupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/sign"
)

// All snapshots in these tests hold an empty graph, so they share one logical
// digest and differ only in build time (and therefore snapshot id).
var emptyDigest = func() string { s := sha256.Sum256(nil); return hex.EncodeToString(s[:]) }()

const testProduct = "Bellu Global Intelligence"

func tsnap(day int) (id string, created time.Time) {
	created = time.Date(2025, 3, day, 0, 0, 0, 0, time.UTC)
	return created.Format("20060102T150405Z") + "-" + emptyDigest[:8], created
}

func sumHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(files[n])), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		tw.Write(files[n])
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func checksums(files map[string][]byte, names ...string) []byte {
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sumHex(files[n]), n)
	}
	return []byte(b.String())
}

// emptyDB returns an SQLite file with the graph.db tables and no rows.
func emptyDB(t *testing.T, schema string, corrupt bool) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "g.db")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE nodes(id TEXT PRIMARY KEY, type TEXT NOT NULL, props TEXT NOT NULL, h TEXT NOT NULL)`,
		`CREATE TABLE edges(id TEXT PRIMARY KEY, type TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, props TEXT NOT NULL, h TEXT NOT NULL)`,
		`INSERT INTO meta VALUES('schema_version','` + schema + `'),('engine','sqlite'),('engine_version','1'),('created_at','x')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if corrupt {
		// A file shorter than its header page count fails the integrity check.
		b = b[:len(b)-4096]
	}
	return b
}

func snapshotPack(t *testing.T, day int, schema string, corrupt bool) []byte {
	t.Helper()
	id, created := tsnap(day)
	m, _ := json.Marshal(map[string]any{
		"product": testProduct, "snapshot_id": id, "schema_version": schema, "database_engine": "sqlite",
		"engine_version": "1", "created_at": created, "distribution_level": "core", "ecosystems": []string{},
		"record_counts": map[string]any{"nodes": map[string]int{}, "edges": map[string]int{}}, "logical_digest": emptyDigest,
	})
	files := map[string][]byte{
		"graph.db": emptyDB(t, schema, corrupt), "manifest.json": m,
		"metadata/sources.json": []byte(`[]`), "metadata/statistics.json": []byte(`{}`),
		"metadata/schema-version.json": []byte(`{"schema_version":"` + schema + `"}`),
	}
	files["checksums.sha256"] = checksums(files, "graph.db", "manifest.json", "metadata/sources.json", "metadata/statistics.json", "metadata/schema-version.json")
	return tarGz(t, files)
}

func deltaPack(t *testing.T, baseDay, targetDay int) []byte {
	t.Helper()
	base, _ := tsnap(baseDay)
	target, created := tsnap(targetDay)
	m, _ := json.Marshal(map[string]any{
		"kind": "delta", "product": testProduct, "base_snapshot_id": base, "target_snapshot_id": target,
		"schema_version": "1", "distribution_level": "core", "ecosystems": []string{}, "created_at": created,
		"counts":         map[string]int{"upsert_nodes": 0, "delete_nodes": 0, "upsert_edges": 0, "delete_edges": 0, "changed_records": 0},
		"record_counts":  map[string]any{"nodes": map[string]int{}, "edges": map[string]int{}},
		"logical_digest": emptyDigest, "files": []string{"checksums.sha256", "delta.jsonl", "manifest.json"},
	})
	files := map[string][]byte{"delta.jsonl": {}, "manifest.json": m}
	files["checksums.sha256"] = checksums(files, "delta.jsonl", "manifest.json")
	return tarGz(t, files)
}

type env struct {
	t       *testing.T
	priv    ed25519.PrivateKey
	v       *Verifier
	mu      sync.Mutex
	objects map[string][]byte
	srv     *httptest.Server
	dir     string
	audit   *memAudit
	up      *Updater
}

type memAudit struct{ rows []AuditEntry }

func (m *memAudit) AppendCVEUpdate(_ context.Context, e AuditEntry) error {
	m.rows = append(m.rows, e)
	return nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pub, priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v, _ := NewVerifier([]ed25519.PublicKey{pub})
	e := &env{t: t, priv: priv, v: v, objects: map[string][]byte{}, audit: &memAudit{}, dir: filepath.Join(t.TempDir(), "cve")}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		b, ok := e.objects[r.URL.Path]
		e.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(e.srv.Close)
	c, err := New(Config{MirrorURL: e.srv.URL, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	e.up = &Updater{Dir: e.dir, Client: c, Verifier: v, Audit: e.audit}
	return e
}

// publish stores a signed pack and returns its index entry fields.
func (e *env) publish(name string, data []byte) (url, sha string, size int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	url = "/cve/v1/" + name
	e.objects[url] = data
	e.objects[url+".sig"] = sign.Sign(e.priv, data)
	return url, sumHex(data), int64(len(data))
}

func (e *env) snap(day int, data []byte) Snapshot {
	id, created := tsnap(day)
	u, h, n := e.publish(fmt.Sprintf("snap-%d.tar.gz", day), data)
	return Snapshot{ID: id, URL: u, SHA256: h, Size: n, CreatedAt: created}
}

func (e *env) delta(from, to int, data []byte) Delta {
	b, _ := tsnap(from)
	g, _ := tsnap(to)
	u, h, n := e.publish(fmt.Sprintf("delta-%d-%d.tar.gz", from, to), data)
	return Delta{Base: b, Target: g, URL: u, SHA256: h, Size: n}
}

func (e *env) currentID() string {
	t := e.t
	t.Helper()
	l, err := os.Readlink(filepath.Join(e.dir, "current"))
	if err != nil {
		return ""
	}
	return filepath.Base(l)
}

func (e *env) stateBytes() string {
	b, _ := os.ReadFile(filepath.Join(e.dir, "state.json"))
	return string(b)
}

func (e *env) assertNoStaging() {
	e.t.Helper()
	if ents, _ := os.ReadDir(filepath.Join(e.dir, "staging")); len(ents) != 0 {
		e.t.Fatalf("staging not removed: %v", ents)
	}
}

func fullIndex(e *env, day int, schema string, corrupt bool) *Index {
	s := e.snap(day, snapshotPack(e.t, day, schema, corrupt))
	return &Index{Latest: s, Snapshots: []Snapshot{s}}
}

func TestFullInstallThenDeltaChain(t *testing.T) {
	e := newEnv(t)
	idx := fullIndex(e, 1, "1", false)
	res, err := e.up.InstallIndex(context.Background(), idx)
	if err != nil {
		t.Fatal(err)
	}
	id1, _ := tsnap(1)
	if e.currentID() != id1 || res.State.InstalledID != id1 || !res.Plan.Full {
		t.Fatalf("after full install: current=%s res=%+v", e.currentID(), res)
	}
	if len(e.audit.rows) != 1 || e.audit.rows[0].Outcome != "success" {
		t.Fatalf("audit: %+v", e.audit.rows)
	}
	e.assertNoStaging()

	// Two deltas 1->2->3: both applied in staging, one swap.
	s1 := Snapshot{ID: id1, CreatedAt: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)}
	s2, s3 := e.snap(2, snapshotPack(t, 2, "1", false)), e.snap(3, snapshotPack(t, 3, "1", false))
	idx2 := &Index{Latest: s3, Snapshots: []Snapshot{s1, s2, s3},
		Deltas: []Delta{e.delta(1, 2, deltaPack(t, 1, 2)), e.delta(2, 3, deltaPack(t, 2, 3))}}
	res, err = e.up.InstallIndex(context.Background(), idx2)
	if err != nil {
		t.Fatal(err)
	}
	id3, _ := tsnap(3)
	if res.Plan.Full || len(res.Plan.Deltas) != 2 || e.currentID() != id3 || len(res.State.AppliedDeltas) != 2 {
		t.Fatalf("chain install: current=%s res=%+v", e.currentID(), res)
	}
	if res.State.PreviousID != id1 {
		t.Fatalf("previous id %s, want %s", res.State.PreviousID, id1)
	}
	e.assertNoStaging()

	// Up to date: nothing fetched, no new audit row.
	res, err = e.up.InstallIndex(context.Background(), idx2)
	if err != nil || !res.Unchanged || len(e.audit.rows) != 2 {
		t.Fatalf("up to date: %v %+v rows=%d", err, res, len(e.audit.rows))
	}
}

func TestKeepsOnlyTwoVersions(t *testing.T) {
	e := newEnv(t)
	for day := 1; day <= 4; day++ {
		idx := fullIndex(e, day, "1", false)
		if _, err := e.up.InstallIndex(context.Background(), idx); err != nil {
			t.Fatalf("day %d: %v", day, err)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(e.dir, "snapshots"))
	var names []string
	for _, x := range ents {
		names = append(names, x.Name())
	}
	id3, _ := tsnap(3)
	id4, _ := tsnap(4)
	if len(names) != 2 || names[0] != id3 || names[1] != id4 {
		t.Fatalf("snapshots kept: %v", names)
	}
}

// failureCase installs day 1, then attempts day 2 and expects a failure that
// leaves everything as it was.
func TestFailuresKeepCurrent(t *testing.T) {
	tests := []struct {
		name     string
		wantStep string
		wantErr  error
		setup    func(e *env) *Index
	}{
		{"checksum", StepVerify, nil, func(e *env) *Index {
			idx := fullIndex(e, 2, "1", false)
			idx.Latest.SHA256 = strings.Repeat("0", 64)
			return idx
		}},
		{"signature", StepVerify, nil, func(e *env) *Index {
			idx := fullIndex(e, 2, "1", false)
			_, other, _ := sign.GenerateKey()
			e.objects[idx.Latest.URL+".sig"] = sign.Sign(other, e.objects[idx.Latest.URL])
			return idx
		}},
		{"download 404", StepDownload, nil, func(e *env) *Index {
			idx := fullIndex(e, 2, "1", false)
			delete(e.objects, idx.Latest.URL)
			return idx
		}},
		{"size differs", StepDownload, ErrPackSize, func(e *env) *Index {
			idx := fullIndex(e, 2, "1", false)
			idx.Latest.Size--
			return idx
		}},
		{"schema mismatch", StepIntegrity, nil, func(e *env) *Index { return fullIndex(e, 2, "99", false) }},
		{"integrity", StepIntegrity, ErrIntegrity, func(e *env) *Index { return fullIndex(e, 2, "1", true) }},
		{"downgrade", StepPlan, ErrDowngrade, func(e *env) *Index { return fullIndex(e, 0+0, "1", false) }},
		{"disk space", StepDisk, ErrDiskSpace, func(e *env) *Index {
			e.up.FreeBytes = func(string) (uint64, error) { return 10, nil }
			return fullIndex(e, 2, "1", false)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.name == "downgrade" {
				// install day 5, then offer day 3
				if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 5, "1", false)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 1, "1", false)); err != nil {
				t.Fatal(err)
			}
			before, state := e.currentID(), e.stateBytes()
			idx := tc.setup(e)
			if tc.name == "downgrade" {
				idx = fullIndex(e, 3, "1", false)
			}
			_, err := e.up.InstallIndex(context.Background(), idx)
			if err == nil {
				t.Fatal("expected failure")
			}
			var ie *InstallError
			if !errors.As(err, &ie) || ie.Step != tc.wantStep {
				t.Fatalf("step: got %v, want %s", err, tc.wantStep)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v does not wrap %v", err, tc.wantErr)
			}
			if e.currentID() != before || e.stateBytes() != state {
				t.Fatalf("current or state changed: %s", e.currentID())
			}
			e.assertNoStaging()
			rows := e.audit.rows
			if len(rows) != 2 || rows[1].Outcome != "failure" || rows[1].Step != tc.wantStep || rows[1].Cause == "" {
				t.Fatalf("audit rows: %+v", rows)
			}
			if _, err := os.Stat(filepath.Join(e.dir, "current", "graph.db")); err != nil {
				t.Fatalf("current unreadable: %v", err)
			}
		})
	}
}

func TestBadPackIsNamedAndDeleted(t *testing.T) {
	e := newEnv(t)
	idx := fullIndex(e, 1, "1", false)
	idx.Latest.SHA256 = strings.Repeat("0", 64)
	_, err := e.up.InstallIndex(context.Background(), idx)
	var pe *PackError
	if !errors.As(err, &pe) || !strings.Contains(err.Error(), "snapshot "+idx.Latest.ID) {
		t.Fatalf("pack not named: %v", err)
	}
	if e.currentID() != "" {
		t.Fatal("current set after rejected pack")
	}
}

func TestMidChainFailureLeavesCurrent(t *testing.T) {
	e := newEnv(t)
	if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 1, "1", false)); err != nil {
		t.Fatal(err)
	}
	before, state := e.currentID(), e.stateBytes()
	id1, _ := tsnap(1)
	s1 := Snapshot{ID: id1, CreatedAt: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)}
	s3 := e.snap(3, snapshotPack(t, 3, "1", false))
	// The second delta names the wrong base, so the apply fails after the
	// first delta was applied in staging.
	bad := deltaPack(t, 1, 3)
	idx := &Index{Latest: s3, Snapshots: []Snapshot{s1, s3},
		Deltas: []Delta{e.delta(1, 2, deltaPack(t, 1, 2)), e.delta(2, 3, bad)}}
	_, err := e.up.InstallIndex(context.Background(), idx)
	if err == nil {
		t.Fatal("expected failure")
	}
	if e.currentID() != before || e.stateBytes() != state {
		t.Fatal("current or state changed after mid-chain failure")
	}
	e.assertNoStaging()
}

// A failure injected after every step must leave readers on the old snapshot.
func TestInjectedFailuresAtEveryStep(t *testing.T) {
	for _, step := range []string{StepDownload, StepVerify, StepApply, StepSwap} {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 1, "1", false)); err != nil {
				t.Fatal(err)
			}
			before, state := e.currentID(), e.stateBytes()
			e.up.AfterStep = func(s string) error {
				if s == step {
					return errors.New("injected")
				}
				return nil
			}
			if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 2, "1", false)); err == nil {
				t.Fatal("expected failure")
			}
			if e.currentID() != before || e.stateBytes() != state {
				t.Fatal("current or state changed")
			}
			e.assertNoStaging()
		})
	}
}

func TestReconcileCompletesInterruptedCommit(t *testing.T) {
	e := newEnv(t)
	if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 1, "1", false)); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after state.json was written but before the swap:
	// install day 2 then point current back at day 1.
	if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 2, "1", false)); err != nil {
		t.Fatal(err)
	}
	id1, _ := tsnap(1)
	id2, _ := tsnap(2)
	cur := filepath.Join(e.dir, "current")
	os.Remove(cur)
	os.Symlink(filepath.Join("snapshots", id1), cur)
	// A stale staging directory from the crashed run.
	os.MkdirAll(filepath.Join(e.dir, "staging", "run-x"), 0o755)
	if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 2, "1", false)); err != nil {
		t.Fatal(err)
	}
	if e.currentID() != id2 {
		t.Fatalf("current %s, want %s", e.currentID(), id2)
	}
	e.assertNoStaging()
}

func TestConcurrentUpdaterRejected(t *testing.T) {
	e := newEnv(t)
	unlock, err := lockDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := e.up.InstallIndex(context.Background(), fullIndex(e, 1, "1", false)); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("got %v", err)
	}
}
