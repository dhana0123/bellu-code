package cce

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	"pgregory.net/rapid"
)

const ws = WorkspaceID("ws1")

func openStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), t.TempDir(), string(ws), sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func addEntity(t *testing.T, s *sqlite.Store, id, key string) {
	t.Helper()
	_, err := s.DB().Exec(`INSERT INTO stable_entity (workspace_id, stable_id, graph, kind, attrs, source_revision, valid_from)
		VALUES (?, ?, 'cve', 'package', json_object('canonical_key', ?), 'r1', '2024-01-01T00:00:00Z')`, string(ws), id, key)
	if err != nil {
		t.Fatal(err)
	}
}

func TestResolveExact(t *testing.T) {
	s := openStore(t)
	addEntity(t, s, "bid:vuln:CVE-2024-0001", "vuln:CVE-2024-0001")
	r := SQLResolver{DB: s.DB()}
	ctx := context.Background()

	id, ok, err := r.ResolveExact(ctx, ws, IdentityKey{CVEID, " cve-2024-0001 "})
	if err != nil || !ok || id != "bid:vuln:CVE-2024-0001" {
		t.Fatalf("got %q %v %v", id, ok, err)
	}
	if _, ok, err := r.ResolveExact(ctx, ws, IdentityKey{CVEID, "CVE-2024-0002"}); ok || err != nil {
		t.Fatalf("expected no match, got %v %v", ok, err)
	}
	if _, ok, _ := r.ResolveExact(ctx, "other", IdentityKey{CVEID, "CVE-2024-0001"}); ok {
		t.Fatal("matched across workspaces")
	}
}

func TestResolveExactAmbiguous(t *testing.T) {
	s := openStore(t)
	addEntity(t, s, "bid:a", "vuln:CVE-2024-0001")
	addEntity(t, s, "bid:b", "vuln:CVE-2024-0001")
	_, ok, err := SQLResolver{DB: s.DB()}.ResolveExact(context.Background(), ws, IdentityKey{CVEID, "CVE-2024-0001"})
	if ok || !errors.Is(err, ErrAmbiguousKey) {
		t.Fatalf("got %v %v", ok, err)
	}
}

func TestInvalidKeys(t *testing.T) {
	s := openStore(t)
	r := SQLResolver{DB: s.DB()}
	cases := []IdentityKey{
		{CVEID, ""},
		{SymbolQualifiedName, strings.Repeat("a", MaxKeyLen+1)},
		{KeyType("bogus"), "x"},
		{CVEID, "not-a-cve"},
		{PURL, "npm/left-pad"},
		{FilePathAtRevision, "no-revision"},
	}
	for _, k := range cases {
		id, ok, err := r.ResolveExact(context.Background(), ws, k)
		if ok || id != "" || !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%+v: got %q %v %v", k, id, ok, err)
		}
	}
	if _, err := Normalize(IdentityKey{SymbolQualifiedName, strings.Repeat("a", MaxKeyLen)}); err != nil {
		t.Fatalf("2048 chars should be accepted: %v", err)
	}
}

func TestNormalizeIdempotent(t *testing.T) {
	types := []KeyType{CVEID, PURL, ARN, RepoFullName, ImageDigest, FilePathAtRevision, SymbolQualifiedName}
	samples := map[KeyType][]string{
		CVEID:               {"cve-2024-1234", "GHSA-abcd-1234-wxyz"},
		PURL:                {"PKG:npm/@Scope/Name@1.0.0", "pkg:golang/github.com/x/y"},
		ARN:                 {"ARN:AWS:S3:::bucket"},
		RepoFullName:        {"git@GitHub.com:Org/Repo.git", "https://github.com/Org/Repo"},
		ImageDigest:         {"sha256:" + strings.Repeat("AB", 32)},
		FilePathAtRevision:  {" org/repo@abc123:src/a.go "},
		SymbolQualifiedName: {" pkg.Type.Method "},
	}
	for _, ty := range types {
		for _, v := range samples[ty] {
			a, err := Normalize(IdentityKey{ty, v})
			if err != nil {
				t.Fatalf("%s %q: %v", ty, v, err)
			}
			b, err := Normalize(IdentityKey{ty, a})
			if err != nil || a != b {
				t.Fatalf("%s %q not idempotent: %q -> %q (%v)", ty, v, a, b, err)
			}
		}
	}
}

func TestNewRelationID(t *testing.T) {
	a := NewRelationID("calls", "bid:a", "bid:b", ws)
	if len(a) != 64 || strings.ToLower(string(a)) != string(a) {
		t.Fatalf("bad id %q", a)
	}
	if a != NewRelationID("calls", "bid:a", "bid:b", ws) {
		t.Fatal("not deterministic")
	}
	for _, o := range []RelationID{
		NewRelationID("imports", "bid:a", "bid:b", ws),
		NewRelationID("calls", "bid:x", "bid:b", ws),
		NewRelationID("calls", "bid:a", "bid:x", ws),
		NewRelationID("calls", "bid:a", "bid:b", "ws2"),
	} {
		if o == a {
			t.Fatal("changed input produced same id")
		}
	}
}

func TestRelationIDDistinctProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g := rapid.StringN(0, 8, -1)
		a := [4]string{g.Draw(t, "t"), g.Draw(t, "f"), g.Draw(t, "to"), g.Draw(t, "ws")}
		b := [4]string{g.Draw(t, "t2"), g.Draw(t, "f2"), g.Draw(t, "to2"), g.Draw(t, "ws2")}
		ia := NewRelationID(a[0], StableID(a[1]), StableID(a[2]), WorkspaceID(a[3]))
		ib := NewRelationID(b[0], StableID(b[1]), StableID(b[2]), WorkspaceID(b[3]))
		if (a == b) != (ia == ib) {
			t.Fatalf("%v %v -> %s %s", a, b, ia, ib)
		}
	})
}

func TestInsertRelationIdempotent(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	rel := Relation{Workspace: ws, Type: "calls", From: "bid:a", To: "bid:b", State: Hypothesis,
		Confidence: 0.4, Method: MethodSemantic,
		Temporal: Temporal{RecordedAt: now, ValidFrom: now, ObservedAt: now, SourceRevision: "run:r1"}}
	ctx := context.Background()
	first, err := InsertRelation(ctx, s, rel)
	if err != nil || first.AlreadyExists {
		t.Fatalf("first: %+v %v", first, err)
	}
	rel.Confidence, rel.State = 0.9, Candidate
	second, err := InsertRelation(ctx, s, rel)
	if err != nil || !second.AlreadyExists || second.ID != first.ID {
		t.Fatalf("second: %+v %v", second, err)
	}
	var state string
	var conf float64
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*), MAX(state), MAX(confidence) FROM relation`).Scan(&n, &state, &conf); err != nil {
		t.Fatal(err)
	}
	if n != 1 || state != "hypothesis" || conf != 0.4 {
		t.Fatalf("stored relation changed: %d %s %v", n, state, conf)
	}
	if _, err := InsertRelation(ctx, s, Relation{Workspace: ws}); !errors.Is(err, ErrInvalidRelation) {
		t.Fatalf("want ErrInvalidRelation, got %v", err)
	}
}
