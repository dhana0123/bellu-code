package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"

	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
)

func jsonl(t *testing.T, vs ...model.Vuln) *strings.Reader {
	var sb strings.Builder
	for _, v := range vs {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return strings.NewReader(sb.String())
}

func vuln(id, purl string, aliases ...string) model.Vuln {
	return model.Vuln{ID: id, Aliases: aliases, Affected: []model.AffectedPackage{{Purl: purl}}}
}

func TestReplaceGetByPurlMeta(t *testing.T) {
	dir := t.TempDir() + "/intel"
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := s.Meta(); m.Active() {
		t.Fatal("fresh store should have no generation")
	}
	err = s.Replace(context.Background(), ImportInfo{Version: "v1"}, jsonl(t,
		vuln("CVE-1", "pkg:npm/lodash", "GHSA-a"),
		vuln("CVE-2", "pkg:npm/lodash"),
		vuln("CVE-3", "pkg:npm/lodash-es"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := s.Get("GHSA-a"); !ok || v.ID != "CVE-1" {
		t.Fatalf("alias lookup: %v %v", v, ok)
	}
	if _, ok, _ := s.Get("nope"); ok {
		t.Fatal("unexpected hit")
	}
	got, err := s.ByPurl("pkg:npm/lodash")
	if err != nil || len(got) != 2 || got[0].ID != "CVE-1" || got[1].ID != "CVE-2" {
		t.Fatalf("ByPurl = %v, %v", got, err)
	}
	m, _ := s.Meta()
	if m.Records != 3 || m.Version != "v1" || m.Gen != 1 {
		t.Fatalf("meta %+v", m)
	}
}

func TestFailedReplaceKeepsOldAndReopenCleans(t *testing.T) {
	dir := t.TempDir() + "/intel"
	s, _ := Open(dir)
	ctx := context.Background()
	if err := s.Replace(ctx, ImportInfo{Version: "v1"}, jsonl(t, vuln("CVE-1", "pkg:npm/a"))); err != nil {
		t.Fatal(err)
	}
	bad := strings.NewReader(`{"ID":"CVE-9","Affected":[{"Purl":"pkg:npm/a"}]}` + "\n{not json\n")
	if err := s.Replace(ctx, ImportInfo{Version: "v2"}, bad); err == nil {
		t.Fatal("expected error")
	}
	m, _ := s.Meta()
	if m.Version != "v1" {
		t.Fatalf("old generation lost: %+v", m)
	}
	if got, _ := s.ByPurl("pkg:npm/a"); len(got) != 1 || got[0].ID != "CVE-1" {
		t.Fatalf("got %v", got)
	}
	if err := s.RecordError("boom"); err != nil {
		t.Fatal(err)
	}
	// Plant a stale generation, then reopen.
	if err := s.db.Set(vKey(7, "X"), []byte("{}"), nil); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, c, err := s.db.Get(vKey(7, "X")); err == nil {
		c.Close()
		t.Fatal("stale generation survived open")
	}
	m, _ = s.Meta()
	if m.LastError != "boom" || m.Version != "v1" {
		t.Fatalf("meta %+v", m)
	}
	// Second replace swaps and removes the old generation.
	if err := s.Replace(ctx, ImportInfo{Version: "v3"}, jsonl(t, vuln("CVE-5", "pkg:npm/b"))); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("CVE-1"); ok {
		t.Fatal("old record visible")
	}
	if _, c, err := s.db.Get(vKey(1, "CVE-1")); !errors.Is(err, pebble.ErrNotFound) {
		if c != nil {
			c.Close()
		}
		t.Fatal("old generation not deleted")
	}
}

func TestLargeImportBatches(t *testing.T) {
	s, _ := Open(t.TempDir() + "/intel")
	defer s.Close()
	var vs []model.Vuln
	for i := 0; i < batchRecords+10; i++ {
		vs = append(vs, vuln(fmt.Sprintf("CVE-%06d", i), "pkg:npm/x"))
	}
	if err := s.Replace(context.Background(), ImportInfo{}, jsonl(t, vs...)); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.Meta(); m.Records != len(vs) {
		t.Fatalf("records %d", m.Records)
	}
}
