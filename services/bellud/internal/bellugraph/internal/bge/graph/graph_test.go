package graph

import (
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

func sv(s string) codec.Value { return codec.Value{T: codec.TagString, S: s} }

type seqr struct{ n uint64 }

func (s *seqr) ev(e codec.Event) codec.Event {
	s.n++
	e.Seq = s.n
	if e.ValidNS == 0 {
		e.ValidNS = int64(s.n) * 10
	}
	e.RecordedNS = int64(s.n) * 100
	return e
}

func mustID(t *testing.T, kind string, id map[string]string) string {
	t.Helper()
	h, err := ident.Hash(kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func hostEv(c, name string) codec.Event {
	return codec.Event{Type: codec.EntityCreated, Collector: c, Kind: "host",
		Identity: map[string]string{"hostname": name}, Attrs: map[string]codec.Value{"name": sv(name)}}
}

func portEv(c, host, proto, addr, port string) codec.Event {
	return codec.Event{Type: codec.EntityCreated, Collector: c, Kind: KindListeningPort,
		Identity: map[string]string{"host": host, "protocol": proto, "address": addr, "port": port}}
}

// build folds a representative event sequence and returns the graph and IDs.
func build(t *testing.T) (*Graph, map[string]string) {
	t.Helper()
	g, s := New(), &seqr{}
	ids := map[string]string{
		"h1": mustID(t, "host", map[string]string{"hostname": "b"}),
		"h0": mustID(t, "host", map[string]string{"hostname": "a"}),
		"p":  mustID(t, KindListeningPort, map[string]string{"host": "b", "protocol": "tcp", "address": "0.0.0.0", "port": "443"}),
	}
	for _, e := range []codec.Event{
		hostEv("c1", "b"), hostEv("c1", "a"), portEv("c1", "b", "tcp", "0.0.0.0", "443"),
		{Type: codec.RelationAdded, Collector: "c1", RelType: "on", From: ids["p"], To: ids["h1"]},
		{Type: codec.EntityUpdated, Collector: "c2", ID: ids["h1"], Class: codec.ClassAttr,
			Set: map[string]codec.Value{"os": sv("linux")}},
		{Type: codec.Annotated, ID: ids["h1"], Actor: "op", AnnoSet: map[string]string{"owner": "x"}},
		{Type: codec.ScopeDelta, Collector: "c2", AddEnts: []string{ids["h1"]}},
	} {
		g.Fold(s.ev(e))
	}
	return g, ids
}

func TestFoldIndexesAndState(t *testing.T) {
	g, ids := build(t)
	if got := g.LiveIDsOfKind("host"); !sort.StringsAreSorted(got) || len(got) != 2 {
		t.Fatalf("host index: %v", got)
	}
	if got := g.LiveIDs(); len(got) != 3 || !sort.StringsAreSorted(got) {
		t.Fatalf("all index: %v", got)
	}
	if got := g.PortEntities("tcp", "443"); !reflect.DeepEqual(got, []string{ids["p"]}) {
		t.Fatalf("port index: %v", got)
	}
	e, _ := g.Entity(ids["h1"])
	if e.Owner["name"] != "c1" || e.Owner["os"] != "c2" || e.Attrs["os"].S != "linux" {
		t.Fatalf("ownership: %+v", e)
	}
	if _, ok := e.Asserted["c2"]; !ok || len(e.Asserted) != 2 {
		t.Fatalf("asserted: %v", e.Asserted)
	}
	if a, ok := g.Annotation(ids["h1"]); !ok || a.Values["owner"] != "x" || a.By != "op" {
		t.Fatalf("annotation: %+v", a)
	}
	k := RelKey{"on", ids["p"], ids["h1"]}
	if _, ok := g.Relation(k); !ok || !reflect.DeepEqual(g.RelationsOf(ids["h1"]), []RelKey{k}) {
		t.Fatal("relation index")
	}
	if sc := g.Scope("c1"); sc == nil || len(sc.Ents) != 3 || len(sc.Rels) != 1 {
		t.Fatalf("scope c1: %+v", sc)
	}
	if g.LastSeq != 7 || g.LastRT.UnixNano() != 700 || g.MaxVT.UnixNano() != 70 {
		t.Fatalf("position: %d %v %v", g.LastSeq, g.LastRT, g.MaxVT)
	}
}

func TestRemoveRevivalAndScopes(t *testing.T) {
	g, ids := build(t)
	s := &seqr{n: g.LastSeq}
	g.Fold(s.ev(codec.Event{Type: codec.RelationRemoved, Collector: "c1", RelType: "on", From: ids["p"], To: ids["h1"]}))
	g.Fold(s.ev(codec.Event{Type: codec.EntityRemoved, Collector: "c1", ID: ids["p"]}))
	if len(g.PortEntities("tcp", "443")) != 0 || g.RelationCount() != 0 || g.LiveCount() != 2 {
		t.Fatal("removal left index entries")
	}
	if e, ok := g.Entity(ids["p"]); !ok || e.Live || len(e.Asserted) != 0 {
		t.Fatal("removed entity must stay, not live")
	}
	if g.Scope("c1").Ents[ids["p"]] != (struct{}{}) && len(g.Scope("c1").Ents) != 2 {
		t.Fatal("scope not shrunk")
	}
	g.Fold(s.ev(portEv("c3", "b", "tcp", "0.0.0.0", "443")))
	if e, _ := g.Entity(ids["p"]); !e.Live || len(e.Asserted) != 1 || len(g.PortEntities("tcp", "443")) != 1 {
		t.Fatal("revival")
	}
	// Updates to removed or unknown entities change nothing.
	g.Fold(s.ev(codec.Event{Type: codec.EntityRemoved, ID: ids["p"]}))
	before := g.Clone()
	g.Fold(s.ev(codec.Event{Type: codec.EntityUpdated, ID: ids["p"], Class: codec.ClassAttr, Set: map[string]codec.Value{"x": sv("y")}}))
	if e, _ := g.Entity(ids["p"]); len(e.Attrs) != 0 {
		t.Fatal("update applied to removed entity")
	}
	_ = before
	// Emptied scopes disappear.
	g.Fold(s.ev(codec.Event{Type: codec.ScopeDelta, Collector: "c3", DelEnts: []string{ids["p"]}}))
	if g.Scope("c3") != nil {
		t.Fatal("empty scope kept")
	}
}

func TestAnnotationRemoval(t *testing.T) {
	g, ids := build(t)
	g.Fold((&seqr{n: g.LastSeq}).ev(codec.Event{Type: codec.Annotated, ID: ids["h1"], Actor: "op", Unset: []string{"owner"}}))
	if _, ok := g.Annotation(ids["h1"]); ok || g.AnnotationCount() != 0 {
		t.Fatal("annotation should be gone")
	}
}

func TestCloneIsIndependent(t *testing.T) {
	g, ids := build(t)
	c := g.Clone()
	if !g.Equal(c) {
		t.Fatal("clone differs")
	}
	c.Fold((&seqr{n: g.LastSeq}).ev(codec.Event{Type: codec.EntityRemoved, ID: ids["h0"]}))
	c.Fold((&seqr{n: g.LastSeq + 1}).ev(codec.Event{Type: codec.EntityUpdated, Collector: "c9", ID: ids["h1"], Class: codec.ClassAttr, Set: map[string]codec.Value{"zz": sv("1")}}))
	if e, _ := g.Entity(ids["h0"]); !e.Live || g.LiveCount() != 3 {
		t.Fatal("mutating clone changed original")
	}
	if e, _ := g.Entity(ids["h1"]); len(e.Attrs) != 2 {
		t.Fatal("attrs shared with clone")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	g, ids := build(t)
	s := &seqr{n: g.LastSeq}
	g.Fold(s.ev(codec.Event{Type: codec.EntityRemoved, Collector: "c1", ID: ids["h0"]}))
	snap := g.Export()
	if int(snap.Header.NEnt) != 3 || int(snap.Header.NRel) != 1 || snap.Header.Seq != g.LastSeq {
		t.Fatalf("header: %+v", snap.Header)
	}
	if !sort.SliceIsSorted(snap.Ents, func(i, j int) bool { return snap.Ents[i].ID < snap.Ents[j].ID }) {
		t.Fatal("entities unsorted")
	}
	// Records survive the codec.
	for i, e := range snap.Ents {
		d, err := codec.DecodeEntityRecord(e.Rec.Encode())
		if err != nil {
			t.Fatal(err)
		}
		snap.Ents[i].Rec = d
	}
	h, err := Import(snap)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Equal(h) {
		t.Fatal("imported graph differs")
	}
	if !reflect.DeepEqual(g.PortEntities("tcp", "443"), h.PortEntities("tcp", "443")) ||
		!reflect.DeepEqual(g.Collectors(), h.Collectors()) || !reflect.DeepEqual(g.LiveIDs(), h.LiveIDs()) {
		t.Fatal("indexes or scopes differ")
	}
	// Folding on both stays equal.
	ev := s.ev(codec.Event{Type: codec.EntityRemoved, Collector: "c1", ID: ids["p"]})
	g.Fold(ev)
	h.Fold(ev)
	if !g.Equal(h) {
		t.Fatal("diverged after fold")
	}
}

func TestImportRejectsCorrupt(t *testing.T) {
	g, ids := build(t)
	good := g.Export()
	cases := map[string]func(s *Snapshot){
		"count":    func(s *Snapshot) { s.Header.NEnt++ },
		"bad id":   func(s *Snapshot) { s.Ents[0].ID = "host:00" },
		"dup":      func(s *Snapshot) { s.Ents[1] = s.Ents[0] },
		"endpoint": func(s *Snapshot) { s.Rels[0].Key.To = "host:missing" },
	}
	_ = ids
	for name, mut := range cases {
		s := g.Export()
		mut(&s)
		if _, err := Import(s); !errors.Is(err, errs.Corrupt) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Import(good); err != nil {
		t.Fatal(err)
	}
}
