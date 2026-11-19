package graph

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
)

// SnapEntity is one entity record with its ID (the record key).
type SnapEntity struct {
	ID  EntityID
	Rec codec.EntityRecord
}

// SnapRel is one relation record with its key.
type SnapRel struct {
	Key RelKey
	Rec codec.RelationRecord
}

// Snapshot is the exported form of a Graph. Ents is sorted by ID and Rels by
// the encoded key type\x00from\x00to, which is the order of the store keys.
// Header.CRC is left zero; the store computes it over the record bytes.
type Snapshot struct {
	Header codec.SnapshotHeader
	Ents   []SnapEntity
	Rels   []SnapRel
}

// RelKeyString is the key suffix type\x00from\x00to used by the store.
func RelKeyString(k RelKey) string { return k.Type + "\x00" + k.From + "\x00" + k.To }

func sortedSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Export returns a deep-copied Snapshot of every entity (live and removed),
// relation and annotation, with Seq, MaxVT and LastRT from the Graph.
func (g *Graph) Export() Snapshot {
	s := Snapshot{
		Header: codec.SnapshotHeader{
			Seq: g.LastSeq, MaxVTNS: toNS(g.MaxVT), LastRTNS: toNS(g.LastRT),
			NEnt: uint32(len(g.ents)), NRel: uint32(len(g.rels)),
		},
		Ents: make([]SnapEntity, 0, len(g.ents)),
		Rels: make([]SnapRel, 0, len(g.rels)),
	}
	for id, e := range g.ents {
		rec := codec.EntityRecord{
			Kind:     e.Kind,
			Identity: copyStrMap(e.Identity),
			Attrs:    copyValues(e.Attrs),
			Owner:    copyStrMap(e.Owner),
			Live:     e.Live,
			Asserted: sortedSet(e.Asserted),
			VTNS:     toNS(e.VT),
			RTNS:     toNS(e.RT),
			Seq:      e.Seq,
		}
		if a := g.ann[id]; a != nil {
			rec.Ann = &codec.Annotation{Values: copyStrMap(a.Values), UpdatedAtNS: toNS(a.UpdatedAt), By: a.By}
		}
		s.Ents = append(s.Ents, SnapEntity{ID: id, Rec: rec})
	}
	sort.Slice(s.Ents, func(i, j int) bool { return s.Ents[i].ID < s.Ents[j].ID })
	for k, r := range g.rels {
		s.Rels = append(s.Rels, SnapRel{Key: k, Rec: codec.RelationRecord{
			Asserted: sortedSet(r.Asserted), VTNS: toNS(r.VT), RTNS: toNS(r.RT), Seq: r.Seq, Attrs: r.Attrs,
		}})
	}
	sort.Slice(s.Rels, func(i, j int) bool { return RelKeyString(s.Rels[i].Key) < RelKeyString(s.Rels[j].Key) })
	return s
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: graph snapshot: %s", errs.Corrupt, fmt.Sprintf(format, a...))
}

// Import builds a Graph from a Snapshot, rebuilding every index and scope.
// It returns an error wrapping errs.Corrupt when the Snapshot is inconsistent:
// counts differ from the header, an ID is duplicated or does not match its
// kind and identity, or a relation lacks a live endpoint. The result shares no
// memory with s.
func Import(s Snapshot) (*Graph, error) {
	if uint64(len(s.Ents)) != uint64(s.Header.NEnt) || uint64(len(s.Rels)) != uint64(s.Header.NRel) {
		return nil, corrupt("record counts %d/%d differ from header %d/%d",
			len(s.Ents), len(s.Rels), s.Header.NEnt, s.Header.NRel)
	}
	g := New()
	for _, se := range s.Ents {
		r := se.Rec
		want, err := ident.Hash(r.Kind, r.Identity)
		if err != nil || want != se.ID {
			return nil, corrupt("entity %q does not match its kind and identity", se.ID)
		}
		if _, dup := g.ents[se.ID]; dup {
			return nil, corrupt("duplicate entity %q", se.ID)
		}
		if !r.Live && len(r.Asserted) > 0 {
			return nil, corrupt("removed entity %q has assertions", se.ID)
		}
		e := &EntityState{
			ID: se.ID, Kind: r.Kind,
			Identity: copyStrMap(r.Identity),
			Attrs:    copyValues(r.Attrs),
			Owner:    copyStrMap(r.Owner),
			Live:     r.Live,
			Asserted: map[string]struct{}{},
			VT:       toTime(r.VTNS), RT: toTime(r.RTNS), Seq: r.Seq,
		}
		if e.Owner == nil {
			e.Owner = map[string]string{}
		}
		g.ents[se.ID] = e
		if e.Live {
			g.indexLive(e)
		}
		for _, c := range r.Asserted {
			if c == "" {
				return nil, corrupt("entity %q has an empty collector", se.ID)
			}
			g.assertEnt(e, c)
		}
		if r.Ann != nil {
			g.ann[se.ID] = &Annotation{
				Values: copyStrMap(r.Ann.Values), UpdatedAt: toTime(r.Ann.UpdatedAtNS), By: r.Ann.By,
			}
		}
	}
	for _, sr := range s.Rels {
		k := sr.Key
		if _, dup := g.rels[k]; dup {
			return nil, corrupt("duplicate relation %q", RelKeyString(k))
		}
		for _, end := range []EntityID{k.From, k.To} {
			if e := g.ents[end]; e == nil || !e.Live {
				return nil, corrupt("relation %q has a missing or removed endpoint", RelKeyString(k))
			}
		}
		r := &RelState{Key: k, Asserted: map[string]struct{}{},
			VT: toTime(sr.Rec.VTNS), RT: toTime(sr.Rec.RTNS), Seq: sr.Rec.Seq, Attrs: sr.Rec.Attrs}
		g.rels[k] = r
		addEdge(g.out, k.From, k)
		addEdge(g.in, k.To, k)
		for _, c := range sr.Rec.Asserted {
			if c == "" {
				return nil, corrupt("relation %q has an empty collector", RelKeyString(k))
			}
			g.assertRel(r, c)
		}
	}
	g.LastSeq = s.Header.Seq
	g.MaxVT = toTime(s.Header.MaxVTNS)
	g.LastRT = toTime(s.Header.LastRTNS)
	return g, nil
}

// Equal reports whether two Graphs hold the same Projection.
func (g *Graph) Equal(o *Graph) bool {
	return reflect.DeepEqual(g.Export(), o.Export())
}
