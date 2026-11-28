package issues

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/posture"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

type fakeSrc struct {
	rels  map[string]RelationInfo
	attrs map[string]string
	fs    []findings.Finding
}

func (f fakeSrc) Relation(a, r, b string) (RelationInfo, bool) {
	i, ok := f.rels[a+"|"+r+"|"+b]
	return i, ok
}
func (f fakeSrc) Attrs(string) map[string]string               { return f.attrs }
func (f fakeSrc) Findings(string, []string) []findings.Finding { return f.fs }

var match = posture.Match{RuleID: "tc1", EntityID: "a", Path: []posture.Hop{{EntityID: "a", Relation: "r"}, {EntityID: "b"}}}

func src(conf string, ev ...string) fakeSrc {
	return fakeSrc{
		rels:  map[string]RelationInfo{"a|r|b": {Confidence: conf, Evidence: ev}},
		attrs: map[string]string{"exposure": "internet", "criticality": "5"},
		fs:    []findings.Finding{{ID: "f1", Category: "code_and_dependencies", Details: []byte(`{"cvss":10,"epss":1,"kev":true}`)}},
	}
}

func TestBuilder(t *testing.T) {
	b := &Builder{Src: src(ConfidenceExtracted, "e1")}
	is, err := b.FromMatch(match)
	if err != nil || is.RiskScore < 0 || is.RiskScore > 100 || is.ID == "" {
		t.Fatalf("got %+v, %v", is, err)
	}
	if _, err := (&Builder{Src: src(ConfidenceExtracted)}).FromMatch(match); !errors.Is(err, ErrHopWithoutEvidence) {
		t.Fatalf("no evidence: %v", err)
	}
	if _, err := (&Builder{Src: src(ConfidenceInferred, "e1")}).FromMatch(match); err == nil {
		t.Fatal("inferred hop must be excluded by default")
	}
	is, err = (&Builder{Src: src(ConfidenceInferred, "e1"), IncludeInferred: true}).FromMatch(match)
	if err != nil || !is.Path[0].Inferred || !is.IncludesInferred {
		t.Fatalf("inferred flag: %+v %v", is, err)
	}
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(db)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { now = now.Add(time.Second); return now }
	mk := func(id string, score float64) Issue {
		return Issue{ID: id, Title: "t", RuleID: "r", Severity: findings.SevHigh, RiskScore: score, Category: "code_and_dependencies",
			FindingIDs: []string{"f1"}, Path: []Hop{{EntityID: "a", Relation: "r", Evidence: []string{"e"}}, {EntityID: "b"}}}
	}
	for _, i := range []Issue{mk("i1", 50), mk("i2", 80), mk("i3", 50), mk("i1", 50)} {
		if err := s.Upsert(ctx, i); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.List(ctx, Query{AssetID: "b"})
	if err != nil || len(l) != 3 {
		t.Fatalf("%v %d", err, len(l))
	}
	if l[0].ID != "i2" || l[1].ID != "i1" || l[2].ID != "i3" { // i1 re-upserted last, so newest among equal scores
		t.Fatalf("order %s %s %s", l[0].ID, l[1].ID, l[2].ID)
	}
	if err := s.SetStatus(ctx, "i2", StatusResolved, "u"); err != nil {
		t.Fatal(err)
	}
	g, _ := s.Get(ctx, "i2")
	var n int
	_ = db.DB().QueryRow(`SELECT count(*) FROM audit WHERE action='issue.status_change'`).Scan(&n)
	if g.Status != StatusResolved || n != 1 {
		t.Fatalf("status %s audit %d", g.Status, n)
	}
	if err := s.Upsert(ctx, mk("x", 101)); !errors.Is(err, ErrInvalid) {
		t.Fatal("score bound")
	}
}
