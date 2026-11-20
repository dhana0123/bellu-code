package cce

import (
	"context"
	"os"
	"testing"
	"time"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"

	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	"pgregory.net/rapid"
)

// Feature: bellu-three-graph-security-intelligence, Property 6: Relation id determinism and idempotence
// **Validates: Requirements 5.5, 5.6**

// relField draws a short non-empty field that includes separator characters,
// so field-boundary ambiguity would show up as an id collision.
func relField() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-c|:0-9]{1,6}`)
}

func TestRelationIDDeterminismProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		typ := relField().Draw(t, "type")
		from := StableID(relField().Draw(t, "from"))
		to := StableID(relField().Draw(t, "to"))
		w := WorkspaceID(relField().Draw(t, "ws"))

		id := NewRelationID(typ, from, to, w)
		if again := NewRelationID(typ, from, to, w); again != id {
			t.Fatalf("id not deterministic: %s vs %s", id, again)
		}
		if len(id) != 64 {
			t.Fatalf("id length %d", len(id))
		}

		// Changing any one component changes the id.
		if NewRelationID(typ+"x", from, to, w) == id ||
			NewRelationID(typ, from+"x", to, w) == id ||
			NewRelationID(typ, from, to+"x", w) == id ||
			NewRelationID(typ, from, to, w+"x") == id {
			t.Fatal("distinct inputs produced the same id")
		}

		// Moving a character across a field boundary must not collide.
		a, b := relField().Draw(t, "a"), relField().Draw(t, "b")
		if NewRelationID(a, StableID(b), to, w) == NewRelationID(a+b, "", to, w) {
			t.Fatal("field boundary ambiguity")
		}
	})
}

func TestRelationInsertIdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "cce-prop")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		ctx := context.Background()
		s, err := sqlite.Open(ctx, dir, string(ws), sqlite.Options{Migrations: sqlitemigrations.FS})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		states := []EdgeState{Hypothesis, Candidate}
		inserts := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Relation {
			return Relation{
				Workspace:  ws,
				Type:       rapid.SampledFrom([]string{"affects", "calls"}).Draw(t, "type"),
				From:       StableID(rapid.SampledFrom([]string{"bid:a", "bid:b"}).Draw(t, "from")),
				To:         StableID(rapid.SampledFrom([]string{"bid:c", "bid:d"}).Draw(t, "to")),
				State:      rapid.SampledFrom(states).Draw(t, "state"),
				Confidence: float64(rapid.IntRange(0, 10).Draw(t, "conf")) / 10,
				Method:     MethodExactID,
				Temporal:   Temporal{RecordedAt: now, ValidFrom: now, ObservedAt: now, SourceRevision: "run:r1"},
			}
		}), 1, 12).Draw(t, "inserts")

		// stored holds the first-written row for each id.
		type row struct {
			state EdgeState
			conf  float64
		}
		stored := map[RelationID]row{}
		for _, rel := range inserts {
			want := NewRelationID(rel.Type, rel.From, rel.To, rel.Workspace)
			_, seen := stored[want]
			res, err := InsertRelation(ctx, s, rel)
			if err != nil {
				t.Fatal(err)
			}
			if res.ID != want || res.AlreadyExists != seen {
				t.Fatalf("got %+v, want id %s exists=%v", res, want, seen)
			}
			if !seen {
				stored[want] = row{rel.State, rel.Confidence}
			}
		}

		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM relation WHERE workspace_id = ?`, string(ws)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != len(stored) {
			t.Fatalf("stored %d rows, want %d", n, len(stored))
		}
		for id, want := range stored {
			var st string
			var conf float64
			if err := s.DB().QueryRow(`SELECT state, confidence FROM relation WHERE workspace_id = ? AND id = ?`,
				string(ws), string(id)).Scan(&st, &conf); err != nil {
				t.Fatal(err)
			}
			if EdgeState(st) != want.state || conf != want.conf {
				t.Fatalf("relation %s changed: %s %v, want %s %v", id, st, conf, want.state, want.conf)
			}
		}
	})
}
