package findings

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

const appendOnlyMsg = "finding_event is append-only"

type eventRow struct {
	Seq         int64
	WorkspaceID string
	FindingID   string
	At          string
	Actor       string
	Prev        sql.NullString
	New         string
	Reason      sql.NullString
}

func eventSnapshot(rt *rapid.T, db *sql.DB) []eventRow {
	rows, err := db.Query(`SELECT seq, workspace_id, finding_id, at, actor, prev_status, new_status, reason
		FROM finding_event ORDER BY seq`)
	if err != nil {
		rt.Fatal(err)
	}
	defer rows.Close()
	out := []eventRow{}
	for rows.Next() {
		var r eventRow
		if err := rows.Scan(&r.Seq, &r.WorkspaceID, &r.FindingID, &r.At, &r.Actor, &r.Prev, &r.New, &r.Reason); err != nil {
			rt.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		rt.Fatal(err)
	}
	return out
}

// Feature: bellu-wiz-security-platform, Property 6: Finding audit events are append-only. For any sequence of finding_event rows and any attempted UPDATE or DELETE against an existing row, the operation is rejected and the table's contents are unchanged after the attempt.
// **Validates: Requirements 3.12**
func TestPropertyFindingEventAppendOnly(t *testing.T) {
	ctx := context.Background()
	statuses := []Status{StatusOpen, StatusInProgress, StatusResolved, StatusIgnored, StatusAcceptedRisk}
	textCols := []string{"workspace_id", "finding_id", "at", "actor", "prev_status", "new_status", "reason"}
	nullable := map[string]bool{"prev_status": true, "reason": true}

	rapid.Check(t, func(rt *rapid.T) {
		s, db, _ := newStore(t)
		raw := db.DB()
		str := rapid.StringN(0, 12, 40)

		// Build history: real Store usage and direct INSERTs, interleaved.
		nFindings := rapid.IntRange(0, 4).Draw(rt, "findings")
		for i := 0; i < nFindings; i++ {
			id := fmt.Sprintf("f%d", i)
			if _, err := s.Report(ctx, ScanRef{JobID: "j"}, []Finding{sample(id)}); err != nil {
				rt.Fatal(err)
			}
			for _, to := range rapid.SliceOfN(rapid.SampledFrom(statuses), 0, 4).Draw(rt, "transitions") {
				// Disallowed transitions are rejected by the Store; only accepted ones add events.
				_ = s.SetStatus(ctx, id, to, Actor{ID: "u1"}, "because", nil)
			}
		}
		nDirect := rapid.IntRange(0, 6).Draw(rt, "direct")
		for i := 0; i < nDirect; i++ {
			_, err := raw.Exec(`INSERT INTO finding_event (workspace_id, finding_id, at, actor, prev_status, new_status, reason)
				VALUES (?,?,?,?,?,?,?)`, "ws1", str.Draw(rt, "fid"), str.Draw(rt, "at"), str.Draw(rt, "actor"),
				rapid.SampledFrom(statuses).Draw(rt, "prev"), rapid.SampledFrom(statuses).Draw(rt, "new"), nil)
			if err != nil {
				rt.Fatal(err)
			}
		}
		before := eventSnapshot(rt, raw)
		if len(before) == 0 {
			// Guarantee at least one row to target.
			if _, err := raw.Exec(`INSERT INTO finding_event (workspace_id, finding_id, at, actor, new_status) VALUES ('ws1','x','t','a','open')`); err != nil {
				rt.Fatal(err)
			}
			before = eventSnapshot(rt, raw)
		}
		seqs := make([]int64, len(before))
		for i, r := range before {
			seqs[i] = r.Seq
		}

		// Random WHERE targeting one row, a subset, or all rows.
		var where string
		var whereArgs []any
		switch rapid.IntRange(0, 2).Draw(rt, "scope") {
		case 0:
			where, whereArgs = ` WHERE seq = ?`, []any{rapid.SampledFrom(seqs).Draw(rt, "seq")}
		case 1:
			sub := rapid.SliceOfNDistinct(rapid.SampledFrom(seqs), 1, len(seqs), func(v int64) int64 { return v }).Draw(rt, "subset")
			ph := make([]string, len(sub))
			for i, v := range sub {
				ph[i] = "?"
				whereArgs = append(whereArgs, v)
			}
			where = ` WHERE seq IN (` + strings.Join(ph, ",") + `)`
		default:
			if rapid.Bool().Draw(rt, "explicitAll") {
				where = ` WHERE 1=1`
			}
		}

		var stmt string
		var args []any
		if rapid.Bool().Draw(rt, "isUpdate") {
			cols := rapid.SliceOfNDistinct(rapid.SampledFrom(append([]string{"seq"}, textCols...)), 1, 8,
				func(c string) string { return c }).Draw(rt, "cols")
			sets := make([]string, len(cols))
			for i, c := range cols {
				sets[i] = c + " = ?"
				switch {
				case c == "seq":
					args = append(args, rapid.Int64Range(1000, 100000).Draw(rt, "newseq"))
				case nullable[c] && rapid.Bool().Draw(rt, "null"):
					args = append(args, nil)
				default:
					args = append(args, str.Draw(rt, c))
				}
			}
			stmt = `UPDATE finding_event SET ` + strings.Join(sets, ", ") + where
		} else {
			stmt = `DELETE FROM finding_event` + where
		}
		args = append(args, whereArgs...)

		check := func(err error, how string) {
			if err == nil || !strings.Contains(err.Error(), appendOnlyMsg) {
				rt.Fatalf("%s: %q expected append-only error, got %v", how, stmt, err)
			}
			if after := eventSnapshot(rt, raw); !reflect.DeepEqual(before, after) {
				rt.Fatalf("%s: %q changed finding_event\nbefore=%+v\nafter=%+v", how, stmt, before, after)
			}
		}

		// Direct statement.
		_, err := raw.Exec(stmt, args...)
		check(err, "direct")

		// Inside a transaction through the single writer. A prior INSERT in the same
		// transaction must roll back with the failed statement.
		err = db.Write(ctx, "ws1", func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO finding_event (workspace_id, finding_id, at, actor, new_status) VALUES ('ws1','tx','t','a','open')`); err != nil {
				return err
			}
			_, err := tx.Exec(stmt, args...)
			return err
		})
		check(err, "writer")

		// INSERT still works and appends exactly one row after the originals.
		res, err := raw.Exec(`INSERT INTO finding_event (workspace_id, finding_id, at, actor, new_status) VALUES ('ws1','new','t','a','open')`)
		if err != nil {
			rt.Fatalf("insert after rejected attempts: %v", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			rt.Fatalf("insert affected %d rows", n)
		}
		after := eventSnapshot(rt, raw)
		if len(after) != len(before)+1 || !reflect.DeepEqual(before, after[:len(before)]) {
			rt.Fatalf("insert did not append cleanly: before=%+v after=%+v", before, after)
		}
	})
}
