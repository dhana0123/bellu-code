package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

// Feature: bellu-three-graph-security-intelligence, Property 42: Append-only
// evidence and audit, read-only retrieval boundary.
//
// **Validates: Requirements 6.4, 6.10, 7.5, 20.10, 20.11**
func TestProperty42AppendOnlyAndReadOnlyBoundary(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		s, err := Open(ctx, t.TempDir(), "ws1", Options{Migrations: sqlitemigrations.FS})
		if err != nil {
			rt.Fatal(err)
		}
		defer s.Close()
		path := filepath.Join(s.Dir(), DBFileName)

		// Raw driver connection that bypasses the Store (the "sqlite3 path").
		raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
		if err != nil {
			rt.Fatal(err)
		}
		defer raw.Close()
		ro, err := OpenReadOnly(ctx, path)
		if err != nil {
			rt.Fatal(err)
		}
		defer ro.Close()

		// Seed one evidence row, one audit row, and relations in each state.
		seed := []string{
			`INSERT INTO evidence VALUES('ws1','ev:0','k',x'01',zeroblob(32),'l','trusted_source',NULL,'x','x','r')`,
			`INSERT INTO audit(workspace_id,at,actor_kind,action,subject) VALUES('ws1','t','a','b','c')`,
			`INSERT INTO relation_evidence VALUES('ws1','rc','ev:0')`,
			`INSERT INTO relation_evidence VALUES('ws1','rk','ev:0')`,
		}
		for _, q := range seed {
			if _, err := s.DB().Exec(q); err != nil {
				rt.Fatal(err)
			}
		}
		states := map[string]string{"rh": "hypothesis", "rc": "candidate", "rk": "candidate"}
		for id, st := range states {
			if _, err := s.DB().Exec(`INSERT INTO relation(workspace_id,id,type,from_id,to_id,state,confidence,method,recorded_at,valid_from,observed_at,source_revision)
				VALUES('ws1',?,'t','a','b','hypothesis',0.5,'static','x','2024-01-01','x','r')`, id); err != nil {
				rt.Fatal(err)
			}
			if st == "candidate" {
				if _, err := s.DB().Exec(`UPDATE relation SET state='candidate' WHERE id=?`, id); err != nil {
					rt.Fatal(err)
				}
			}
		}
		if _, err := s.DB().Exec(`UPDATE relation SET state='confirmed' WHERE id='rk'`); err != nil {
			rt.Fatal(err)
		}
		if _, err := s.DB().Exec(`INSERT INTO relation(workspace_id,id,type,from_id,to_id,state,confidence,method,recorded_at,valid_from,observed_at,source_revision)
			VALUES('ws1','rl','t','a','b','hypothesis',0.5,'llm','x','2024-01-01','x','r')`); err != nil {
			rt.Fatal(err)
		}

		snapshot := func() string {
			var out string
			for _, q := range []string{
				`SELECT coalesce(group_concat(id||kind||hex(content)||locator,'|'),'') FROM (SELECT * FROM evidence ORDER BY id)`,
				`SELECT coalesce(group_concat(seq||at||actor_kind||action||subject||coalesce(detail,''),'|'),'') FROM (SELECT * FROM audit ORDER BY seq)`,
				`SELECT coalesce(group_concat(id||state||method,'|'),'') FROM (SELECT * FROM relation ORDER BY id)`,
			} {
				var v string
				if err := s.DB().QueryRow(q).Scan(&v); err != nil {
					rt.Fatal(err)
				}
				out += v + "#"
			}
			return out
		}

		type op struct {
			name string
			sql  string
		}
		opGen := rapid.Custom(func(rt *rapid.T) op {
			col := rapid.SampledFrom([]string{"kind", "locator", "trust", "content"}).Draw(rt, "col")
			val := rapid.StringMatching(`[a-z]{1,6}`).Draw(rt, "val")
			switch rapid.IntRange(0, 7).Draw(rt, "op") {
			case 0:
				if col == "trust" || col == "content" {
					col = "kind"
				}
				return op{"evidence update", fmt.Sprintf(`UPDATE evidence SET %s='%s'`, col, val)}
			case 1:
				return op{"evidence delete", `DELETE FROM evidence`}
			case 2:
				return op{"audit update", fmt.Sprintf(`UPDATE audit SET action='%s'`, val)}
			case 3:
				return op{"audit delete", `DELETE FROM audit`}
			case 4:
				return op{"llm confirmed insert", fmt.Sprintf(`INSERT INTO relation(workspace_id,id,type,from_id,to_id,state,confidence,method,recorded_at,valid_from,observed_at,source_revision)
					VALUES('ws1','n%s','t','a','b','confirmed',0.5,'llm','x','2024-01-01','x','r')`, val)}
			case 5:
				// Make an llm relation confirmed via update.
				return op{"llm confirmed update", `UPDATE relation SET state='confirmed' WHERE id='rl'`}
			case 6:
				// Illegal transitions only: from candidate or confirmed back
				// to an earlier state.
				if rapid.Bool().Draw(rt, "fromConfirmed") {
					return op{"confirmed regress", fmt.Sprintf(`UPDATE relation SET state='%s' WHERE id='rk'`,
						rapid.SampledFrom([]string{"hypothesis", "candidate"}).Draw(rt, "to"))}
				}
				return op{"candidate regress", `UPDATE relation SET state='hypothesis' WHERE id='rc'`}
			default:
				return op{"hypothesis to confirmed", `UPDATE relation SET state='confirmed' WHERE id='rh'`}
			}
		})

		before := snapshot()
		ops := rapid.SliceOfN(opGen, 1, 12).Draw(rt, "ops")
		for _, o := range ops {
			for connName, db := range map[string]*sql.DB{"store": s.DB(), "raw": raw} {
				if _, err := db.Exec(o.sql); err == nil {
					rt.Fatalf("%s on %s connection succeeded: %s", o.name, connName, o.sql)
				}
			}
			// Read-only connection rejects every write statement.
			if _, err := ro.Exec(o.sql); err == nil {
				rt.Fatalf("%s succeeded on read-only connection", o.name)
			}
			if _, err := ro.Exec(`INSERT INTO audit(workspace_id,at,actor_kind,action,subject) VALUES('ws1','t','a','b','c')`); err == nil {
				rt.Fatal("audit insert succeeded on read-only connection")
			}
		}
		if after := snapshot(); after != before {
			rt.Fatalf("rows changed:\nbefore=%s\nafter=%s", before, after)
		}
		// Appending is still allowed and keeps earlier rows intact.
		if _, err := raw.Exec(`INSERT INTO audit(workspace_id,at,actor_kind,action,subject) VALUES('ws1','t2','a','b','c')`); err != nil {
			rt.Fatal(err)
		}
	})
}
