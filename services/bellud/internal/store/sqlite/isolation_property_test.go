package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
	"pgregory.net/rapid"
)

// Feature: bellu-three-graph-security-intelligence, Property 49: Workspace
// isolation by directory.
//
// **Validates: Requirements 18.2, 18.3, 20.2**

// dirState captures names, modes, sizes and contents of every entry under dir.
func dirState(t *rapid.T, dir string) string {
	var out string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out += fmt.Sprintf("%s|%v|%d|", rel, info.Mode(), info.Size())
		if !info.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out += fmt.Sprintf("%x", b)
		}
		out += "\n"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWorkspaceIsolationByDirectoryProperty(t *testing.T) {
	ctx := context.Background()
	rapid.Check(t, func(t *rapid.T) {
		root, err := os.MkdirTemp("", "iso")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(root)

		idGen := rapid.StringMatching(`[A-Za-z0-9][A-Za-z0-9._-]{0,15}`)
		idA := idGen.Draw(t, "idA")
		idB := idGen.Filter(func(s string) bool { return s != idA }).Draw(t, "idB")
		if idA == "." || idA == ".." || idB == "." || idB == ".." {
			t.Skip()
		}

		a, err := Open(ctx, root, idA, Options{Migrations: sqlitemigrations.FS})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		b, err := Open(ctx, root, idB, Options{Migrations: sqlitemigrations.FS})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()

		if a.Dir() == b.Dir() {
			t.Fatalf("workspaces share a directory: %s", a.Dir())
		}
		// Modes 0700 for directories and 0600 for database files.
		for _, d := range []string{a.Dir(), b.Dir()} {
			if m := mustStat(t, d).Mode().Perm(); m != 0o700 {
				t.Fatalf("dir %s mode %o", d, m)
			}
		}
		before := dirState(t, b.Dir())

		insert := func(id string) func(tx *sql.Tx) error {
			return func(tx *sql.Tx) error {
				_, err := tx.Exec(`INSERT INTO audit(workspace_id,at,actor_kind,action,subject) VALUES(?,?,?,?,?)`,
					id, "2024-01-01T00:00:00Z", "system", "x", "y")
				return err
			}
		}
		n := rapid.IntRange(1, 5).Draw(t, "ownWrites")
		for i := 0; i < n; i++ {
			if err := a.Write(ctx, idA, insert(idA)); err != nil {
				t.Fatal(err)
			}
		}
		m := rapid.IntRange(1, 5).Draw(t, "foreignWrites")
		for i := 0; i < m; i++ {
			if err := a.Write(ctx, idB, insert(idB)); !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("foreign write err=%v", err)
			}
		}

		var total, own int
		if err := a.DB().QueryRow(`SELECT count(*), coalesce(sum(workspace_id = ?), 0) FROM audit`, idA).Scan(&total, &own); err != nil {
			t.Fatal(err)
		}
		if total != n || own != n {
			t.Fatalf("rows total=%d own=%d want %d", total, own, n)
		}
		if got := dirState(t, b.Dir()); got != before {
			t.Fatalf("workspace %q changed files in %q", idA, idB)
		}

		for _, d := range []string{a.Dir(), b.Dir()} {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				fi, err := os.Stat(filepath.Join(d, DBFileName+suffix))
				if err != nil {
					continue
				}
				if fi.Mode().Perm() != 0o600 {
					t.Fatalf("%s%s mode %o", d, suffix, fi.Mode().Perm())
				}
			}
		}
	})
}

func mustStat(t *rapid.T, p string) os.FileInfo {
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}
