package connectors

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/github"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

func genRepos(t *rapid.T, n int) []string {
	repos := make([]string, n)
	for i := range repos {
		repos[i] = fmt.Sprintf("owner%d/repo%d", rapid.IntRange(0, 9).Draw(t, "o"), i)
	}
	return repos
}

// Feature: github-app-signin, Property 32: Selection bounds and the required message
//
// ValidateSelection accepts a list of owner/name entries if and only if it has
// between 1 and MaxSelection entries.
//
// **Validates: Requirements 5.4, 5.6**
func TestProperty32SelectionBoundsValidate(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var n int
		switch rapid.IntRange(0, 2).Draw(t, "kind") {
		case 0:
			n = rapid.IntRange(0, 3).Draw(t, "small")
		case 1:
			n = rapid.IntRange(github.MaxSelection-2, github.MaxSelection+3).Draw(t, "edge")
		default:
			n = rapid.IntRange(0, github.MaxSelection+50).Draw(t, "any")
		}
		err := github.ValidateSelection(genRepos(t, n))
		want := n >= 1 && n <= github.MaxSelection
		if want != (err == nil) {
			t.Fatalf("n=%d accepted=%v want %v (err %v)", n, err == nil, want, err)
		}
		if err != nil {
			var le *lifecycle.Error
			if !asErr(err, &le) || le.Code != lifecycle.CodeValidationFailed {
				t.Fatalf("n=%d: want validation_failed, got %v", n, err)
			}
			if n == 0 && !strings.Contains(err.Error(), "select at least one repository") {
				t.Fatalf("empty selection message: %v", err)
			}
		}
	})
}

// A rejected selection update leaves the stored selection unchanged.
//
// **Validates: Requirements 5.4, 5.6**
func TestProperty32RejectedSelectionLeavesStoredUnchanged(t *testing.T) {
	ctx := context.Background()
	src := &memSource{slots: map[string][]byte{}}
	s := newSvc(t, t.TempDir(), src, testEngine(t), ghTransport{})
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	conn, err := s.Create(ctx, CreateInput{
		ConnectorID: "github", Alias: "main", Method: "pat",
		Params:     map[string]string{"repos": "octo/hello"},
		Credential: map[string]string{"token": "github_pat_" + strings.Repeat("a", 30)},
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := func() []string {
		c, ok := s.Connection(conn.ID)
		if !ok {
			t.Fatal("connection missing")
		}
		return c.Selection.Repos
	}
	rapid.Check(t, func(t *rapid.T) {
		before := append([]string(nil), stored()...)
		n := rapid.SampledFrom([]int{0, 1, 2, github.MaxSelection, github.MaxSelection + 1, github.MaxSelection + 7}).Draw(t, "n")
		repos := genRepos(t, n)
		err := s.Update(ctx, conn.ID, lifecycle.ConnectionPatch{Selection: &store.Selection{Repos: repos}})
		valid := n >= 1 && n <= github.MaxSelection
		if valid {
			if err != nil {
				t.Fatalf("n=%d rejected: %v", n, err)
			}
			if !reflect.DeepEqual(stored(), repos) {
				t.Fatalf("n=%d accepted but not stored", n)
			}
			return
		}
		if err == nil {
			t.Fatalf("n=%d accepted, want rejection", n)
		}
		if after := stored(); !reflect.DeepEqual(after, before) {
			t.Fatalf("n=%d rejected but stored selection changed: %v -> %v", n, before, after)
		}
	})
}
