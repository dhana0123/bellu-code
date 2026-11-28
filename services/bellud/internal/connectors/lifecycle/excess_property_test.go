package lifecycle

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"pgregory.net/rapid"
)

// grant is one granted permission with the independent oracle's verdict.
type grant struct {
	op    manifest.Operation
	write bool
}

func genGrant() *rapid.Generator[grant] {
	return rapid.Custom(func(t *rapid.T) grant {
		if rapid.Bool().Draw(t, "aws") {
			readVerbs := []string{"Describe", "List", "Get", "Head", "Simulate", "Lookup", "Search"}
			writeVerbs := []string{"Put", "Create", "Delete", "Update", "Attach", "Run", "*"}
			svc := rapid.SampledFrom([]string{"s3", "iam", "ec2", "lambda"}).Draw(t, "svc")
			write := rapid.Bool().Draw(t, "w")
			verbs := readVerbs
			if write {
				verbs = writeVerbs
			}
			verb := rapid.SampledFrom(verbs).Draw(t, "verb")
			suffix := rapid.StringMatching(`([A-Z][A-Za-z]{0,7})?`).Draw(t, "suffix")
			return grant{op: manifest.Operation{Name: svc + ":" + verb + suffix}, write: write}
		}
		method := rapid.SampledFrom([]string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}).Draw(t, "method")
		query := method == "POST" && rapid.Bool().Draw(t, "query")
		path := rapid.StringMatching(`/[a-z]{1,8}`).Draw(t, "path")
		write := !(method == "GET" || method == "HEAD" || method == "OPTIONS" || query)
		return grant{
			op:    manifest.Operation{Name: method + " " + path, Method: method, Path: path, Query: query},
			write: write,
		}
	})
}

// Feature: cloud-connectors, Property 20: Excess permission classification
// Validates: Requirements 2.5, 3.8, 3.9, 4.5, 5.6
func TestPropertyExcessPermissionClassification(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		grants := rapid.SliceOfNDistinct(genGrant(), 0, 12, func(g grant) string { return g.op.Name }).Draw(rt, "grants")

		var want []string
		for _, g := range grants {
			if got := manifest.IsWrite(g.op); got != g.write {
				rt.Fatalf("IsWrite(%+v) = %v, want %v", g.op, got, g.write)
			}
			if g.write {
				want = append(want, g.op.Name)
			}
		}

		f := newMgrFix(t)
		// The provider reports exactly the write-capable grants.
		f.p.perms = func(string) (PermissionReport, error) {
			var off []string
			for _, g := range grants {
				if manifest.IsWrite(g.op) {
					off = append(off, g.op.Name)
				}
			}
			return PermissionReport{WriteOffenders: off}, nil
		}
		c, err := f.m.Create(context.Background(), CreateInput{
			ConnectorID: "ex", Alias: "a", Method: "token",
			Credential: CredentialInput{Secret: []byte("secret-token-prop20")},
		})

		if len(want) == 0 {
			if err != nil {
				rt.Fatalf("empty offenders must pass, got %v", err)
			}
			if c.Status != string(StatusActive) || c.PermissionCheck != store.PermissionOK {
				rt.Fatalf("connection %+v", c)
			}
			if len(f.sup.started) != 1 {
				rt.Fatal("collector must run")
			}
			if _, ok := f.v.get(credRef(c.ID)); !ok {
				rt.Fatal("credential must be kept")
			}
			return
		}

		var te *Error
		if !errors.As(err, &te) || te.Code != CodeExcessPermission {
			rt.Fatalf("err = %v", err)
		}
		if !slices.Equal(te.Offenders, want) {
			rt.Fatalf("offenders = %v, want %v", te.Offenders, want)
		}
		for _, n := range want {
			if !strings.Contains(te.Message, n) && len(te.Message) < MaxMessage {
				rt.Fatalf("message %q does not name %q", te.Message, n)
			}
		}
		if c.Status != string(StatusError) || c.PermissionCheck != store.PermissionExcess {
			rt.Fatalf("connection %+v", c)
		}
		if len(f.sup.started) != 0 {
			rt.Fatal("no collector may run")
		}
		if _, ok := f.v.get(credRef(c.ID)); ok {
			rt.Fatal("credential must be deleted on first verification")
		}
	})
}
