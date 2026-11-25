package dataclass

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func TestBuiltinClassify(t *testing.T) {
	p, errs := Load("")
	if len(errs) != 0 {
		t.Fatalf("builtin errors: %v", errs)
	}
	cases := []struct {
		s    Store
		want []string
	}{
		{Store{Name: "prod-customer-email-export"}, []string{ClassPII}},
		{Store{Name: "data", Tags: map[string]string{"data-classification": "PHI"}}, []string{ClassHealth}},
		{Store{Name: "x", Schema: []string{"id", "card_number", "password"}}, []string{ClassCredentials, ClassFinancial}},
		{Store{Name: "static-assets", Tags: map[string]string{"env": "prod"}}, []string{ClassNone}},
	}
	for _, c := range cases {
		if got := p.Classify(c.s); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%+v: got %v want %v", c.s, got, c.want)
		}
	}
}

func TestBadAndSlowPatternsExcluded(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "u.yaml"), []byte(`patterns:
  - {id: ok, class: pii, field: name, regex: 'zebra'}
  - {id: bad, class: pii, field: name, regex: '(['}
  - {id: badclass, class: secret, regex: 'x'}
`), 0o600)
	p, errs := Load(dir)
	if len(errs) != 2 || errs[0].ID != "bad" || errs[1].ID != "badclass" {
		t.Fatalf("errs: %v", errs)
	}
	if got := p.Classify(Store{Name: "zebra-store"}); !reflect.DeepEqual(got, []string{ClassPII}) {
		t.Fatalf("user pattern: %v", got)
	}
	if got := p.Classify(Store{Name: "payment-db"}); !reflect.DeepEqual(got, []string{ClassFinancial}) {
		t.Fatalf("builtin still applies: %v", got)
	}
}

func TestSlowPatternRejected(t *testing.T) {
	// A zero limit makes any evaluation too slow; it drives the same check Load uses.
	if _, err := build(spec{ID: "s", Class: ClassPII, Regex: `[a-z ]{1,1000}q`}, time.Nanosecond); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("want slow rejection, got %v", err)
	}
	if _, err := build(spec{ID: "s", Class: ClassPII, Regex: `abc`}, time.Second); err != nil {
		t.Fatal(err)
	}
}

type sink struct{ errs []string }

func (s *sink) Findings([]findings.Finding) error { return nil }
func (s *sink) ScannerError(in, _ string) error   { s.errs = append(s.errs, in); return nil }
func (s *sink) Seen(string)                       {}
func (s *sink) Batch(batch.Batch) error           { return nil }

type fixed []Store

func (f fixed) Stores(context.Context, string) ([]Store, error) { return f, nil }

func TestRunStoresAndDropsStale(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res := NewResults(db)
	out := &sink{}
	tgt := scanners.Target{Type: scanners.TargetCloudAccount, ID: "conn1"}
	a := New(fixed{{ID: "e1", Type: "s3:bucket", Name: "patient-records"}, {ID: "e2", Type: "s3:bucket", Name: "logs"}}, res, "")
	if err := a.Run(ctx, tgt, out); err != nil {
		t.Fatal(err)
	}
	if c, ok, _ := res.Classes(ctx, "e1"); !ok || !reflect.DeepEqual(c, []string{ClassHealth}) {
		t.Fatalf("e1: %v %v", c, ok)
	}
	if c, _, _ := res.Classes(ctx, "e2"); !reflect.DeepEqual(c, []string{ClassNone}) {
		t.Fatalf("e2: %v", c)
	}
	if err := New(fixed{{ID: "e1", Type: "s3:bucket", Name: "logs"}}, res, "").Run(ctx, tgt, out); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := res.Classes(ctx, "e2"); ok {
		t.Fatal("e2 should be dropped")
	}
	if c, _, _ := res.Classes(ctx, "e1"); !reflect.DeepEqual(c, []string{ClassNone}) {
		t.Fatalf("e1 updated: %v", c)
	}
}
