package findings_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
	"pgregory.net/rapid"
)

var (
	listSpec = listquery.Spec{
		Filters: listquery.AllFilters,
		Sorts:   []string{findings.SortLastSeen, findings.SortFirstSeen, findings.SortSeverity, findings.SortRiskScore},
	}
	listTypes = []findings.Type{findings.TypeVulnerability, findings.TypeMisconfiguration, findings.TypeSecret,
		findings.TypeLicense, findings.TypeMalware, findings.TypeRuntimeThreat, findings.TypeAIRisk,
		findings.TypeDataExposure, findings.TypeIdentityRisk}
	listSeverities = []findings.Severity{findings.SevCritical, findings.SevHigh, findings.SevMedium, findings.SevLow, findings.SevInfo}
	listStatuses   = []findings.Status{findings.StatusOpen, findings.StatusInProgress, findings.StatusResolved, findings.StatusIgnored, findings.StatusAcceptedRisk}
	listAssets     = []string{"a0", "a1", "a2", "a3"}
	listSources    = []string{"grype", "trivy", "gitleaks"}
	listEpoch      = time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
)

// row is the model's view of one stored finding.
type listRow struct {
	id, category, typ, severity, status, asset, source string
	lastSeen                                           time.Time
}

type listClock struct{ t time.Time }

// pick draws 1..3 values from pool (repeats allowed, so repeated query values
// and duplicates are exercised).
func pick[T any](t *rapid.T, label string, pool []T) []T {
	return rapid.SliceOfN(rapid.SampledFrom(pool), 1, 3).Draw(t, label)
}

// Feature: bellu-wiz-security-platform, Property 34: For any list request, a parameter outside its domain SHALL be rejected with HTTP 400 naming the parameter, run no query and leave data unchanged; for any well-formed filters and repeated values, the result SHALL equal the AND across distinct filters of the OR across repeated values.
// **Validates: Requirements 20.3, 20.4**
func TestPropertyListFilterSemantics(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	n := 0
	rapid.Check(t, func(t *rapid.T) {
		n++
		dir, err := os.MkdirTemp(root, "ws")
		if err != nil {
			t.Fatal(err)
		}
		db, err := sqlite.Open(ctx, dir, "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		clk := &listClock{t: listEpoch}
		store := findings.New(db, findings.WithClock(func() time.Time { return clk.t }))
		defer store.Close()

		// Generate rows and store them through the real Report and SetStatus paths.
		var rows []listRow
		count := rapid.IntRange(0, 25).Draw(t, "count")
		for i := range count {
			r := listRow{
				id:       fmt.Sprintf("f%02d", i),
				category: string(rapid.SampledFrom(schema.OverviewOrder[:]).Draw(t, "category")),
				typ:      string(rapid.SampledFrom(listTypes).Draw(t, "type")),
				severity: string(rapid.SampledFrom(listSeverities).Draw(t, "severity")),
				status:   string(rapid.SampledFrom(listStatuses).Draw(t, "status")),
				asset:    rapid.SampledFrom(listAssets).Draw(t, "asset"),
				source:   rapid.SampledFrom(listSources).Draw(t, "source"),
				lastSeen: listEpoch.Add(time.Duration(rapid.IntRange(0, 20).Draw(t, "lastSeen")) * time.Second),
			}
			clk.t = r.lastSeen
			f := findings.Finding{ID: r.id, RuleID: "r1", Title: "t", Category: schema.OverviewCategory(r.category),
				Type: findings.Type(r.typ), Severity: findings.Severity(r.severity), AssetID: r.asset, Source: r.source}
			if _, err := store.Report(ctx, findings.ScanRef{}, []findings.Finding{f}); err != nil {
				t.Fatal(err)
			}
			switch findings.Status(r.status) {
			case findings.StatusOpen:
			case findings.StatusResolved:
				// resolved is reached only by ResolveMissing, which works per (asset, source).
				if _, err := db.DB().ExecContext(ctx, `UPDATE finding SET status='resolved' WHERE id=?`, r.id); err != nil {
					t.Fatal(err)
				}
			default:
				if err := store.SetStatus(ctx, r.id, findings.Status(r.status), findings.Actor{ID: "u1"}, "because", nil); err != nil {
					t.Fatal(err)
				}
			}
			rows = append(rows, r)
		}

		// Random filters, each with 1..3 values, as URL parameters.
		v := url.Values{}
		in := map[string][]string{}
		add := func(name string, vals []string) {
			if rapid.Bool().Draw(t, "use-"+name) {
				v[name] = vals
				in[name] = vals
			}
		}
		add(listquery.Category, pick(t, "categories", categoriesOf()))
		add(listquery.Severity, pick(t, "severities", strs(listSeverities)))
		add(listquery.Status, pick(t, "statuses", strs(listStatuses)))
		add(listquery.Type, pick(t, "types", strs(listTypes)))
		add(listquery.Asset, pick(t, "assets", append(slices.Clone(listAssets), "a-missing")))
		add(listquery.Source, pick(t, "sources", append(slices.Clone(listSources), "other")))
		var from, to *time.Time
		if rapid.Bool().Draw(t, "useFrom") {
			x := listEpoch.Add(time.Duration(rapid.IntRange(-2, 22).Draw(t, "from")) * time.Second)
			from = &x
		}
		if rapid.Bool().Draw(t, "useTo") {
			x := listEpoch.Add(time.Duration(rapid.IntRange(-2, 22).Draw(t, "to")) * time.Second)
			if from != nil && x.Before(*from) {
				x = *from
			}
			to = &x
		}
		if from != nil {
			v.Set(listquery.From, from.Format(time.RFC3339))
		}
		if to != nil {
			v.Set(listquery.To, to.Format(time.RFC3339))
		}
		if rapid.Bool().Draw(t, "useSort") {
			s := rapid.SampledFrom(listSpec.Sorts).Draw(t, "sort")
			if rapid.Bool().Draw(t, "desc") {
				s = "-" + s
			}
			v.Set("sort", s)
		}
		limit := rapid.IntRange(1, 8).Draw(t, "limit")
		v.Set("limit", fmt.Sprint(limit))

		// Model: AND across filters, OR across the values of one filter.
		want := map[string]bool{}
		for _, r := range rows {
			ok := true
			for name, got := range map[string]string{
				listquery.Category: r.category, listquery.Severity: r.severity, listquery.Status: r.status,
				listquery.Type: r.typ, listquery.Asset: r.asset, listquery.Source: r.source,
			} {
				if vals, used := in[name]; used && !slices.Contains(vals, got) {
					ok = false
				}
			}
			if from != nil && r.lastSeen.Before(*from) || to != nil && r.lastSeen.After(*to) {
				ok = false
			}
			if ok {
				want[r.id] = true
			}
		}

		// Page through the real Parse -> ToFindings -> List path.
		got := map[string]bool{}
		pages := 0
		for {
			pages++
			if pages > count+2 {
				t.Fatalf("paging did not terminate after %d pages", pages)
			}
			q, err := listSpec.Parse(v)
			if err != nil {
				t.Fatalf("Parse(%v): %v", v, err)
			}
			fq, err := listquery.ToFindings(q)
			if err != nil {
				t.Fatalf("ToFindings: %v", err)
			}
			page, err := store.List(ctx, fq)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(page.Items) > limit {
				t.Fatalf("page of %d exceeds limit %d", len(page.Items), limit)
			}
			for _, f := range page.Items {
				if got[f.ID] {
					t.Fatalf("duplicate %s across pages (query %v)", f.ID, v)
				}
				got[f.ID] = true
			}
			if page.NextCursor == "" {
				break
			}
			v.Set("cursor", q.NextCursor(page.NextCursor))
		}
		if !mapsEqual(got, want) {
			t.Fatalf("query %v:\n got  %v\n want %v", v, keys(got), keys(want))
		}
	})
}

func categoriesOf() []string {
	out := make([]string, len(schema.OverviewOrder))
	for i, c := range schema.OverviewOrder {
		out[i] = string(c)
	}
	return out
}

func strs[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, x := range in {
		out[i] = string(x)
	}
	return out
}

func mapsEqual(a, b map[string]bool) bool {
	return slices.Equal(keys(a), keys(b))
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
