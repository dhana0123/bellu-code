package dataclass

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

const fakeEmail, fakeSSN = "jane.doe@example.com", "123-45-6789"

// fakeS3 serves objects that contain fake PII and honours the limit like the client.
type fakeS3 struct {
	objects []string
	calls   int
	limit   int
	fail    map[string]bool
}

func (f *fakeS3) SampleObjects(_ context.Context, bucket, _ string, limit, maxBytes int, fn func([]byte)) error {
	f.calls++
	f.limit = limit
	if f.fail[bucket] {
		return errors.New("s3:ListObjectsV2: AccessDenied password=hunter2secret")
	}
	for i, o := range f.objects {
		if i >= limit {
			break
		}
		fn([]byte(o[:min(len(o), maxBytes)]))
	}
	return nil
}

type recSink struct{ errs []string }

func (s *recSink) Findings([]findings.Finding) error { return nil }
func (s *recSink) ScannerError(in, cause string) error {
	s.errs = append(s.errs, in+": "+cause)
	return nil
}
func (s *recSink) Seen(string)               {}
func (s *recSink) Batch(b batch.Batch) error { s.errs = append(s.errs, "BATCH"); return nil }

func TestSamplingClassifiesWithoutPersistingContent(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	obj := "name: Jane\nemail " + fakeEmail + "\nssn " + fakeSSN + "\n"
	fs := &fakeS3{objects: []string{obj, obj, obj, obj, obj}, fail: map[string]bool{"broken": true}}
	stores := fixed{
		{ID: "e1", Type: "s3:bucket", Name: "plain-bucket"},
		{ID: "e2", Type: "s3:bucket", Name: "broken"},
		{ID: "e3", Type: "s3:bucket", Name: "optedout"},
	}
	res := NewResults(db)
	out := &recSink{}
	a := New(stores, res, "").WithSampling(Sampling{Reader: fs, Limit: 3, Stores: map[string]bool{"e1": true, "e2": true}})
	if err := a.Run(ctx, scanners.Target{Type: scanners.TargetCloudAccount, ID: "c1"}, out); err != nil {
		t.Fatal(err)
	}
	if fs.calls != 2 || fs.limit != 3 {
		t.Fatalf("calls=%d limit=%d: only opted-in stores are read, with the limit", fs.calls, fs.limit)
	}
	var classes, counts string
	if err := db.DB().QueryRowContext(ctx, `SELECT classes, match_counts FROM data_classification WHERE entity_id='e1'`).Scan(&classes, &counts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(classes, "pii") || counts != `{"pii":6}` { // 3 objects x (email + ssn)
		t.Fatalf("classes=%s counts=%s", classes, counts)
	}
	rows, _ := db.DB().QueryContext(ctx, `SELECT classes || match_counts || entity_id || entity_type FROM data_classification`)
	var all strings.Builder
	for rows.Next() {
		var s string
		rows.Scan(&s)
		all.WriteString(s)
	}
	rows.Close()
	dump := all.String() + strings.Join(out.errs, "\n")
	for _, secret := range []string{fakeEmail, fakeSSN, "Jane", "hunter2secret"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("%q leaked into rows, gaps or batch: %s", secret, dump)
		}
	}
	if len(out.errs) != 1 || !strings.HasPrefix(out.errs[0], "e2: missing_data:") {
		t.Fatalf("want one missing_data gap for e2, got %v", out.errs)
	}
	if c, ok, _ := res.Classes(ctx, "e3"); !ok || c[0] != ClassNone {
		t.Fatalf("e3 still classified from metadata: %v", c)
	}
}

func TestSamplingOffMakesNoReads(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fs := &fakeS3{objects: []string{fakeEmail}}
	a := New(fixed{{ID: "e1", Type: "s3:bucket", Name: "b"}}, NewResults(db), "").
		WithSampling(Sampling{Reader: fs, Limit: 100}) // nothing opted in
	if err := a.Run(ctx, scanners.Target{Type: scanners.TargetCloudAccount, ID: "c1"}, &recSink{}); err != nil {
		t.Fatal(err)
	}
	if err := New(fixed{{ID: "e1", Type: "s3:bucket", Name: "b"}}, NewResults(db), "").Run(ctx, scanners.Target{ID: "c1"}, &recSink{}); err != nil {
		t.Fatal(err)
	}
	if fs.calls != 0 {
		t.Fatalf("reads with sampling off: %d", fs.calls)
	}
}
