package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// Exact error text for Requirement 3.10: the message names the invalid field.
func TestSetStatusRejectionMessages(t *testing.T) {
	ctx := context.Background()
	s, db, c := newStore(t)
	if _, err := s.Report(ctx, ScanRef{}, []Finding{sample("a")}); err != nil {
		t.Fatal(err)
	}
	user := Actor{ID: "u1"}
	past := c.t.Add(-time.Minute)
	cases := []struct {
		name    string
		to      Status
		reason  string
		expires *time.Time
		want    string
	}{
		{"empty reason ignored", StatusIgnored, "", nil, "findings: invalid reason: required for ignored"},
		{"blank reason accepted_risk", StatusAcceptedRisk, " \t\n", nil, "findings: invalid reason: required for accepted_risk"},
		{"expiry in the past", StatusIgnored, "ok", &past, "findings: invalid expires: must be in the future"},
		{"expiry equal to now", StatusAcceptedRisk, "ok", &c.t, "findings: invalid expires: must be in the future"},
		{"reason over 1024", StatusIgnored, strings.Repeat("x", MaxReason+1), nil, "findings: invalid reason: longer than 1024"},
		{"expiry on a non-snooze status", StatusInProgress, "", func() *time.Time { x := c.t.Add(time.Hour); return &x }(), "findings: invalid expires: applies only to ignored and accepted_risk"},
	}
	for _, tc := range cases {
		err := s.SetStatus(ctx, "a", tc.to, user, tc.reason, tc.expires)
		var inv *InvalidError
		if !errors.As(err, &inv) || !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: want InvalidError, got %v", tc.name, err)
		}
		if err.Error() != tc.want {
			t.Fatalf("%s: message %q, want %q", tc.name, err.Error(), tc.want)
		}
	}
	f, ev, err := s.Get(ctx, "a")
	if err != nil || f.Status != StatusOpen || len(ev) != 1 {
		t.Fatalf("finding changed by rejected calls: %s %d %v", f.Status, len(ev), err)
	}
	if n := count(t, db, `SELECT count(*) FROM audit WHERE action='finding.status_change'`); n != 0 {
		t.Fatalf("audit rows after rejections: %d", n)
	}
}

// Requirement 3.1: 0 to 50 evidence references per Finding.
func TestEvidenceCap(t *testing.T) {
	ctx := context.Background()
	refs := func(n int) []EvidenceRef {
		out := make([]EvidenceRef, n)
		for i := range out {
			out[i] = EvidenceRef{Kind: "file", Ref: fmt.Sprintf("p%d", i)}
		}
		return out
	}
	s, db, _ := newStore(t)

	ok := sample("ok50")
	ok.Evidence = refs(MaxEvidence)
	if _, err := s.Report(ctx, ScanRef{}, []Finding{ok}); err != nil {
		t.Fatalf("50 refs rejected: %v", err)
	}
	if got, _, _ := s.Get(ctx, "ok50"); len(got.Evidence) != 50 {
		t.Fatalf("stored %d refs, want 50", len(got.Evidence))
	}

	bad := sample("bad51")
	bad.Evidence = refs(MaxEvidence + 1)
	res, err := s.Report(ctx, ScanRef{}, []Finding{bad})
	var inv *InvalidError
	if !errors.As(err, &inv) || inv.Field != "evidence_refs" {
		t.Fatalf("want InvalidError on evidence_refs, got %v", err)
	}
	if err.Error() != "findings: invalid evidence_refs: more than 50 references" {
		t.Fatalf("message %q", err.Error())
	}
	if res.Created != 0 {
		t.Fatalf("created %d", res.Created)
	}
	if n := count(t, db, `SELECT count(*) FROM finding WHERE id='bad51'`); n != 0 {
		t.Fatalf("over-cap finding stored")
	}

	// An over-cap Finding on an existing id leaves the stored evidence alone.
	bad.ID = "ok50"
	if _, err := s.Report(ctx, ScanRef{}, []Finding{bad}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	if got, _, _ := s.Get(ctx, "ok50"); len(got.Evidence) != 50 {
		t.Fatalf("evidence changed to %d refs", len(got.Evidence))
	}
}

// Requirement 3.14, end to end: MapSeverity -> Report -> Get/List.
func TestUnmappedSeverityStoredAndRead(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newStore(t)
	build := func(id, raw string) Finding {
		f := sample(id)
		f.Severity, f.UnmappedSeverity = MapSeverity("grype", raw)
		return f
	}
	// The unmapped finding is first, so a later row proves processing continued.
	res, err := s.Report(ctx, ScanRef{}, []Finding{build("odd", "catastrophic"), build("known", "High")})
	if err != nil || res.Created != 2 {
		t.Fatalf("report: %+v %v", res, err)
	}
	odd, _, _ := s.Get(ctx, "odd")
	known, _, _ := s.Get(ctx, "known")
	if odd.Severity != SevInfo || !odd.UnmappedSeverity {
		t.Fatalf("odd: %s unmapped=%v", odd.Severity, odd.UnmappedSeverity)
	}
	if known.Severity != SevHigh || known.UnmappedSeverity {
		t.Fatalf("known: %s unmapped=%v", known.Severity, known.UnmappedSeverity)
	}
	if n := count(t, db, `SELECT unmapped_severity FROM finding WHERE id='odd'`); n != 1 {
		t.Fatalf("column = %d, want 1", n)
	}
	page, err := s.List(ctx, ListQuery{})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("list: %+v %v", page, err)
	}
	for _, f := range page.Items {
		if f.UnmappedSeverity != (f.ID == "odd") {
			t.Fatalf("list %s unmapped=%v", f.ID, f.UnmappedSeverity)
		}
	}
	// A later report with a mapped severity clears the flag.
	if _, err := s.Report(ctx, ScanRef{}, []Finding{build("odd", "low")}); err != nil {
		t.Fatal(err)
	}
	if odd, _, _ = s.Get(ctx, "odd"); odd.Severity != SevLow || odd.UnmappedSeverity {
		t.Fatalf("after remap: %s unmapped=%v", odd.Severity, odd.UnmappedSeverity)
	}
}

// Requirement 3.18: a failing Redactor drops the excerpt, stores the Finding,
// writes a scanner_error row and keeps no unredacted text anywhere.
func TestRedactionFailureRetainsNoUnredactedText(t *testing.T) {
	ctx := context.Background()
	const leak = "AKIAIOSFODNN7EXAMPLE-hunter2"
	s, db, _ := newStore(t, WithRedactor(func(string) (string, error) { return "", errors.New("redactor down") }))
	f := sample("a")
	f.Evidence = []EvidenceRef{{Kind: "file", Ref: "cfg.env", Line: 3, Excerpt: leak}, {Kind: "entity", Ref: "e1"}}
	res, err := s.Report(ctx, ScanRef{JobID: "j1"}, []Finding{f})
	if err != nil || res.Created != 1 || res.RedactionFailures != 1 {
		t.Fatalf("report: %+v %v", res, err)
	}
	got, _, err := s.Get(ctx, "a")
	if err != nil {
		t.Fatalf("finding not stored: %v", err)
	}
	if len(got.Evidence) != 2 || got.Evidence[0].Excerpt != "" || got.Evidence[0].Ref != "cfg.env" || got.Evidence[0].Line != 3 {
		t.Fatalf("evidence: %+v", got.Evidence)
	}
	var input, cause string
	if err := db.DB().QueryRow(`SELECT input, cause FROM scanner_error WHERE job_id='j1'`).Scan(&input, &cause); err != nil {
		t.Fatalf("scanner_error row: %v", err)
	}
	if input != "finding a evidence[0]" || cause != "redaction_failed: excerpt dropped" {
		t.Fatalf("scanner_error: %q / %q", input, cause)
	}
	for _, q := range []string{
		`SELECT coalesce(group_concat(evidence_refs||body||title||description||revisions, '|'), '') FROM finding`,
		`SELECT coalesce(group_concat(input||cause, '|'), '') FROM scanner_error`,
		`SELECT coalesce(group_concat(coalesce(reason,'')||actor, '|'), '') FROM finding_event`,
	} {
		var all string
		if err := db.DB().QueryRow(q).Scan(&all); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(all, "AKIA") || strings.Contains(all, "hunter2") {
			t.Fatalf("unredacted text stored by %q: %s", q, all)
		}
	}
}

// countingEngine delegates to a real engine and counts Apply calls by the
// findings collector.
type countingEngine struct {
	graph.Engine
	applies atomic.Int64
}

func (e *countingEngine) Ingest() graph.Ingest { return countingIngest{e.Engine.Ingest(), &e.applies} }

type countingIngest struct {
	graph.Ingest
	n *atomic.Int64
}

func (c countingIngest) Apply(ctx context.Context, b graph.Batch) (graph.Receipt, error) {
	r, err := c.Ingest.Apply(ctx, b)
	// Counted after the apply returns so a waiter that sees the count can read the batch.
	if b.Collector == ProjectorCollector {
		c.n.Add(1)
	}
	return r, err
}

func startProjector(t *testing.T, debounce, maxWait time.Duration) (*Store, *countingEngine, graph.Engine, string) {
	t.Helper()
	s, e, asset := projectorFixture(t)
	ce := &countingEngine{Engine: e}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	p := NewProjector(s, ce, WithProjectorTiming(debounce, maxWait, time.Hour))
	go func() { p.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, 2*time.Second, "initial projection", func() bool { return ce.applies.Load() == 1 })
	return s, ce, e, asset
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Requirement 3.16: reports inside the debounce window produce one projection,
// and only after the window closes.
func TestProjectorDebouncesBurst(t *testing.T) {
	ctx := context.Background()
	s, ce, e, asset := startProjector(t, 300*time.Millisecond, 10*time.Second)
	start := time.Now()
	for i := 0; i < 5; i++ {
		f := sample(fmt.Sprintf("f%d", i))
		f.AssetID = asset
		if _, err := s.Report(ctx, ScanRef{}, []Finding{f}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := ce.applies.Load(); n != 1 {
		t.Fatalf("projected %d times inside the debounce window, want only the initial one", n)
	}
	waitFor(t, 3*time.Second, "debounced projection", func() bool { return ce.applies.Load() == 2 })
	if since := time.Since(start); since < 300*time.Millisecond {
		t.Fatalf("projection after %v, before the debounce elapsed", since)
	}
	time.Sleep(600 * time.Millisecond) // a second projection would show up here
	if n := ce.applies.Load(); n != 2 {
		t.Fatalf("projections = %d, want 2 (initial + one for the burst)", n)
	}
	if n := findingCount(t, e); n != 5 {
		t.Fatalf("findings in graph = %d, want 5", n)
	}
}

// Requirement 3.16: continuous changes cannot postpone projection past the hard bound.
func TestProjectorHardBoundUnderContinuousChanges(t *testing.T) {
	ctx := context.Background()
	s, ce, e, asset := startProjector(t, 250*time.Millisecond, 600*time.Millisecond)
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		// A new finding every 50 ms: the 250 ms quiet period never completes.
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			f := sample(fmt.Sprintf("c%d", i))
			f.AssetID = asset
			if _, err := s.Report(ctx, ScanRef{}, []Finding{f}); err != nil {
				return
			}
		}
	}()
	defer func() { close(stop); <-finished }()
	start := time.Now()
	waitFor(t, 3*time.Second, "projection under continuous changes", func() bool { return ce.applies.Load() >= 2 })
	if since := time.Since(start); since < 500*time.Millisecond || since > 1500*time.Millisecond {
		t.Fatalf("hard-bound projection after %v, want about 600ms", since)
	}
	if n := findingCount(t, e); n < 1 {
		t.Fatalf("findings in graph = %d, want at least 1", n)
	}
}
