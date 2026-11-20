package cce

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func goodTemporal() Temporal {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	return Temporal{RecordedAt: now, ValidFrom: now, ObservedAt: now, SourceRevision: "run:r1"}
}

func TestParseSourceRevision(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for rev, want := range map[string]SourceRevisionKind{
		sha: RevCommit, strings.Repeat("0", 64): RevCommit,
		"snapshot:2024-01-01.1": RevSnapshot, "run:abc_1": RevRun,
	} {
		if got, err := ParseSourceRevision(rev); err != nil || got != want {
			t.Errorf("%q: got %v, %v", rev, got, err)
		}
	}
	for _, rev := range []string{"", "abc", "main", sha + "x", "snapshot:", "run:", "snapshot:a b",
		sha + ",run:r1", sha + " run:r1", "snapshot:a;run:b"} {
		var te *TemporalError
		if _, err := ParseSourceRevision(rev); !errors.As(err, &te) || te.Field != "source_revision" {
			t.Errorf("%q: want source_revision error, got %v", rev, err)
		}
	}
}

func TestValidateTemporal(t *testing.T) {
	base := goodTemporal()
	if err := ValidateTemporal(base); err != nil {
		t.Fatal(err)
	}
	est := time.FixedZone("EST", -5*3600)
	until := func(d time.Duration) *time.Time { u := base.ValidFrom.Add(d); return &u }
	nonUTC := base.ValidFrom.In(est)
	for field, mutate := range map[string]func(*Temporal){
		"valid_from":      func(x *Temporal) { x.ValidFrom = time.Time{} },
		"recorded_at":     func(x *Temporal) { x.RecordedAt = time.Time{} },
		"source_revision": func(x *Temporal) { x.SourceRevision = "" },
	} {
		x := base
		mutate(&x)
		var te *TemporalError
		if err := ValidateTemporal(x); !errors.As(err, &te) || te.Field != field || !errors.Is(err, ErrInvalidTemporal) {
			t.Errorf("%s: got %v", field, err)
		}
	}
	for name, mutate := range map[string]func(*Temporal){
		"valid_from":  func(x *Temporal) { x.ValidFrom = nonUTC },
		"recorded_at": func(x *Temporal) { x.RecordedAt = nonUTC },
		"valid_until": func(x *Temporal) { x.ValidUntil = until(0) },
	} {
		x := base
		mutate(&x)
		if err := ValidateTemporal(x); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	x := base
	x.ValidUntil = until(-time.Second)
	if err := ValidateTemporal(x); err == nil {
		t.Error("valid_until before valid_from accepted")
	}
	x.ValidUntil = until(time.Second)
	if err := ValidateTemporal(x); err != nil {
		t.Error(err)
	}
}

func TestInsertRelationRejectsInvalidTemporalAndStoresNothing(t *testing.T) {
	s := openStore(t)
	rel := Relation{Workspace: ws, Type: "calls", From: "bid:a", To: "bid:b", State: Hypothesis,
		Confidence: 0.4, Method: MethodSemantic, Temporal: goodTemporal()}
	rel.Temporal.ValidFrom = time.Time{}
	if _, err := InsertRelation(context.Background(), s, rel); !errors.Is(err, ErrInvalidTemporal) {
		t.Fatalf("got %v", err)
	}
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM relation`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows=%d err=%v", n, err)
	}
}

func TestEvidenceRejectsInvalidSourceRevision(t *testing.T) {
	es, s := newEvStore(t)
	ev := goodEvidence("x")
	ev.Temporal.SourceRevision = "main"
	_, err := es.Write(context.Background(), ev)
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "source_revision" || evidenceCount(t, s) != 0 {
		t.Fatalf("got %v", err)
	}
}

func TestReadRelationsAsOf(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	d := func(day int) time.Time { return time.Date(2024, 1, day, 0, 0, 0, 0, time.UTC) }
	ptr := func(x time.Time) *time.Time { return &x }
	add := func(to string, from time.Time, until *time.Time, rec time.Time) {
		t.Helper()
		tm := Temporal{RecordedAt: rec, ValidFrom: from, ValidUntil: until, ObservedAt: rec, SourceRevision: "run:r1"}
		if _, err := InsertRelation(ctx, s, Relation{Workspace: ws, Type: "calls", From: "bid:a", To: StableID(to),
			State: Hypothesis, Confidence: 0.5, Method: MethodSemantic, Temporal: tm}); err != nil {
			t.Fatal(err)
		}
	}
	add("bid:open", d(5), nil, d(6))         // valid from day 5, recorded day 6
	add("bid:closed", d(2), ptr(d(5)), d(2)) // valid [2,5)
	add("bid:fraction", d(1), ptr(d(1).Add(500*time.Millisecond)), d(1))

	names := func(at time.Time, known *time.Time) []string {
		t.Helper()
		got, err := ReadRelationsAsOf(ctx, s, AsOfQuery{Workspace: ws, At: at, KnownAt: known})
		if err != nil || got == nil {
			t.Fatalf("got %v, %v", got, err)
		}
		var out []string
		for _, r := range got {
			out = append(out, string(r.To))
		}
		return out
	}
	eq := func(got []string, want ...string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("got %v want %v", got, want)
		}
	}
	eq(names(d(1), nil), "bid:fraction")           // valid_from <= t
	eq(names(d(1).Add(500*time.Millisecond), nil)) // t == valid_until excluded
	eq(names(d(3), nil), "bid:closed")
	eq(names(d(5), nil), "bid:open") // closed ends at 5 exclusive
	eq(names(d(7), nil), "bid:open")
	eq(names(d(5), ptr(d(5)))) // open recorded day 6, unknown on 5
	eq(names(d(7), ptr(d(6))), "bid:open")
	eq(names(d(0+1).Add(-time.Hour), nil)) // before everything: empty, no error

	if _, err := ReadRelationsAsOf(ctx, s, AsOfQuery{Workspace: ws}); !errors.Is(err, ErrInvalidTemporal) {
		t.Errorf("zero as-of: %v", err)
	}
}
