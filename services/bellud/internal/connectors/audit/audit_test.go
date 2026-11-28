package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func mustOpen(t *testing.T, now *time.Time, days int) (*FileLog, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	l, err := Open(dir, Options{RetentionDays: days, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return l, dir
}

func ent(conn string) Entry {
	return Entry{ConnectionID: conn, ConnectorID: "aws", Event: EventConnect, Outcome: OutcomeSuccess, Actor: ActorUser,
		Detail: map[string]string{"from": "VERIFYING", "to": "ACTIVE"}}
}

func TestAppendModesChainAndRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 13, 7, 54, 52, 123456789, time.UTC)
	l, dir := mustOpen(t, &now, 90)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := l.Append(ctx, ent("c1")); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := os.Stat(dir)
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode().Perm())
	}
	p := filepath.Join(dir, "audit-2026-11-13.jsonl")
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
	lines, _ := readLines(p)
	if len(lines) != 3 {
		t.Fatalf("lines %d", len(lines))
	}
	var e1, e2 Entry
	_ = json.Unmarshal(lines[0], &e1)
	_ = json.Unmarshal(lines[1], &e2)
	if e1.Prev != "" || e2.Prev != hashLine(lines[0]) || e2.Seq != 2 {
		t.Fatalf("bad chain %+v %+v", e1, e2)
	}
	if e1.TS.Nanosecond() != 123000000 {
		t.Fatalf("ts not ms: %v", e1.TS)
	}
	// round trip
	b, _ := json.Marshal(e2)
	var back Entry
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, e2) {
		t.Fatalf("round trip %v %+v", err, back)
	}
	// reopen continues the chain
	l2, err := Open(dir, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Append(ctx, ent("c1"))
	lines, _ = readLines(p)
	var e4 Entry
	_ = json.Unmarshal(lines[3], &e4)
	if e4.Seq != 4 || e4.Prev != hashLine(lines[2]) {
		t.Fatalf("chain not continued %+v", e4)
	}
}

func TestAppendValidation(t *testing.T) {
	now := time.Now()
	l, _ := mustOpen(t, &now, 90)
	bad := ent("c")
	bad.Outcome = "nope"
	if l.Append(context.Background(), bad) == nil {
		t.Fatal("bad outcome accepted")
	}
	bad = ent("c")
	bad.Event = "plugin_x"
	if err := l.Append(context.Background(), bad); err != nil {
		t.Fatal(err)
	}
	bad.Event = "weird"
	if l.Append(context.Background(), bad) == nil {
		t.Fatal("bad event accepted")
	}
}

func TestListPagingFilterAndRetention(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	l, _ := mustOpen(t, &now, 10)
	ctx := context.Background()
	// 120 entries for c1 spread over days, 1 per 2h going back; some for c2
	var want []uint64
	base := now.Add(-300 * time.Hour)
	for i := 0; i < 150; i++ {
		e := ent("c1")
		if i%5 == 0 {
			e.ConnectionID = "c2"
		}
		e.TS = base.Add(time.Duration(i*2) * time.Hour)
		if e.TS.After(now) {
			e.TS = now
		}
		if err := l.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := now.Add(-10 * 24 * time.Hour)
	var got []Entry
	cur := ""
	pages := 0
	for {
		p, err := l.List("c1", cur, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Entries) > PageSize {
			t.Fatal("page too big")
		}
		got = append(got, p.Entries...)
		pages++
		if p.NextCursor == "" {
			break
		}
		cur = p.NextCursor
	}
	for seq := uint64(150); seq >= 1; seq-- {
		i := int(seq - 1)
		if i%5 == 0 {
			continue
		}
		ts := base.Add(time.Duration(i*2) * time.Hour)
		if ts.After(now) {
			ts = now
		}
		if !ts.Before(cutoff) {
			want = append(want, seq)
		}
	}
	if len(got) != len(want) || pages < 2 {
		t.Fatalf("got %d want %d pages %d", len(got), len(want), pages)
	}
	for i, e := range got {
		if e.Seq != want[i] || e.ConnectionID != "c1" {
			t.Fatalf("entry %d: %+v want seq %d", i, e, want[i])
		}
	}
}

func TestPrune(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	l, dir := mustOpen(t, &now, 90)
	ctx := context.Background()
	for _, d := range []int{0, 5, 20} {
		e := ent("c")
		e.TS = now.Add(-time.Duration(d) * 24 * time.Hour)
		if err := l.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []int{0, -1, 366} {
		if l.Prune(now, bad) == nil {
			t.Fatalf("retention %d accepted", bad)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.jsonl")); len(m) != 3 {
		t.Fatal("files deleted on rejected prune")
	}
	if err := l.Prune(now, 7); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.jsonl")); len(m) != 2 {
		t.Fatalf("want 2 files, got %d", len(m))
	}
	if _, err := Open(dir, Options{RetentionDays: 400}); err == nil {
		t.Fatal("open accepted bad retention")
	}
}
