package audit

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"pgregory.net/rapid"
)

var propNow = time.Date(2026, 11, 13, 7, 54, 52, 0, time.UTC)

func tmpDir(t *rapid.T) string {
	dir, err := os.MkdirTemp("", "audit-prop-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func propOpen(t *rapid.T, days int) *FileLog {
	dir, err := os.MkdirTemp("", "audit-prop-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	now := propNow // fake clock, never advances
	l, err := Open(dir, Options{RetentionDays: days, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

var (
	genEvent   = rapid.SampledFrom([]string{EventConnect, EventTest, EventDisconnect, EventRotate, EventCollect, EventScopeDenied, "plugin_x"})
	genOutcome = rapid.SampledFrom([]string{OutcomeSuccess, OutcomeFailure, OutcomeBlocked})
	genText    = rapid.StringMatching(`[A-Za-z0-9 _.:/\-é€]{0,40}`)
)

func genDetail() *rapid.Generator[map[string]string] {
	return rapid.Custom(func(t *rapid.T) map[string]string {
		n := rapid.IntRange(0, 5).Draw(t, "n")
		if n == 0 {
			return nil
		}
		m := map[string]string{}
		for i := 0; i < n; i++ {
			m[rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "k")] = genText.Draw(t, "v")
		}
		return m
	})
}

// Feature: cloud-connectors, Property 12: Audit paging and retention
// **Validates: Requirements 9.4, 9.6**
func TestPropAuditPagingAndRetention(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		days := rapid.IntRange(MinRetentionDays, MaxRetentionDays).Draw(t, "days")
		l := propOpen(t, days)
		n := rapid.IntRange(0, 160).Draw(t, "n")
		conns := []string{"c1", "c2", "c3"}
		// Timestamps (ms before now, up to 400 days) appended oldest first.
		offs := make([]int64, n)
		for i := range offs {
			offs[i] = rapid.Int64Range(0, 400*24*3600*1000).Draw(t, "off")
		}
		sort.Slice(offs, func(a, b int) bool { return offs[a] > offs[b] })
		cutoff := propNow.Add(-time.Duration(days) * 24 * time.Hour)
		byConn := map[string][]uint64{}
		for i, off := range offs {
			e := ent(rapid.SampledFrom(conns).Draw(t, "conn"))
			e.TS = propNow.Add(-time.Duration(off) * time.Millisecond)
			if err := l.Append(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if !e.TS.Before(cutoff) {
				byConn[e.ConnectionID] = append(byConn[e.ConnectionID], uint64(i+1))
			}
		}
		if rapid.Bool().Draw(t, "prune") {
			if err := l.Prune(propNow, days); err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range conns {
			want := byConn[c]
			var got []uint64
			cursor := ""
			for pages := 0; ; pages++ {
				if pages > n+2 {
					t.Fatal("paging does not terminate")
				}
				p, err := l.List(c, cursor, 0)
				if err != nil {
					t.Fatal(err)
				}
				if len(p.Entries) > PageSize {
					t.Fatalf("page of %d", len(p.Entries))
				}
				if p.NextCursor != "" && len(p.Entries) != PageSize {
					t.Fatalf("non-final page has %d entries", len(p.Entries))
				}
				for _, e := range p.Entries {
					if e.ConnectionID != c {
						t.Fatalf("foreign entry %q", e.ConnectionID)
					}
					got = append(got, e.Seq)
				}
				if p.NextCursor == "" {
					break
				}
				cursor = p.NextCursor
			}
			// want is ascending in append order; expect newest first.
			exp := make([]uint64, len(want))
			for i, s := range want {
				exp[len(want)-1-i] = s
			}
			if len(exp) == 0 && len(got) == 0 {
				continue
			}
			if !reflect.DeepEqual(got, exp) {
				t.Fatalf("conn %s days %d: got %v want %v", c, days, got, exp)
			}
		}
	})
}

// Feature: cloud-connectors, Property 12: Audit paging and retention (retention bounds)
// **Validates: Requirements 9.6**
func TestPropAuditRetentionBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		l := propOpen(t, DefaultRetentionDays)
		bad := rapid.OneOf(rapid.IntRange(-1000, 0), rapid.IntRange(366, 100000)).Draw(t, "bad")
		if err := l.SetRetention(bad); err != ErrInvalidRetention {
			t.Fatalf("SetRetention(%d) = %v", bad, err)
		}
		if err := l.Prune(propNow, bad); err != ErrInvalidRetention {
			t.Fatalf("Prune(%d) = %v", bad, err)
		}
		if l.Retention() != DefaultRetentionDays {
			t.Fatal("retention changed by rejected value")
		}
		if _, err := Open(tmpDir(t), Options{RetentionDays: bad}); bad != 0 && err != ErrInvalidRetention {
			t.Fatalf("Open(%d) = %v", bad, err)
		}
		good := rapid.IntRange(MinRetentionDays, MaxRetentionDays).Draw(t, "good")
		if err := l.SetRetention(good); err != nil || l.Retention() != good {
			t.Fatalf("SetRetention(%d) = %v", good, err)
		}
	})
}

// Feature: cloud-connectors, Property 9: Manifest and state serialization round trip (audit entry)
// **Validates: Requirements 9.2**
func TestPropAuditEntryRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := Entry{
			Seq:          rapid.Uint64Range(1, 1<<53).Draw(t, "seq"),
			TS:           time.UnixMilli(rapid.Int64Range(0, 4102444800000).Draw(t, "ms")).UTC(),
			ConnectionID: genText.Draw(t, "conn"),
			ConnectorID:  genText.Draw(t, "cid"),
			Event:        genEvent.Draw(t, "ev"),
			Outcome:      genOutcome.Draw(t, "out"),
			Actor:        genText.Draw(t, "actor"),
			Detail:       genDetail().Draw(t, "detail"),
			Prev:         rapid.SampledFrom([]string{"", "sha256:ab12"}).Draw(t, "prev"),
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var back Entry
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(e, back) {
			t.Fatalf("marshal round trip: %+v != %+v", e, back)
		}
		b2, _ := json.Marshal(back)
		if string(b) != string(b2) {
			t.Fatalf("not canonical: %s vs %s", b, b2)
		}

		// Through the log: Append then List returns an equivalent entry.
		l := propOpen(t, MaxRetentionDays)
		in := e
		in.Actor = rapid.StringMatching(`[a-z]{1,10}`).Draw(t, "actor2")
		in.TS = propNow.Add(-time.Duration(rapid.Int64Range(0, 30*24*3600*1000).Draw(t, "off")) * time.Millisecond)
		if err := l.Append(context.Background(), in); err != nil {
			t.Fatal(err)
		}
		p, err := l.List("", "", 0)
		if err != nil || len(p.Entries) != 1 {
			t.Fatalf("list: %v %d", err, len(p.Entries))
		}
		in.Seq, in.Prev = 1, ""
		if in.Detail != nil && len(in.Detail) == 0 {
			in.Detail = nil
		}
		if !reflect.DeepEqual(in, p.Entries[0]) {
			t.Fatalf("append/list round trip: %+v != %+v", in, p.Entries[0])
		}
	})
}
