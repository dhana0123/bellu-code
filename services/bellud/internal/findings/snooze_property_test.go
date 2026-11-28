package findings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"pgregory.net/rapid"
)

type snoozeRow struct {
	Finding Finding
	Events  []StatusEvent
	Reason  sql.NullString
	Until   sql.NullString
}

// Feature: bellu-wiz-security-platform, Property 4: Snooze status changes validate reason and expiry. For status ignored or accepted_risk the Store accepts iff the reason is non-blank (contains at least one non-whitespace character) and at most 1,024 characters and the expiry is absent or strictly after now; otherwise it rejects naming the invalid field and leaves the Finding unchanged.
// **Validates: Requirements 3.9, 3.10**
func TestPropertySnoozeValidation(t *testing.T) {
	ctx := context.Background()
	s, db, clk := newStore(t)
	now := clk.now()
	iter := 0

	snapshot := func(rt *rapid.T, id string) snoozeRow {
		f, ev, err := s.Get(ctx, id)
		if err != nil {
			rt.Fatal(err)
		}
		r := snoozeRow{Finding: f, Events: ev}
		if err := db.DB().QueryRow(`SELECT snooze_reason, snooze_until FROM finding WHERE workspace_id=? AND id=?`,
			s.ws, id).Scan(&r.Reason, &r.Until); err != nil {
			rt.Fatal(err)
		}
		return r
	}

	// Characters, not bytes: multibyte runes of 1 to 4 bytes.
	runeGen := rapid.SampledFrom([]rune{'a', 'Z', '7', ' ', 'é', '日', '😀'})
	reasonGen := rapid.OneOf(
		rapid.Just(""),
		rapid.StringMatching(`[ \t\n]{1,6}`),
		rapid.Map(rapid.SliceOfN(runeGen, 1, 1), func(r []rune) string { return string(r) }),
		rapid.Map(rapid.SampledFrom([]int{1, 2, 1023, 1024, 1025, 1100}), func(n int) string { return strings.Repeat("a", n) }),
		rapid.Custom(func(rt *rapid.T) string {
			// Multibyte runes: the byte length exceeds 1,024 even when the character count does not.
			n := rapid.SampledFrom([]int{512, 1023, 1024, 1025}).Draw(rt, "n")
			r := rapid.SampledFrom([]rune{'é', '日', '😀'}).Draw(rt, "r")
			return strings.Repeat(string(r), n)
		}),
		rapid.Map(rapid.SliceOfN(runeGen, 0, 40), func(r []rune) string { return string(r) }),
	)
	expiryGen := rapid.OneOf(
		rapid.Just[*time.Time](nil),
		rapid.Custom(func(rt *rapid.T) *time.Time {
			var d time.Duration
			switch rapid.IntRange(0, 4).Draw(rt, "kind") {
			case 0:
				d = -time.Duration(rapid.Int64Range(1, int64(48*time.Hour)).Draw(rt, "past"))
			case 1:
				d = 0
			case 2:
				d = time.Nanosecond
			case 3:
				d = -time.Nanosecond
			default:
				d = time.Duration(rapid.Int64Range(1, int64(30*24*time.Hour)).Draw(rt, "future"))
			}
			e := now.Add(d)
			return &e
		}),
	)

	rapid.Check(t, func(rt *rapid.T) {
		iter++
		id := fmt.Sprintf("snooze-%d", iter)
		if _, err := s.Report(ctx, ScanRef{JobID: "seed"}, []Finding{sample(id)}); err != nil {
			rt.Fatal(err)
		}
		to := rapid.SampledFrom([]Status{StatusIgnored, StatusAcceptedRisk}).Draw(rt, "status")
		reason := reasonGen.Draw(rt, "reason")
		expires := expiryGen.Draw(rt, "expires")

		reasonOK := strings.TrimSpace(reason) != "" && utf8.RuneCountInString(reason) <= 1024
		expiryOK := expires == nil || expires.After(now)

		before := snapshot(rt, id)
		err := s.SetStatus(ctx, id, to, Actor{ID: "user"}, reason, expires)
		after := snapshot(rt, id)

		if reasonOK && expiryOK {
			if err != nil {
				rt.Fatalf("rejected valid input (reason %d chars, %d bytes, expires %v): %v",
					utf8.RuneCountInString(reason), len(reason), expires, err)
			}
			if after.Finding.Status != to {
				rt.Fatalf("status %s, want %s", after.Finding.Status, to)
			}
			if !after.Reason.Valid || after.Reason.String != reason {
				rt.Fatalf("stored reason %q, want %q", after.Reason.String, reason)
			}
			if expires == nil {
				if after.Until.Valid {
					rt.Fatalf("stored expiry %q, want none", after.Until.String)
				}
			} else {
				got, perr := parseTS(after.Until.String)
				if perr != nil || !got.Equal(*expires) {
					rt.Fatalf("stored expiry %q (%v), want %v", after.Until.String, perr, expires)
				}
			}
			if len(after.Events) != len(before.Events)+1 {
				rt.Fatalf("events %d, want %d", len(after.Events), len(before.Events)+1)
			}
			last := after.Events[len(after.Events)-1]
			if last.Prev != StatusOpen || last.New != to || last.Reason != reason {
				rt.Fatalf("bad event %+v", last)
			}
			return
		}

		if err == nil {
			rt.Fatalf("accepted invalid input (reason %d chars, %d bytes, expires %v)",
				utf8.RuneCountInString(reason), len(reason), expires)
		}
		var ie *InvalidError
		if !errors.Is(err, ErrInvalid) || !errors.As(err, &ie) {
			rt.Fatalf("error %v is not ErrInvalid", err)
		}
		okField := (!reasonOK && ie.Field == "reason") || (!expiryOK && ie.Field == "expires")
		if !okField {
			rt.Fatalf("error names field %q (reasonOK=%v expiryOK=%v)", ie.Field, reasonOK, expiryOK)
		}
		if !reflect.DeepEqual(before, after) {
			rt.Fatalf("finding changed on rejection:\nbefore %+v\nafter  %+v", before, after)
		}
	})
}
