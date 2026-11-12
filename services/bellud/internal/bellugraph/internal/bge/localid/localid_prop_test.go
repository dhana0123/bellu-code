package localid

import (
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

// Feature: bellu-graph-native, Property 23: Local_ID lifecycle
//
// Validates: Requirements 11.3, 11.4, 11.6
func TestPropLocalIDLifecycle(t *testing.T) {
	type entry struct {
		id   string
		last time.Time
	}
	rapid.Check(t, func(t *rapid.T) {
		r, clk := newReg()
		model := map[string]*entry{} // every alias ever issued
		ids := []string{"e1", "e2", "e3", "e4"}

		// state classifies an alias against the model: live, expired, or
		// ambiguous (exactly at the idle boundary).
		state := func(e *entry) int {
			switch el := clk.now().Sub(e.last); {
			case el < DefaultIdle:
				return 1
			case el == DefaultIdle:
				return 0
			}
			return -1
		}

		t.Repeat(map[string]func(*rapid.T){
			"for": func(t *rapid.T) {
				id := rapid.SampledFrom(ids).Draw(t, "id")
				var liveAlias string
				ambiguous := false
				for a, e := range model {
					if e.id != id {
						continue
					}
					switch state(e) {
					case 1:
						liveAlias = a
					case 0:
						ambiguous = true
					}
				}
				got := r.For(id)
				now := clk.now()
				if liveAlias != "" {
					if got != liveAlias {
						t.Fatalf("For(%s)=%s, want live alias %s", id, got, liveAlias)
					}
					model[got].last = now
					return
				}
				if prev, seen := model[got]; seen {
					// A reissued alias is only legal when it is the ambiguous
					// boundary alias itself, or 24h have passed since it could
					// have been retired.
					if !(ambiguous && prev.id == id && state(prev) == 0) &&
						now.Sub(prev.last.Add(DefaultIdle)) < DefaultTombstone {
						t.Fatalf("alias %s reissued (was %s) within 24h of retirement", got, prev.id)
					}
				}
				model[got] = &entry{id: id, last: now}
			},
			"lookup": func(t *rapid.T) {
				if len(model) == 0 {
					return
				}
				keys := make([]string, 0, len(model))
				for a := range model {
					keys = append(keys, a)
				}
				// Map order is random; sort-free pick via rapid index is fine
				// because the check only depends on the chosen alias.
				a := keys[rapid.IntRange(0, len(keys)-1).Draw(t, "idx")]
				e := model[a]
				st := state(e)
				id, err := r.Lookup(a)
				switch st {
				case 1:
					if err != nil || id != e.id {
						t.Fatalf("Lookup(%s)=%q,%v want %q", a, id, err, e.id)
					}
					e.last = clk.now()
				case -1:
					if !errors.Is(err, errs.NotFound) {
						t.Fatalf("Lookup(%s) idle >15m: %v, want NotFound", a, err)
					}
				default:
					if err == nil {
						e.last = clk.now()
					}
				}
			},
			"sweep": func(t *rapid.T) { r.Sweep() },
			"advance": func(t *rapid.T) {
				d := rapid.OneOf(
					rapid.Int64Range(1, int64(20*time.Minute)),
					rapid.Int64Range(int64(20*time.Minute), int64(26*time.Hour)),
				).Draw(t, "d")
				clk.advance(time.Duration(d))
			},
		})
	})
}
