// Package gen holds the rapid generators shared by the Engine's property
// tests: kinds, identities, attribute values, Batch schedules over a small ID
// universe, out-of-order Valid_Times, fake clocks and HTML strings.
package gen

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen/model"
)

// Epoch is the base instant of generated times.
var Epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// Kind draws a registered entity kind.
func Kind() *rapid.Generator[string] { return rapid.SampledFrom(ident.Kinds()) }

// Identity draws a complete identity map for kind: every registered key with
// a non-empty value (Unicode included).
func Identity(kind string) *rapid.Generator[map[string]string] {
	return rapid.Custom(func(t *rapid.T) map[string]string {
		keys, _ := ident.IdentityAttributes(kind)
		m := make(map[string]string, len(keys))
		for _, k := range keys {
			m[k] = rapid.StringN(1, 12, -1).Draw(t, k)
		}
		return m
	})
}

// RelType draws a registered or arbitrary relation type.
func RelType() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.SampledFrom(ident.RelationTypes()),
		rapid.SampledFrom([]string{"custom_link", "talks_to"}),
	)
}

// Value draws any supported attribute value, edge cases included: empty and
// Unicode strings, -0, MaxInt64/MinInt64, empty lists, and the narrower
// integer types accepted by codec.FromAny.
func Value() *rapid.Generator[any] {
	return rapid.OneOf(
		rapid.Map(rapid.OneOf(rapid.SampledFrom([]string{"", " ", "héllo", "日本語", "a\x00b"}), rapid.String()), func(s string) any { return s }),
		rapid.Map(rapid.Bool(), func(b bool) any { return b }),
		rapid.Map(rapid.Int64(), func(i int64) any { return i }),
		rapid.SampledFrom([]any{int64(math.MaxInt64), int64(math.MinInt64), int(0), int32(-7), uint8(255), uint32(1 << 31), uint64(math.MaxInt64)}),
		rapid.Map(rapid.Float64(), func(f float64) any { return f }),
		rapid.SampledFrom([]any{math.Copysign(0, -1), float32(1.5), math.MaxFloat64, math.SmallestNonzeroFloat64}),
		rapid.Map(rapid.SliceOfN(rapid.String(), 0, 3), func(l []string) any { return l }),
		rapid.SampledFrom([]any{[]string{}, []any{}, []any{"x", "y"}}),
	)
}

// Unsupported draws a value that codec.FromAny must reject.
func Unsupported() *rapid.Generator[any] {
	return rapid.SampledFrom([]any{
		nil, math.NaN(), math.Inf(1), math.Inf(-1), float32(math.NaN()),
		uint64(math.MaxInt64) + 1, uint(math.MaxUint64),
		map[string]any{"a": 1}, []int{1}, []any{"a", 1}, struct{}{}, time.Time{},
	})
}

var attrNames = []string{"state", "status", "name", "version", "owner", "tags", "count", "zone"}

// SmallValue draws from a tiny value pool so that repeated observations often
// repeat, change or omit a value.
func SmallValue() *rapid.Generator[any] {
	return rapid.SampledFrom([]any{"up", "down", "a", 1, int64(2), true, 1.5, []string{"x"}, []string{}})
}

// Attributes draws a small descriptive attribute map; state and status are in
// the name pool so state-changed classification is exercised.
func Attributes() *rapid.Generator[map[string]any] {
	return rapid.MapOfN(rapid.SampledFrom(attrNames), SmallValue(), 0, 4)
}

// Universe is the small ID universe: N identities for each of Kinds.
type Universe struct {
	Kinds []string
	N     int
}

// DefaultUniverse has 5 kinds x 3 identities = 15 entities.
func DefaultUniverse() Universe {
	return Universe{Kinds: []string{"host", "process", "container", "listening_port", "image"}, N: 3}
}

// Ref names one entity of the universe.
type Ref struct {
	Kind  string
	Index int
}

// Identity returns the identity map of r.
func (r Ref) Identity() map[string]string {
	keys, _ := ident.IdentityAttributes(r.Kind)
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		m[k] = fmt.Sprintf("%s-%d", k, r.Index)
	}
	return m
}

// ID returns the Entity_ID of r.
func (r Ref) ID() string {
	id, err := ident.Hash(r.Kind, r.Identity())
	if err != nil {
		panic(err) // universe kinds are registered
	}
	return id
}

// Ref draws an entity of the universe.
func (u Universe) Ref() *rapid.Generator[Ref] {
	return rapid.Custom(func(t *rapid.T) Ref {
		return Ref{Kind: rapid.SampledFrom(u.Kinds).Draw(t, "kind"), Index: rapid.IntRange(0, u.N-1).Draw(t, "index")}
	})
}

// IDs returns every Entity_ID of the universe.
func (u Universe) IDs() []string {
	var out []string
	for _, k := range u.Kinds {
		for i := 0; i < u.N; i++ {
			out = append(out, Ref{k, i}.ID())
		}
	}
	return out
}

// Options configures Batch and Schedule generation.
type Options struct {
	Universe     Universe
	Collectors   []string // default c1..c3
	MaxEntities  int      // default 6
	MaxRelations int      // default 6
	// ForeignEndpoints lets relations name universe entities that are not in
	// the Batch; such Batches are rejected unless the entity is live.
	ForeignEndpoints bool
}

func (o Options) norm() Options {
	if o.Universe.N == 0 {
		o.Universe = DefaultUniverse()
	}
	if len(o.Collectors) == 0 {
		o.Collectors = []string{"c1", "c2", "c3"}
	}
	if o.MaxEntities == 0 {
		o.MaxEntities = 6
	}
	if o.MaxRelations == 0 {
		o.MaxRelations = 6
	}
	return o
}

// Batch draws a Batch for collector observed at observed (zero allowed).
func (o Options) Batch(collector string, observed time.Time) *rapid.Generator[batch.Batch] {
	o = o.norm()
	return rapid.Custom(func(t *rapid.T) batch.Batch {
		refs := rapid.SliceOfNDistinct(o.Universe.Ref(), 0, o.MaxEntities, func(r Ref) Ref { return r }).Draw(t, "refs")
		b := batch.Batch{Collector: collector, ObservedAt: observed}
		ids := make([]string, 0, len(refs))
		for _, r := range refs {
			e := batch.Entity{Type: r.Kind, Identity: r.Identity(), Attributes: Attributes().Draw(t, "attrs")}
			if rapid.IntRange(0, 4).Draw(t, "extra") == 0 {
				e.Identity["alias"] = rapid.SampledFrom([]string{"p", "q"}).Draw(t, "alias") // non-identity key
			}
			b.Entities = append(b.Entities, e)
			ids = append(ids, r.ID())
		}
		pool := ids
		if o.ForeignEndpoints {
			pool = append(append([]string(nil), ids...), o.Universe.IDs()...)
		}
		if len(pool) > 0 {
			n := rapid.IntRange(0, o.MaxRelations).Draw(t, "nrel")
			for i := 0; i < n; i++ {
				b.Relations = append(b.Relations, batch.Relation{
					Type: RelType().Draw(t, "rtype"),
					From: rapid.SampledFrom(pool).Draw(t, "from"),
					To:   rapid.SampledFrom(pool).Draw(t, "to"),
				})
			}
		}
		return b
	})
}

// Step is one scheduled Apply: a Batch, its mode and the clock reading.
type Step struct {
	Batch batch.Batch
	Mode  model.Mode
	Now   time.Time
}

// Schedule draws between minSteps and maxSteps Steps across the collectors.
// Valid_Times (ObservedAt) are out of order and often repeat, or are zero
// ("now"); the clock may move backwards.
func (o Options) Schedule(minSteps, maxSteps int) *rapid.Generator[[]Step] {
	o = o.norm()
	return rapid.Custom(func(t *rapid.T) []Step {
		n := rapid.IntRange(minSteps, maxSteps).Draw(t, "steps")
		steps := make([]Step, 0, n)
		now := Epoch.Add(time.Hour)
		for i := 0; i < n; i++ {
			now = now.Add(time.Duration(rapid.IntRange(-30, 120).Draw(t, "dt")) * time.Second)
			var observed time.Time
			if rapid.IntRange(0, 5).Draw(t, "zero") != 0 {
				observed = ValidTime().Draw(t, "observed")
			}
			steps = append(steps, Step{
				Batch: o.Batch(rapid.SampledFrom(o.Collectors).Draw(t, "collector"), observed).Draw(t, "batch"),
				Mode:  rapid.SampledFrom([]model.Mode{model.Full, model.Full, model.Partial}).Draw(t, "mode"),
				Now:   now,
			})
		}
		return steps
	})
}

// ValidTime draws an instant on a 1-minute grid within +-1h of Epoch+1h, so
// that ties and out-of-order values are common.
func ValidTime() *rapid.Generator[time.Time] {
	return rapid.Map(rapid.IntRange(0, 120), func(m int) time.Time { return Epoch.Add(time.Duration(m) * time.Minute) })
}

// ValidTimes draws n out-of-order Valid_Times.
func ValidTimes(n int) *rapid.Generator[[]time.Time] { return rapid.SliceOfN(ValidTime(), n, n) }

// Clock is a fake clock that replays a script of readings; the last reading
// repeats once the script is exhausted. It is safe for concurrent use.
type Clock struct {
	mu    sync.Mutex
	times []time.Time
	i     int
}

// NewClock returns a Clock over times (at least one).
func NewClock(times ...time.Time) *Clock { return &Clock{times: times} }

// Now returns the next reading.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.times[c.i]
	if c.i < len(c.times)-1 {
		c.i++
	}
	return t
}

// Clocks draws a fake clock whose readings may move backwards.
func Clocks(minN, maxN int) *rapid.Generator[*Clock] {
	return rapid.Custom(func(t *rapid.T) *Clock {
		n := rapid.IntRange(max(minN, 1), max(maxN, 1)).Draw(t, "n")
		ts := make([]time.Time, n)
		cur := Epoch.Add(2 * time.Hour)
		for i := range ts {
			cur = cur.Add(time.Duration(rapid.IntRange(-20, 60).Draw(t, "dt")) * time.Second)
			ts[i] = cur
		}
		return NewClock(ts...)
	})
}

var htmlFragments = []string{
	"<script>alert(1)</script>", "\"", "'", "&", "&amp;", "<", ">", "</td>", "<img src=x onerror=alert(1)>",
	"javascript:alert(1)", "`", "{{.X}}", "%3Cscript%3E", "\u2028", "plain", "日本",
}

// HTML draws strings dense in HTML metacharacters.
func HTML() *rapid.Generator[string] {
	return rapid.Map(rapid.SliceOfN(rapid.SampledFrom(htmlFragments), 1, 5), func(p []string) string { return strings.Join(p, "") })
}
