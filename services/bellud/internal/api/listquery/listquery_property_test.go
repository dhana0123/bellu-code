package listquery

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

var propSpec = Spec{
	Filters:     AllFilters,
	Sorts:       []string{"updated_at", "score", "severity"},
	DefaultSort: "-score",
}

var propNow = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

// genValidParams draws a well-formed request: 0..3 values (repeats allowed) per
// filter, an ordered time range, at most one sort and one limit.
func genValidParams(t *rapid.T) url.Values {
	v := url.Values{}
	for _, name := range []string{Category, Severity, Status, Type} {
		dom := propSpec.domain(name)
		if vals := rapid.SliceOfN(rapid.SampledFrom(dom), 0, 3).Draw(t, name); len(vals) > 0 {
			v[name] = vals
		}
	}
	for _, name := range []string{Asset, Source} {
		if vals := rapid.SliceOfN(rapid.StringMatching(`[a-z0-9:/_.-]{1,20}`), 0, 3).Draw(t, name); len(vals) > 0 {
			v[name] = vals
		}
	}
	base := propNow.Add(-time.Duration(rapid.IntRange(0, 1_000_000).Draw(t, "base")) * time.Minute)
	span := time.Duration(rapid.IntRange(0, 100_000).Draw(t, "span")) * time.Minute
	if rapid.Bool().Draw(t, "hasFrom") {
		v.Set(From, base.Format(time.RFC3339))
	}
	if rapid.Bool().Draw(t, "hasTo") {
		v.Set(To, base.Add(span).Format(time.RFC3339))
	}
	if rapid.Bool().Draw(t, "hasSort") {
		s := rapid.SampledFrom(propSpec.Sorts).Draw(t, "sortField")
		if rapid.Bool().Draw(t, "desc") {
			s = "-" + s
		}
		v.Set("sort", s)
	}
	if rapid.Bool().Draw(t, "hasLimit") {
		v.Set("limit", strconv.Itoa(rapid.IntRange(1, MaxLimit).Draw(t, "limit")))
	}
	return v
}

// breakage is one way to make a request invalid. apply edits v and returns the
// parameter Parse must name when this is the only defect.
type breakage struct {
	name  string
	apply func(t *rapid.T, v url.Values) string
}

func enumBreakage(param string) breakage {
	return breakage{"bad-" + param, func(t *rapid.T, v url.Values) string {
		bad := "bogus-" + rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "bogus")
		vals := slices.Clone(v[param])
		at := rapid.IntRange(0, len(vals)).Draw(t, "at")
		v[param] = slices.Insert(vals, at, bad)
		return param
	}}
}

var breakages = []breakage{
	{"unknown-name", func(t *rapid.T, v url.Values) string {
		k := "zz_" + rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "unknown")
		v.Set(k, rapid.StringMatching(`[a-z0-9]{0,5}`).Draw(t, "unknownValue"))
		return k
	}},
	enumBreakage(Category), enumBreakage(Severity), enumBreakage(Status), enumBreakage(Type),
	{"bad-limit", func(t *rapid.T, v url.Values) string {
		v.Set("limit", rapid.SampledFrom([]string{"0", "-1", "501", "99999999999999999999", "abc", "1.5", "", " 5", "5 ", "+5", "1e2", "0x10"}).Draw(t, "badLimit"))
		return "limit"
	}},
	{"repeated-limit", func(t *rapid.T, v url.Values) string {
		v["limit"] = []string{strconv.Itoa(rapid.IntRange(1, MaxLimit).Draw(t, "l1")), strconv.Itoa(rapid.IntRange(1, MaxLimit).Draw(t, "l2"))}
		return "limit"
	}},
	{"bad-sort", func(t *rapid.T, v url.Values) string {
		v.Set("sort", rapid.SampledFrom([]string{"bogus", "-bogus", "--score", "+score", " score", "", "score,severity", "SCORE"}).Draw(t, "badSort"))
		return "sort"
	}},
	{"repeated-sort", func(t *rapid.T, v url.Values) string {
		v["sort"] = []string{rapid.SampledFrom(propSpec.Sorts).Draw(t, "s1"), rapid.SampledFrom(propSpec.Sorts).Draw(t, "s2")}
		return "sort"
	}},
	{"wrong-type-from", func(t *rapid.T, v url.Values) string {
		v.Set(From, rapid.SampledFrom([]string{"yesterday", "1700000000", "2025-01-01", "2025-01-01 00:00:00", "12:00", "true"}).Draw(t, "badFrom"))
		return From
	}},
	{"wrong-type-to", func(t *rapid.T, v url.Values) string {
		v.Set(To, rapid.SampledFrom([]string{"tomorrow", "1700000000", "2025-01-01", "2025-01-01 00:00:00", "12:00", "false"}).Draw(t, "badTo"))
		return To
	}},
	{"from-after-to", func(t *rapid.T, v url.Values) string {
		to := propNow.Add(-time.Duration(rapid.IntRange(0, 1_000_000).Draw(t, "to")) * time.Minute)
		from := to.Add(time.Duration(rapid.IntRange(1, 100_000).Draw(t, "gap")) * time.Second)
		v.Set(From, from.Format(time.RFC3339))
		v.Set(To, to.Format(time.RFC3339))
		return From
	}},
	{"malformed-cursor", func(t *rapid.T, v url.Values) string {
		v.Set("cursor", rapid.SampledFrom([]string{"x", "abc.def", "...", "!!.!!", "e30.e30", "a.b.c"}).Draw(t, "badCursor"))
		return "cursor"
	}},
	{"empty-cursor", func(t *rapid.T, v url.Values) string {
		v.Set("cursor", "")
		return "cursor"
	}},
	{"repeated-cursor", func(t *rapid.T, v url.Values) string {
		v["cursor"] = []string{"a.b", "c.d"}
		return "cursor"
	}},
}

// A cursor breakage that needs a codec is built separately so it can be
// issued for the request's own filters (tampered, expired) or for others.
const (
	curTampered = iota
	curExpired
	curOtherFilters
)

// timeKinds are mutually exclusive: each rewrites from and/or to.
var timeKinds = []string{"wrong-type-from", "wrong-type-to", "from-after-to"}

// Feature: bellu-wiz-security-platform, Property 34: For any list request, a parameter outside its domain SHALL be rejected with HTTP 400 naming the parameter, run no query and leave data unchanged; for any well-formed filters and repeated values, the result SHALL equal the AND across distinct filters of the OR across repeated values.
// **Validates: Requirements 20.3, 20.4**
func TestPropertyListParameterValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		codec := NewCodec().WithClock(func() time.Time { return propNow })
		v := genValidParams(t)

		// The undamaged request must parse, and its own cursor must be accepted.
		q0, err := propSpec.ParseWith(codec, v)
		if err != nil {
			t.Fatalf("well-formed request rejected: %v (%v)", err, v)
		}

		// Choose a set of defects; time defects exclude each other.
		picked := rapid.SliceOfNDistinct(rapid.IntRange(0, len(breakages)+2), 0, 4, func(i int) int { return i }).Draw(t, "defects")
		timeKind := ""
		var invalid []string
		damaged := url.Values{}
		for k, vals := range v {
			damaged[k] = slices.Clone(vals)
		}
		var cursorKind = -1
		for _, i := range picked {
			if i >= len(breakages) {
				cursorKind = i - len(breakages) // codec-backed cursor defect
				continue
			}
			b := breakages[i]
			if slices.Contains(timeKinds, b.name) {
				if timeKind != "" {
					continue
				}
				timeKind = b.name
			}
			if strings.HasSuffix(b.name, "cursor") && cursorKind >= 0 {
				continue
			}
			invalid = append(invalid, b.apply(t, damaged))
		}
		switch cursorKind {
		case curTampered:
			tok := q0.NextCursorWith(codec, "pos")
			b := []byte(tok)
			if b[0] == 'A' {
				b[0] = 'B'
			} else {
				b[0] = 'A'
			}
			damaged.Set("cursor", string(b))
			invalid = append(invalid, "cursor")
		case curExpired:
			old := codec.WithClock(func() time.Time { return propNow.Add(-CursorTTL - time.Second) })
			damaged.Set("cursor", q0.NextCursorWith(old, "pos"))
			invalid = append(invalid, "cursor")
		case curOtherFilters:
			other := q0
			other.Assets = append(slices.Clone(q0.Assets), "some-other-asset")
			damaged.Set("cursor", other.NextCursorWith(codec, "pos"))
			invalid = append(invalid, "cursor")
		default:
			if len(invalid) == 0 && rapid.Bool().Draw(t, "validCursor") {
				damaged.Set("cursor", q0.NextCursorWith(codec, "pos"))
			}
		}

		_, err = propSpec.ParseWith(codec, damaged)
		if len(invalid) == 0 {
			if err != nil {
				t.Fatalf("valid request rejected: %v (%v)", err, damaged)
			}
			return
		}
		var qe *Error
		if !errors.As(err, &qe) {
			t.Fatalf("invalid request %v (invalid %v) gave %v, want *Error", damaged, invalid, err)
		}
		if !slices.Contains(invalid, qe.Param) {
			t.Fatalf("error names %q, invalid parameters are %v (request %v)", qe.Param, invalid, damaged)
		}

		w := httptest.NewRecorder()
		WriteError(w, qe)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", w.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["field"] != qe.Param || body["code"] != "invalid_request" || !strings.Contains(body["message"], qe.Param) {
			t.Fatalf("body does not name %q: %v", qe.Param, body)
		}
	})
}
