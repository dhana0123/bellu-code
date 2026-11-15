package model

import (
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 9: Package matching follows the half-open range rule
//
// For any affected-package list, purl name, and version, MatchPackage is true
// if and only if some entry has the same purl name and either declares no
// ranges or declares a range with introduced <= version < fixed (empty or "0"
// introduced is unbounded below, empty fixed is unbounded above).
// SplitPurl(name + "@" + version) returns (name, version).
//
// The reference below works on integer tuples and never touches the
// production string comparison. Versions are plain dotted numbers, where a
// missing trailing component is 0, so "1.0" and "1.0.0" are the same version.
//
// **Validates: Requirements 5.2, 5.4, 5.5**

type refVersion []int

func (v refVersion) String() string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

// refCompare compares two tuples, padding the shorter one with zeros.
func refCompare(a, b refVersion) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// refBound is one side of a generated range. text is what the production type
// receives; version is nil when the bound is unbounded.
type refBound struct {
	text    string
	version refVersion
}

type refRange struct {
	introduced, fixed refBound
}

type refEntry struct {
	purl   string
	ranges []refRange
}

func (r refRange) contains(v refVersion) bool {
	if r.introduced.version != nil && refCompare(v, r.introduced.version) < 0 {
		return false
	}
	if r.fixed.version != nil && refCompare(v, r.fixed.version) >= 0 {
		return false
	}
	return true
}

func refMatches(entries []refEntry, name string, v refVersion) bool {
	for _, e := range entries {
		if e.purl != name {
			continue
		}
		if len(e.ranges) == 0 {
			return true
		}
		for _, r := range e.ranges {
			if r.contains(v) {
				return true
			}
		}
	}
	return false
}

func genVersion() *rapid.Generator[refVersion] {
	return rapid.Map(rapid.SliceOfN(rapid.IntRange(0, 12), 1, 4), func(s []int) refVersion { return s })
}

func genBound(lower bool) *rapid.Generator[refBound] {
	unbounded := []refBound{{text: ""}}
	if lower {
		unbounded = append(unbounded, refBound{text: "0"})
	}
	return rapid.OneOf(
		rapid.SampledFrom(unbounded),
		rapid.Map(genVersion(), func(v refVersion) refBound {
			return refBound{text: v.String(), version: v}
		}),
	)
}

func genEntry() *rapid.Generator[refEntry] {
	return rapid.Custom(func(t *rapid.T) refEntry {
		return refEntry{
			purl: rapid.SampledFrom([]string{"pkg:pypi/a", "pkg:npm/b", "pkg:golang/c"}).Draw(t, "purl"),
			ranges: rapid.SliceOfN(rapid.Custom(func(t *rapid.T) refRange {
				return refRange{
					introduced: genBound(true).Draw(t, "introduced"),
					fixed:      genBound(false).Draw(t, "fixed"),
				}
			}), 0, 3).Draw(t, "ranges"),
		}
	})
}

func TestProperty9MatchPackageHalfOpenRange(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		entries := rapid.SliceOfN(genEntry(), 0, 4).Draw(t, "entries")
		name := rapid.SampledFrom([]string{"pkg:pypi/a", "pkg:npm/b", "pkg:golang/c", "pkg:pypi/other"}).Draw(t, "name")
		version := genVersion().Draw(t, "version")

		affected := make([]AffectedPackage, len(entries))
		for i, e := range entries {
			affected[i].Purl = e.purl
			for _, r := range e.ranges {
				affected[i].Ranges = append(affected[i].Ranges, SemverRange{Introduced: r.introduced.text, Fixed: r.fixed.text})
			}
		}

		want := refMatches(entries, name, version)
		got, ap := MatchPackage(affected, name, version.String())
		if got != want {
			t.Fatalf("MatchPackage(%+v, %q, %q) = %v, want %v", affected, name, version, got, want)
		}
		if got && ap.Purl != name {
			t.Fatalf("matched entry purl %q, want %q", ap.Purl, name)
		}
	})
}

func TestProperty9RangeContainsBoundaries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		lo := genVersion().Draw(t, "lo")
		hi := genVersion().Draw(t, "hi")
		v := genVersion().Draw(t, "v")
		r := SemverRange{Introduced: lo.String(), Fixed: hi.String()}

		ref := refRange{introduced: refBound{version: lo}, fixed: refBound{version: hi}}
		if got, want := r.Contains(v.String()), ref.contains(v); got != want {
			t.Fatalf("%+v.Contains(%q) = %v, want %v", r, v, got, want)
		}
		// Introduced is inclusive and Fixed is exclusive.
		if refCompare(lo, hi) < 0 {
			if !r.Contains(lo.String()) {
				t.Fatalf("%+v must contain its introduced version", r)
			}
			if r.Contains(hi.String()) {
				t.Fatalf("%+v must not contain its fixed version", r)
			}
		}
	})
}

func TestProperty9SplitPurlRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`pkg:[a-z]{2,6}/[a-z0-9._/-]{1,20}`).Draw(t, "name")
		version := genVersion().Draw(t, "version").String()
		gotName, gotVersion := SplitPurl(name + "@" + version)
		if gotName != name || gotVersion != version {
			t.Fatalf("SplitPurl(%q) = (%q, %q), want (%q, %q)", name+"@"+version, gotName, gotVersion, name, version)
		}
	})
}

// Trailing zeros do not change a version, so a bound written with a different
// number of trailing zeros must still be inclusive (Introduced) or exclusive
// (Fixed) for the same version.
func TestProperty9TrailingZerosAreSameVersion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := genVersion().Draw(t, "base")
		padded := append(append(refVersion{}, base...), make([]int, rapid.IntRange(0, 2).Draw(t, "zeros"))...)
		r := SemverRange{Introduced: base.String(), Fixed: ""}
		if !r.Contains(padded.String()) || !(SemverRange{Introduced: padded.String()}).Contains(base.String()) {
			t.Fatalf("%q and %q must satisfy an inclusive Introduced bound in both directions", base, padded)
		}
		if (SemverRange{Fixed: base.String()}).Contains(padded.String()) || (SemverRange{Fixed: padded.String()}).Contains(base.String()) {
			t.Fatalf("%q and %q must fail an exclusive Fixed bound in both directions", base, padded)
		}
	})
}
