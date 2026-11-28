package vulnmatch

import (
	"github.com/anchore/grype/grype/version"

	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
)

// formatFor returns the Grype version format for a purl type. Grype's
// ParseFormat covers most types; cargo is added because it has no entry there
// and uses semantic versions.
func formatFor(purlType string) version.Format {
	if purlType == "cargo" {
		return version.SemanticFormat
	}
	return version.ParseFormat(purlType)
}

// compare orders a and b for the ecosystem. ok is false when no comparator
// can parse them, so the caller must not decide on the result. Under the
// osvmatch tag OSV's comparator answers first for the ecosystems where Grype's
// ordering is weakest; Grype's version package answers the rest.
func compare(purlType, a, b string) (c int, ok bool) {
	if c, ok := osvCompare(purlType, a, b); ok {
		return c, true
	}
	f := formatFor(purlType)
	if f == version.UnknownFormat {
		return 0, false
	}
	c, err := version.New(a, f).Compare(version.New(b, f))
	if err != nil {
		return 0, false
	}
	return c, true
}

// inRanges reports whether ver lies in any of the half-open ranges
// [Introduced, Fixed). decided is false when a bound could not be compared and
// no range contained the version. No ranges means every version is affected,
// the reading cvesource's MatchPackage applies.
func inRanges(purlType, ver string, ranges []cvesource.Range) (inside, decided bool) {
	if len(ranges) == 0 {
		return true, true
	}
	decided = true
	for _, r := range ranges {
		low, lowOK := true, true
		if r.Introduced != "" && r.Introduced != "0" {
			var c int
			if c, lowOK = compare(purlType, ver, r.Introduced); lowOK {
				low = c >= 0
			}
		}
		high, highOK := true, true
		if r.Fixed != "" {
			var c int
			if c, highOK = compare(purlType, ver, r.Fixed); highOK {
				high = c < 0
			}
		}
		switch {
		case !lowOK || !highOK:
			decided = false
		case low && high:
			return true, true
		}
	}
	return false, decided
}
