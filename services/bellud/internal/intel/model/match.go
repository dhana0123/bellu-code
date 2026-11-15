package model

import "strings"

// SplitPurl splits a package URL into its name (the purl without any version
// qualifier) and its version. Graph Package nodes are keyed by a versioned purl
// such as "pkg:pypi/requests@2.30.0"; AffectedPackage.Purl is the
// name only ("pkg:pypi/requests"), with the version carried in its ranges. This
// helper reconciles the two forms.
//
// The version is the substring after the final '@'. If the purl carries no '@'
// the whole string is the name and the version is empty. Surrounding
// whitespace is trimmed from both results.
//
// Examples:
//
//	SplitPurl("pkg:pypi/requests@2.30.0") => "pkg:pypi/requests", "2.30.0"
//	SplitPurl("pkg:pypi/requests")        => "pkg:pypi/requests", ""
func SplitPurl(purl string) (name, version string) {
	purl = strings.TrimSpace(purl)
	if i := strings.LastIndexByte(purl, '@'); i >= 0 {
		name = strings.TrimSpace(purl[:i])
		version = strings.TrimSpace(purl[i+1:])
		return name, version
	}
	return purl, ""
}

// MatchPackage reports whether a graph Package (identified by its purl name and
// version) is affected by any of the given AffectedPackage entries,
// and returns the matched entry.
//
// A package matches an AffectedPackage only when the purl names are equal AND
// one of the following holds:
//
//   - the AffectedPackage declares one or more SemverRanges and the package
//     version lies within at least one of them, tested with
//     SemverRange.Contains (introduced <= v < fixed). A version that
//     falls outside every declared range does NOT match (Requirement 8.5).
//   - the AffectedPackage declares NO ranges at all, in which case the whole
//     package is treated as affected and the purl-name match alone is
//     sufficient. This is the conservative, deterministic reading for an
//     "all versions" advisory: ranges are the mechanism by which a source
//     narrows the affected set, so their absence means the source did not
//     narrow it. (Requirement 8.5 constrains only the case where ranges exist
//     and none contain the version.)
//
// Entries are evaluated in slice order and the first match wins, so the result
// is deterministic for a given input. When nothing matches, matched is false
// and the returned AffectedPackage is the zero value.
//
// pkgPurlName must be the purl name (no version qualifier); use SplitPurl to
// derive it from a versioned graph purl.
func MatchPackage(vulnAffected []AffectedPackage, pkgPurlName, pkgVersion string) (matched bool, ap AffectedPackage) {
	name := strings.TrimSpace(pkgPurlName)
	version := strings.TrimSpace(pkgVersion)
	for _, cand := range vulnAffected {
		if strings.TrimSpace(cand.Purl) != name {
			continue
		}
		if len(cand.Ranges) == 0 {
			// No ranges declared: the whole package is affected.
			return true, cand
		}
		for _, rng := range cand.Ranges {
			if rng.Contains(version) {
				return true, cand
			}
		}
		// Purl name matched but the version fell outside every declared
		// range: per Requirement 8.5 this is NOT a match. Keep scanning in
		// case another entry for the same purl covers this version.
	}
	return false, AffectedPackage{}
}
