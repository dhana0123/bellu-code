// Package bom reads and writes software bills of materials. Writers stream
// their output and order components so that two exports of the same content
// are byte-identical apart from the serial number and timestamp.
package bom

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Format names an export format.
type Format string

// FormatCycloneDXJSON is the CycloneDX JSON format.
const FormatCycloneDXJSON Format = "cyclonedx-json"

// FormatSPDXJSON is the SPDX JSON format.
const FormatSPDXJSON Format = "spdx-json"

// DefaultCycloneDXVersion is used when Options.Version is empty.
const DefaultCycloneDXVersion = "1.6"

// supported lists the versions of each implemented format.
var supported = map[Format][]string{
	FormatCycloneDXJSON: {"1.5", "1.6", "1.7"},
	FormatSPDXJSON:      {"2.3"},
}

// ErrUnsupportedFormat is returned for a format that is not implemented. The
// error text lists the supported formats and versions.
var ErrUnsupportedFormat = errors.New("bom: unsupported format")

// ErrUnsupportedVersion is returned for a version the format does not support.
var ErrUnsupportedVersion = errors.New("bom: unsupported version")

// ErrInvalidPackage is returned when a package cannot be exported, for example
// when a package with a known ecosystem has no valid purl.
var ErrInvalidPackage = errors.New("bom: invalid package")

// Hash is a content hash of a package.
type Hash struct {
	Algorithm string // e.g. "SHA-256"
	Value     string
}

// Package is one entry of an SBOM. A nil pointer or empty slice means the
// source did not provide that field; it is omitted on export.
type Package struct {
	Type       string // CycloneDX component type; empty means "library"
	Name       string
	Version    *string
	Purl       *string
	Ecosystem  string   // purl type such as "golang", "npm", "deb"; empty if unknown
	Licenses   []string // SPDX license ids or expressions
	Supplier   *string
	Locations  []string // file paths where the package was found
	Hashes     []Hash
	Properties map[string]string
}

// SBOM is a package list for one asset.
type SBOM struct {
	Subject  string // optional asset name, written to metadata.component
	Packages []Package
}

// knownEcosystems are the purl types for which a package must have a purl.
var knownEcosystems = map[string]bool{
	"golang": true, "npm": true, "pypi": true, "maven": true, "cargo": true,
	"gem": true, "composer": true, "nuget": true, "apk": true, "deb": true, "rpm": true,
}

func unsupportedFormat(f Format) error {
	return fmt.Errorf("%w %q; supported: %s", ErrUnsupportedFormat, f, supportedList())
}

func unsupportedVersion(f Format, v string) error {
	return fmt.Errorf("%w %q for %s; supported: %s", ErrUnsupportedVersion, v, f, strings.Join(supported[f], ", "))
}

func supportedList() string {
	formats := make([]string, 0, len(supported))
	for f := range supported {
		formats = append(formats, string(f))
	}
	sort.Strings(formats)
	parts := make([]string, len(formats))
	for i, f := range formats {
		parts[i] = f + " (" + strings.Join(supported[Format(f)], ", ") + ")"
	}
	return strings.Join(parts, "; ")
}

func versionSupported(f Format, v string) bool {
	for _, s := range supported[f] {
		if s == v {
			return true
		}
	}
	return false
}
