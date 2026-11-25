package bom

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"pgregory.net/rapid"
)

// rtPair is one (purl, version) pair of a package that has a purl.
type rtPair struct{ purl, version string }

var (
	rtNameGen = rapid.StringMatching(`[A-Za-z][A-Za-z0-9._-]{0,11}`)
	// Versions use the special characters + ~ : - and ".".
	rtVersionGen = rapid.StringMatching(`[0-9A-Za-z][0-9A-Za-z.+~:-]{0,11}`)
	rtQualGen    = rapid.StringMatching(`[a-z0-9_.-]{1,8}`)
)

// rtPurlGen draws a package with a valid purl for one of the known
// ecosystems, or a package without a purl (empty ecosystem).
func rtPurlGen() *rapid.Generator[Package] {
	return rapid.Custom(func(t *rapid.T) Package {
		name := rtNameGen.Draw(t, "name")
		eco := rapid.SampledFrom([]string{"", "golang", "npm", "pypi", "maven", "cargo", "gem", "composer", "nuget", "apk", "deb", "rpm"}).Draw(t, "eco")
		p := Package{Name: name, Ecosystem: eco}
		if rapid.IntRange(0, 4).Draw(t, "hasVersion") > 0 {
			v := rtVersionGen.Draw(t, "version")
			p.Version = &v
		}
		if eco == "" {
			return p
		}
		path := name
		switch eco {
		case "maven":
			path = rtNameGen.Draw(t, "group") + "." + rtNameGen.Draw(t, "group2") + "/" + name
		case "golang":
			path = "example.com/" + rtNameGen.Draw(t, "owner") + "/" + name
		case "npm":
			if rapid.Bool().Draw(t, "scoped") {
				path = "%40" + rtNameGen.Draw(t, "scope") + "/" + name
			}
		case "deb", "rpm", "apk":
			path = rapid.SampledFrom([]string{"debian", "ubuntu", "alpine", "fedora"}).Draw(t, "distroNs") + "/" + name
		}
		purl := "pkg:" + eco + "/" + path
		if p.Version != nil {
			purl += "@" + *p.Version
		}
		if eco == "deb" || eco == "rpm" || eco == "apk" {
			purl += "?arch=" + rapid.SampledFrom([]string{"amd64", "arm64", "x86_64"}).Draw(t, "arch")
			purl += "&distro=" + rtQualGen.Draw(t, "distro")
		}
		if rapid.IntRange(0, 5).Draw(t, "subpath") == 0 {
			purl += "#" + rtNameGen.Draw(t, "sub") + "/" + rtNameGen.Draw(t, "sub2")
		}
		p.Purl = &purl
		return p
	})
}

// rtLargeUsed counts the large cases of the current run so there are few.
var rtLargeUsed int

func rtSBOMGen() *rapid.Generator[SBOM] {
	pkgs := rtPurlGen()
	return rapid.Custom(func(t *rapid.T) SBOM {
		large := rtLargeUsed < 3 && rapid.IntRange(0, 59).Draw(t, "largeRoll") == 0
		if !large {
			return SBOM{Subject: "asset", Packages: rapid.SliceOfN(pkgs, 0, 50).Draw(t, "pkgs")}
		}
		rtLargeUsed++
		n := rapid.IntRange(1000, 10000).Draw(t, "n")
		pool := rapid.SliceOfN(pkgs, 20, 20).Draw(t, "pool")
		out := make([]Package, n)
		for i := range out {
			p := pool[i%len(pool)]
			if p.Purl != nil && p.Version != nil && i >= len(pool) {
				// Make the pair unique while keeping the purl valid.
				v := fmt.Sprintf("%s+%d", *p.Version, i)
				purl := fmt.Sprintf("%s@%s", rtStripVersion(*p.Purl, *p.Version), v)
				purl += rtTail(*p.Purl)
				p.Version, p.Purl = &v, &purl
			}
			out[i] = p
		}
		return SBOM{Subject: "asset", Packages: out}
	})
}

// rtStripVersion returns the purl up to, not including, "@version".
func rtStripVersion(purl, version string) string {
	i := bytes.LastIndex([]byte(purl), []byte("@"+version))
	return purl[:i]
}

// rtTail returns the qualifiers and subpath of a purl, with the leading
// character, or "".
func rtTail(purl string) string {
	if i := bytes.IndexAny([]byte(purl), "?#"); i >= 0 {
		return purl[i:]
	}
	return ""
}

func rtPairs(pkgs []Package, normalize bool) (map[rtPair]bool, error) {
	m := map[rtPair]bool{}
	for _, p := range pkgs {
		if p.Purl == nil {
			continue
		}
		purl := *p.Purl
		if normalize {
			c, ok := canonicalPurl(purl)
			if !ok {
				return nil, fmt.Errorf("canonicalPurl rejected %q", purl)
			}
			purl = c
		}
		m[rtPair{purl, deref(p.Version)}] = true
	}
	return m, nil
}

func rtNames(pkgs []Package) []string {
	n := make([]string, len(pkgs))
	for i, p := range pkgs {
		n[i] = p.Name
	}
	slices.Sort(n)
	return n
}

// Feature: bellu-wiz-security-platform, Property 11: SBOM round trip preserves purl and version pairs
//
// **Validates: Requirements 5.5**
func TestSBOMRoundTripProperty(t *testing.T) {
	rtLargeUsed = 0
	rapid.Check(t, func(t *rapid.T) {
		in := rtSBOMGen().Draw(t, "sbom")
		format := rapid.SampledFrom([]Format{FormatCycloneDXJSON, FormatSPDXJSON}).Draw(t, "format")
		version := "2.3"
		if format == FormatCycloneDXJSON {
			version = rapid.SampledFrom([]string{"1.5", "1.6", "1.7"}).Draw(t, "version")
		}

		var buf bytes.Buffer
		if err := Write(context.Background(), &buf, in, Options{Format: format, Version: version}); err != nil {
			t.Fatalf("Write(%s %s) rejected %d generated packages: %v", format, version, len(in.Packages), err)
		}
		var out SBOM
		var err error
		if format == FormatCycloneDXJSON {
			out, err = ReadCycloneDX(&buf)
		} else {
			out, err = ReadSPDX(&buf)
		}
		if err != nil {
			t.Fatalf("read back %s %s: %v", format, version, err)
		}

		if len(out.Packages) != len(in.Packages) {
			t.Fatalf("package count: wrote %d, read %d", len(in.Packages), len(out.Packages))
		}
		if a, b := rtNames(in.Packages), rtNames(out.Packages); !slices.Equal(a, b) {
			t.Fatalf("package names changed")
		}
		want, err := rtPairs(in.Packages, true)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := rtPairs(out.Packages, false)
		for p := range want {
			if !got[p] {
				t.Fatalf("%s %s lost pair %+v", format, version, p)
			}
		}
		for p := range got {
			if !want[p] {
				t.Fatalf("%s %s added pair %+v", format, version, p)
			}
		}
	})
}
