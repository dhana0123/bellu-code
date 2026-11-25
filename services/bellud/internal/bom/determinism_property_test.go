package bom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"
)

var detHashLens = map[string]int{"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128}

var detHashAlgs = []string{"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"}

var detLicensePool = []string{"MIT", "Apache-2.0", "GPL-3.0-only", "BSD-3-Clause", "MIT OR Apache-2.0", "(MIT AND Zlib)", "LicenseRef-custom"}

var detPurlTypes = []string{"npm", "pypi", "golang", "cargo", "gem", "maven", "deb"}

var detTypes = []string{"", "library", "application", "framework", "container"}

func detPackage() *rapid.Generator[Package] {
	name := rapid.StringMatching(`[a-z][a-z0-9-]{0,7}`)
	version := rapid.StringMatching(`[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}`)
	return rapid.Custom(func(t *rapid.T) Package {
		p := Package{
			Type: rapid.SampledFrom(detTypes).Draw(t, "type"),
			Name: name.Draw(t, "name"),
		}
		if rapid.Bool().Draw(t, "hasVersion") {
			v := version.Draw(t, "version")
			p.Version = &v
		}
		if rapid.IntRange(0, 3).Draw(t, "purlKind") > 0 {
			eco := rapid.SampledFrom(detPurlTypes).Draw(t, "eco")
			purl := "pkg:" + eco + "/" + p.Name
			if eco == "golang" {
				purl = "pkg:golang/example.com/" + p.Name
			}
			if eco == "maven" || eco == "deb" {
				purl = "pkg:" + eco + "/acme/" + p.Name
			}
			if p.Version != nil {
				purl += "@" + *p.Version
			}
			p.Purl, p.Ecosystem = &purl, eco
		}
		p.Licenses = rapid.SliceOfN(rapid.SampledFrom(detLicensePool), 0, 4).Draw(t, "licenses")
		if rapid.Bool().Draw(t, "hasSupplier") {
			s := rapid.StringMatching(`[A-Za-z][A-Za-z ]{0,9}`).Draw(t, "supplier")
			p.Supplier = &s
		}
		p.Locations = rapid.SliceOfN(rapid.StringMatching(`[a-z]{1,4}/[a-z]{1,4}\.json`), 0, 4).Draw(t, "locations")
		for _, alg := range rapid.SliceOfNDistinct(rapid.SampledFrom(detHashAlgs), 0, 3, rapid.ID[string]).Draw(t, "algs") {
			v := rapid.StringMatching(fmt.Sprintf(`[0-9a-f]{%d}`, detHashLens[alg])).Draw(t, "hash")
			p.Hashes = append(p.Hashes, Hash{Algorithm: alg, Value: v})
		}
		if props := rapid.MapOfN(rapid.StringMatching(`[a-z]{1,5}`), rapid.StringMatching(`[a-z0-9]{0,5}`), 0, 4).Draw(t, "props"); len(props) > 0 {
			p.Properties = props
		}
		return p
	})
}

// detSBOM draws packages and appends exact and near duplicates (same name,
// version and purl, other fields redrawn).
func detSBOM() *rapid.Generator[SBOM] {
	return rapid.Custom(func(t *rapid.T) SBOM {
		pkgs := rapid.SliceOfN(detPackage(), 0, 60).Draw(t, "packages")
		if len(pkgs) > 0 {
			for range rapid.IntRange(0, 10).Draw(t, "dups") {
				d := detClone(pkgs[rapid.IntRange(0, len(pkgs)-1).Draw(t, "dupOf")])
				if rapid.Bool().Draw(t, "near") {
					o := detPackage().Draw(t, "dupOther")
					d.Licenses, d.Supplier, d.Hashes, d.Properties = o.Licenses, o.Supplier, o.Hashes, o.Properties
				}
				pkgs = append(pkgs, d)
			}
		}
		s := SBOM{Packages: pkgs}
		if rapid.Bool().Draw(t, "hasSubject") {
			s.Subject = rapid.StringMatching(`[a-z]{1,6}/[a-z]{1,6}`).Draw(t, "subject")
		}
		return s
	})
}

func detClone(p Package) Package {
	c := p
	c.Licenses = append([]string(nil), p.Licenses...)
	c.Locations = append([]string(nil), p.Locations...)
	c.Hashes = append([]Hash(nil), p.Hashes...)
	if p.Properties != nil {
		c.Properties = make(map[string]string, len(p.Properties))
		for k, v := range p.Properties {
			c.Properties[k] = v
		}
	}
	return c
}

func detShuffle[T any](t *rapid.T, label string, in []T) []T {
	out := append([]T(nil), in...)
	for i := len(out) - 1; i > 0; i-- {
		j := rapid.IntRange(0, i).Draw(t, label)
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// detShuffled returns a copy with the packages, the inner lists and the map
// insertion order permuted.
func detShuffled(t *rapid.T, s SBOM) SBOM {
	out := SBOM{Subject: s.Subject}
	for _, p := range detShuffle(t, "pkgOrder", s.Packages) {
		c := detClone(p)
		c.Licenses = detShuffle(t, "licOrder", c.Licenses)
		c.Locations = detShuffle(t, "locOrder", c.Locations)
		c.Hashes = detShuffle(t, "hashOrder", c.Hashes)
		if p.Properties != nil {
			keys := make([]string, 0, len(p.Properties))
			for k := range p.Properties {
				keys = append(keys, k)
			}
			c.Properties = make(map[string]string, len(keys))
			for _, k := range detShuffle(t, "propOrder", keys) {
				c.Properties[k] = p.Properties[k]
			}
		}
		out.Packages = append(out.Packages, c)
	}
	return out
}

// detOrder returns the per-package identifiers in document order.
func detOrder(t *rapid.T, f Format, doc []byte) []string {
	var parsed struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
		Packages []struct {
			SPDXID string `json:"SPDXID"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	var ids []string
	if f == FormatSPDXJSON {
		for _, p := range parsed.Packages {
			ids = append(ids, p.SPDXID)
		}
	} else {
		for _, c := range parsed.Components {
			ids = append(ids, c.BOMRef)
		}
	}
	return ids
}

// Feature: bellu-wiz-security-platform, Property 12: SBOM export is deterministic apart from timestamp and serial number
//
// Validates: Requirements 5.8
func TestProperty12SBOMExportDeterministic(t *testing.T) {
	targets := []struct {
		format  Format
		version string
	}{
		{FormatCycloneDXJSON, "1.5"}, {FormatCycloneDXJSON, "1.6"}, {FormatCycloneDXJSON, "1.7"}, {FormatSPDXJSON, "2.3"},
	}
	const (
		time1, time2, time3 = "2026-01-02T03:04:05Z", "2031-06-07T08:09:10Z", "2036-11-12T13:14:15Z"
		ser1, ser2, ser3    = "urn:uuid:11111111-1111-4111-8111-111111111111", "urn:uuid:22222222-2222-4222-8222-222222222222", "urn:uuid:33333333-3333-4333-8333-333333333333"
	)
	export := func(t *rapid.T, s SBOM, f Format, v, now, serial string) []byte {
		ts, err := time.Parse(time.RFC3339, now)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = Write(context.Background(), &buf, s, Options{Format: f, Version: v,
			Now: func() time.Time { return ts }, Serial: func() string { return serial }})
		if err != nil {
			t.Fatalf("%s %s: %v", f, v, err)
		}
		// Replace the injected values, so the raw bytes and byte order are compared.
		b := bytes.ReplaceAll(buf.Bytes(), []byte(now), []byte(time1))
		return bytes.ReplaceAll(b, []byte(serial), []byte(ser1))
	}
	rapid.Check(t, func(t *rapid.T) {
		s := detSBOM().Draw(t, "sbom")
		shuffled := detShuffled(t, s)
		for _, tg := range targets {
			a := export(t, s, tg.format, tg.version, time1, ser1)
			b := export(t, s, tg.format, tg.version, time2, ser2)
			c := export(t, shuffled, tg.format, tg.version, time3, ser3)
			if !bytes.Equal(a, b) {
				t.Fatalf("%s %s: repeated export differs\n%s\n%s", tg.format, tg.version, a, b)
			}
			if !reflect.DeepEqual(detOrder(t, tg.format, a), detOrder(t, tg.format, b)) {
				t.Fatalf("%s %s: package order differs between repeated exports", tg.format, tg.version)
			}
			if !bytes.Equal(a, c) {
				t.Fatalf("%s %s: shuffled input changes export\n%s\n%s", tg.format, tg.version, a, c)
			}
			if !reflect.DeepEqual(detOrder(t, tg.format, a), detOrder(t, tg.format, c)) {
				t.Fatalf("%s %s: package order differs for shuffled input", tg.format, tg.version)
			}
		}
	})
}
