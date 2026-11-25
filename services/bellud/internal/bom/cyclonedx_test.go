package bom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func sp(s string) *string { return &s }

func fixture() SBOM {
	return SBOM{
		Subject: "repo/app",
		Packages: []Package{
			{Name: "zlib", Version: sp("1.2.13"), Purl: sp("pkg:deb/debian/zlib@1.2.13?arch=amd64"), Ecosystem: "deb",
				Licenses: []string{"Zlib"}, Locations: []string{"/var/lib/dpkg/status"}},
			{Name: "Left-Pad", Version: sp("1.3.0"), Purl: sp("pkg:NPM/left-pad@1.3.0"), Ecosystem: "npm",
				Licenses: []string{"MIT", "Apache-2.0", "MIT"}, Supplier: sp("Acme"),
				Hashes:     []Hash{{"SHA-512", strings.Repeat("b", 128)}, {"SHA-256", strings.Repeat("a", 64)}},
				Locations:  []string{"b/package.json", "a/package.json"},
				Properties: map[string]string{"z": "1", "a": "2"}},
			{Name: "app", Type: "framework"},
			{Name: "dual", Version: sp("1"), Purl: sp("pkg:golang/example.com/dual@1"), Ecosystem: "golang",
				Licenses: []string{"MIT OR Apache-2.0"}},
		},
	}
}

func testOpts(version string) Options {
	return Options{
		Version: version,
		Now:     func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		Serial:  func() string { return "urn:uuid:00000000-0000-4000-8000-000000000001" },
	}
}

func write(t *testing.T, s SBOM, o Options) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(context.Background(), &buf, s, o); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGolden(t *testing.T) {
	got := write(t, fixture(), testOpts(""))
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile("testdata/golden-1.6.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/golden-1.6.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("output differs from testdata/golden-1.6.json (run with UPDATE_GOLDEN=1)\n%s", got)
	}
}

func TestOrderingAndDeterminism(t *testing.T) {
	s := fixture()
	rev := SBOM{Subject: s.Subject}
	for i := len(s.Packages) - 1; i >= 0; i-- {
		rev.Packages = append(rev.Packages, s.Packages[i])
	}
	a, b := write(t, s, testOpts("1.5")), write(t, rev, testOpts("1.5"))
	if !bytes.Equal(a, b) {
		t.Fatalf("input order changed output:\n%s\n%s", a, b)
	}
	// Differing clock and serial only change those two fields.
	o := testOpts("1.5")
	o.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	o.Serial = func() string { return "urn:uuid:00000000-0000-4000-8000-000000000002" }
	c := write(t, s, o)
	c = bytes.ReplaceAll(c, []byte("2030-01-01T00:00:00Z"), []byte("2026-01-02T03:04:05Z"))
	c = bytes.ReplaceAll(c, []byte("0000-4000-8000-000000000002"), []byte("0000-4000-8000-000000000001"))
	if !bytes.Equal(a, c) {
		t.Fatal("outputs differ beyond serialNumber and timestamp")
	}
	var doc struct {
		Components []struct{ Type, Name string }
	}
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range doc.Components {
		names = append(names, c.Type+"/"+c.Name)
	}
	want := []string{"framework/app", "library/Left-Pad", "library/dual", "library/zlib"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("order = %v, want %v", names, want)
	}
}

func TestAbsentFieldsOmitted(t *testing.T) {
	out := string(write(t, SBOM{Packages: []Package{{Name: "bare"}}}, testOpts("")))
	comp := out[strings.Index(out, `"components"`):]
	for _, key := range []string{`"version"`, `"purl"`, `"licenses"`, `"supplier"`, `"hashes"`, `"evidence"`, `"properties"`} {
		if strings.Contains(comp, key) {
			t.Errorf("component carries %s: %s", key, comp)
		}
	}
}

func TestEmptySBOM(t *testing.T) {
	out := write(t, SBOM{}, testOpts(""))
	if !bytes.Contains(out, []byte(`"components":[]}`)) {
		t.Fatalf("no empty component list: %s", out)
	}
	got, err := ReadCycloneDX(bytes.NewReader(out))
	if err != nil || len(got.Packages) != 0 {
		t.Fatalf("read back = %+v, %v", got, err)
	}
}

func TestUnsupportedWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		o    Options
		err  error
		text string
	}{
		{Options{Format: "xml"}, ErrUnsupportedFormat, "cyclonedx-json (1.5, 1.6, 1.7)"},
		{Options{Version: "1.4"}, ErrUnsupportedVersion, "1.5, 1.6, 1.7"},
		{Options{Version: "2.0"}, ErrUnsupportedVersion, "1.5, 1.6, 1.7"},
	} {
		var buf bytes.Buffer
		err := Write(context.Background(), &buf, fixture(), tc.o)
		if !errors.Is(err, tc.err) || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%+v: err = %v", tc.o, err)
		}
		if buf.Len() != 0 {
			t.Errorf("%+v: wrote %d bytes", tc.o, buf.Len())
		}
	}
}

func TestInvalidPackageWritesNothing(t *testing.T) {
	for _, p := range []Package{
		{Name: "x", Ecosystem: "npm"},
		{Name: "x", Purl: sp("not-a-purl")},
	} {
		var buf bytes.Buffer
		err := Write(context.Background(), &buf, SBOM{Packages: []Package{p}}, testOpts(""))
		if !errors.Is(err, ErrInvalidPackage) || buf.Len() != 0 {
			t.Errorf("%+v: err = %v, wrote %d", p, err, buf.Len())
		}
	}
}

func TestPurlCanonicalizedKeepingQualifiers(t *testing.T) {
	out := string(write(t, fixture(), testOpts("")))
	for _, want := range []string{`"purl":"pkg:npm/left-pad@1.3.0"`, `"purl":"pkg:deb/debian/zlib@1.2.13?arch=amd64"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestDuplicateBomRefsStayUnique(t *testing.T) {
	p := Package{Name: "a", Version: sp("1"), Purl: sp("pkg:npm/a@1"), Ecosystem: "npm"}
	var doc struct {
		Components []struct {
			Ref string `json:"bom-ref"`
		}
	}
	if err := json.Unmarshal(write(t, SBOM{Packages: []Package{p, p}}, testOpts("")), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 2 || doc.Components[0].Ref == doc.Components[1].Ref {
		t.Fatalf("refs = %+v", doc.Components)
	}
}

func TestRoundTrip(t *testing.T) {
	want := fixture()
	got, err := ReadCycloneDX(bytes.NewReader(write(t, want, testOpts(""))))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != want.Subject || len(got.Packages) != len(want.Packages) {
		t.Fatalf("got %+v", got)
	}
	pairs := map[string]bool{}
	for _, p := range got.Packages {
		if p.Purl != nil {
			pairs[*p.Purl+"|"+deref(p.Version)] = true
		}
	}
	for _, k := range []string{"pkg:npm/left-pad@1.3.0|1.3.0", "pkg:deb/debian/zlib@1.2.13?arch=amd64|1.2.13", "pkg:golang/example.com/dual@1|1"} {
		if !pairs[k] {
			t.Errorf("missing pair %s in %v", k, pairs)
		}
	}
	for _, p := range got.Packages {
		if p.Name == "Left-Pad" {
			if !reflect.DeepEqual(p.Licenses, []string{"Apache-2.0", "MIT"}) || p.Ecosystem != "npm" ||
				deref(p.Supplier) != "Acme" || p.Properties["a"] != "2" ||
				!reflect.DeepEqual(p.Locations, []string{"a/package.json", "b/package.json"}) {
				t.Errorf("left-pad = %+v", p)
			}
		}
		if p.Name == "app" && (p.Version != nil || p.Purl != nil || p.Licenses != nil || p.Hashes != nil || p.Properties != nil) {
			t.Errorf("absent fields came back present: %+v", p)
		}
	}
}

func TestReadRejectsOldVersionAndForeignDocs(t *testing.T) {
	if _, err := ReadCycloneDX(strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("1.4: %v", err)
	}
	if _, err := ReadCycloneDX(strings.NewReader(`{"bomFormat":"other","specVersion":"1.6"}`)); err == nil {
		t.Error("foreign bomFormat accepted")
	}
	if _, err := ReadCycloneDX(strings.NewReader(`not json`)); err == nil {
		t.Error("garbage accepted")
	}
}

func compileSchema(t *testing.T, version string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	for name, id := range map[string]string{
		"cryptography-defs.schema.json":   "http://cyclonedx.org/schema/cryptography-defs.schema.json",
		"spdx.schema.json":                "http://cyclonedx.org/schema/spdx.schema.json",
		"jsf-0.82.schema.json":            "http://cyclonedx.org/schema/jsf-0.82.schema.json",
		"bom-" + version + ".schema.json": "http://cyclonedx.org/schema/bom-" + version + ".schema.json",
	} {
		f, err := os.Open("testdata/schema/" + name)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(id, doc); err != nil {
			t.Fatal(err)
		}
	}
	sch, err := c.Compile("http://cyclonedx.org/schema/bom-" + version + ".schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func TestSchemaValidation(t *testing.T) {
	for _, v := range []string{"1.5", "1.6", "1.7"} {
		t.Run(v, func(t *testing.T) {
			sch := compileSchema(t, v)
			for name, s := range map[string]SBOM{"fixture": fixture(), "empty": {}} {
				doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(write(t, s, testOpts(v))))
				if err != nil {
					t.Fatal(err)
				}
				if err := sch.Validate(doc); err != nil {
					t.Errorf("%s does not validate against %s: %v", name, v, err)
				}
			}
		})
	}
}
