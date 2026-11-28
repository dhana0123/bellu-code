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

func spdxOpts() Options {
	o := testOpts("")
	o.Format = FormatSPDXJSON
	return o
}

func TestSPDXGolden(t *testing.T) {
	got := write(t, fixture(), spdxOpts())
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile("testdata/golden-spdx-2.3.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/golden-spdx-2.3.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("output differs from testdata/golden-spdx-2.3.json (run with UPDATE_GOLDEN=1)\n%s", got)
	}
}

type spdxDoc struct {
	Namespace string `json:"documentNamespace"`
	Packages  []struct {
		Name     string                       `json:"name"`
		ID       string                       `json:"SPDXID"`
		Declared string                       `json:"licenseDeclared"`
		Supplier string                       `json:"supplier"`
		Checksum []struct{ Algorithm string } `json:"checksums"`
	} `json:"packages"`
	Relationships []struct{ SpdxElementID, RelationshipType, RelatedSpdxElement string }
}

func TestSPDXOrderingAndDeterminism(t *testing.T) {
	s := fixture()
	rev := SBOM{Subject: s.Subject}
	for i := len(s.Packages) - 1; i >= 0; i-- {
		rev.Packages = append(rev.Packages, s.Packages[i])
	}
	a, b := write(t, s, spdxOpts()), write(t, rev, spdxOpts())
	if !bytes.Equal(a, b) {
		t.Fatalf("input order changed output:\n%s\n%s", a, b)
	}
	// Differing clock and serial only change created and documentNamespace.
	o := spdxOpts()
	o.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	o.Serial = func() string { return "urn:uuid:00000000-0000-4000-8000-000000000002" }
	c := write(t, s, o)
	c = bytes.ReplaceAll(c, []byte("2030-01-01T00:00:00Z"), []byte("2026-01-02T03:04:05Z"))
	c = bytes.ReplaceAll(c, []byte("0000-4000-8000-000000000002"), []byte("0000-4000-8000-000000000001"))
	if !bytes.Equal(a, c) {
		t.Fatal("outputs differ beyond created and documentNamespace")
	}

	var doc spdxDoc
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	var names []string
	ids := map[string]bool{}
	for _, p := range doc.Packages {
		names = append(names, p.Name)
		ids[p.ID] = true
		if !strings.HasPrefix(p.ID, "SPDXRef-Package-") {
			t.Errorf("id = %s", p.ID)
		}
	}
	if want := []string{"app", "Left-Pad", "dual", "zlib"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("order = %v, want %v", names, want)
	}
	if len(ids) != 4 || len(doc.Relationships) != 4 {
		t.Fatalf("ids = %v, relationships = %+v", ids, doc.Relationships)
	}
	for _, r := range doc.Relationships {
		if r.SpdxElementID != "SPDXRef-DOCUMENT" || r.RelationshipType != "DESCRIBES" || !ids[r.RelatedSpdxElement] {
			t.Errorf("relationship = %+v", r)
		}
	}
	if !strings.HasSuffix(doc.Namespace, "urn:uuid:00000000-0000-4000-8000-000000000001") {
		t.Errorf("namespace = %s", doc.Namespace)
	}
}

func TestSPDXMapping(t *testing.T) {
	var doc spdxDoc
	if err := json.Unmarshal(write(t, fixture(), spdxOpts()), &doc); err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for i, p := range doc.Packages {
		by[p.Name] = i
	}
	app, lp, dual := doc.Packages[by["app"]], doc.Packages[by["Left-Pad"]], doc.Packages[by["dual"]]
	if app.Declared != "NOASSERTION" || app.Supplier != "NOASSERTION" {
		t.Errorf("absent fields: %+v", app)
	}
	if lp.Declared != "Apache-2.0 AND MIT" || lp.Supplier != "Organization: Acme" {
		t.Errorf("left-pad: %+v", lp)
	}
	if got := []string{lp.Checksum[0].Algorithm, lp.Checksum[1].Algorithm}; !reflect.DeepEqual(got, []string{"SHA256", "SHA512"}) {
		t.Errorf("checksum algorithms = %v", got)
	}
	if dual.Declared != "MIT OR Apache-2.0" {
		t.Errorf("dual = %s", dual.Declared)
	}
}

func TestSPDXEmptySBOM(t *testing.T) {
	out := write(t, SBOM{}, spdxOpts())
	var doc spdxDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Packages) != 0 || len(doc.Relationships) != 1 || doc.Relationships[0].RelatedSpdxElement != "NONE" {
		t.Fatalf("doc = %+v", doc)
	}
	got, err := ReadSPDX(bytes.NewReader(out))
	if err != nil || len(got.Packages) != 0 {
		t.Fatalf("read back = %+v, %v", got, err)
	}
}

func TestSPDXUnsupported(t *testing.T) {
	var buf bytes.Buffer
	o := spdxOpts()
	o.Version = "2.2"
	err := Write(context.Background(), &buf, fixture(), o)
	if !errors.Is(err, ErrUnsupportedVersion) || !strings.Contains(err.Error(), "2.3") || buf.Len() != 0 {
		t.Errorf("2.2: err = %v, wrote %d", err, buf.Len())
	}
	err = Write(context.Background(), &buf, fixture(), Options{Format: "xml"})
	if !errors.Is(err, ErrUnsupportedFormat) || !strings.Contains(err.Error(), "spdx-json (2.3)") {
		t.Errorf("format error = %v", err)
	}
	for _, in := range []string{
		`{"spdxVersion":"SPDX-2.2","SPDXID":"SPDXRef-DOCUMENT"}`,
		`{"spdxVersion":"SPDX-3.0"}`,
	} {
		if _, err := ReadSPDX(strings.NewReader(in)); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%s: %v", in, err)
		}
	}
	for _, in := range []string{`not json`, `{"bomFormat":"CycloneDX"}`} {
		if _, err := ReadSPDX(strings.NewReader(in)); err == nil || errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestSPDXInvalidPackageWritesNothing(t *testing.T) {
	for _, p := range []Package{
		{Name: "x", Ecosystem: "npm"},
		{Name: "x", Purl: sp("not-a-purl")},
		{Name: "x", Hashes: []Hash{{"CRC32", "00"}}},
	} {
		var buf bytes.Buffer
		err := Write(context.Background(), &buf, SBOM{Packages: []Package{p}}, spdxOpts())
		if !errors.Is(err, ErrInvalidPackage) || buf.Len() != 0 {
			t.Errorf("%+v: err = %v, wrote %d", p, err, buf.Len())
		}
	}
}

func TestSPDXDuplicateIDsStayUnique(t *testing.T) {
	p := Package{Name: "a", Version: sp("1"), Purl: sp("pkg:npm/a@1"), Ecosystem: "npm"}
	var doc spdxDoc
	if err := json.Unmarshal(write(t, SBOM{Packages: []Package{p, p}}, spdxOpts()), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Packages) != 2 || doc.Packages[0].ID == doc.Packages[1].ID {
		t.Fatalf("ids = %+v", doc.Packages)
	}
}

func TestSPDXRoundTrip(t *testing.T) {
	want := fixture()
	got, err := ReadSPDX(bytes.NewReader(write(t, want, spdxOpts())))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != want.Subject || len(got.Packages) != len(want.Packages) {
		t.Fatalf("got %+v", got)
	}
	by := map[string]Package{}
	for _, p := range got.Packages {
		by[p.Name] = p
	}
	// The writer canonicalizes the purl and sorts and dedupes lists.
	wantPkgs := map[string]Package{
		"zlib": {Name: "zlib", Version: sp("1.2.13"), Purl: sp("pkg:deb/debian/zlib@1.2.13?arch=amd64"), Ecosystem: "deb",
			Licenses: []string{"Zlib"}, Locations: []string{"/var/lib/dpkg/status"}},
		"Left-Pad": {Name: "Left-Pad", Version: sp("1.3.0"), Purl: sp("pkg:npm/left-pad@1.3.0"), Ecosystem: "npm",
			Licenses: []string{"Apache-2.0", "MIT"}, Supplier: sp("Acme"),
			Hashes:     []Hash{{"SHA-256", strings.Repeat("a", 64)}, {"SHA-512", strings.Repeat("b", 128)}},
			Locations:  []string{"a/package.json", "b/package.json"},
			Properties: map[string]string{"z": "1", "a": "2"}},
		"app":  {Name: "app", Type: "framework"},
		"dual": {Name: "dual", Version: sp("1"), Purl: sp("pkg:golang/example.com/dual@1"), Ecosystem: "golang", Licenses: []string{"MIT OR Apache-2.0"}},
	}
	for name, w := range wantPkgs {
		if !reflect.DeepEqual(by[name], w) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, by[name], w)
		}
	}
}

func TestSPDXReadForeignDocumentDerivesEcosystem(t *testing.T) {
	in := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x","dataLicense":"CC0-1.0",
"documentNamespace":"https://example.com/x","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: other"]},
"packages":[{"name":"a","SPDXID":"SPDXRef-a","versionInfo":"1","downloadLocation":"NOASSERTION","licenseDeclared":"NONE",
"supplier":"Person: Bob","comment":"hello",
"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:pypi/a@1"}],
"checksums":[{"algorithm":"SHA1","checksumValue":"ff"}]}]}`
	got, err := ReadSPDX(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := Package{Name: "a", Version: sp("1"), Purl: sp("pkg:pypi/a@1"), Ecosystem: "pypi", Supplier: sp("Bob"), Hashes: []Hash{{"SHA-1", "ff"}}}
	if len(got.Packages) != 1 || !reflect.DeepEqual(got.Packages[0], want) {
		t.Fatalf("got %+v", got.Packages)
	}
}

func TestSPDXSchemaValidation(t *testing.T) {
	c := jsonschema.NewCompiler()
	f, err := os.Open("testdata/schema/spdx-2.3.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	schemaDoc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("http://spdx.org/rdf/terms/2.3", schemaDoc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("http://spdx.org/rdf/terms/2.3")
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]SBOM{"fixture": fixture(), "empty": {}, "bare": {Packages: []Package{{Name: "bare"}}}} {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(write(t, s, spdxOpts())))
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(doc); err != nil {
			t.Errorf("%s does not validate: %v", name, err)
		}
	}
}
