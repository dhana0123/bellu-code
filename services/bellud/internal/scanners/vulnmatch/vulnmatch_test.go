package vulnmatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/correlate"
	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
	"github.com/bellu/bellucode/services/bellud/internal/risk"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/testutil/noexternal"
)

func TestMain(m *testing.M) { noexternal.Main(m) }

const testdata = "../testdata"

// fixtureVulns are the advisories for the known-vulnerable fixture packages
// listed in testdata/README.md, with the ranges of the public advisories.
var fixtureVulns = []model.Vuln{
	vuln("CVE-2021-38561", "pkg:golang/golang.org/x/text", "0", "0.3.7", model.SevHigh, 7.5, false, 0.01),
	vuln("CVE-2019-11254", "pkg:golang/gopkg.in/yaml.v2", "0", "2.2.8", model.SevMedium, 6.5, false, 0.02),
	vuln("CVE-2021-23337", "pkg:npm/lodash", "0", "4.17.21", model.SevHigh, 7.2, false, 0.03),
	{
		ID: "CVE-2021-44906", Summary: "minimist prototype pollution", Severity: model.SevCritical,
		CVSS: model.CVSS{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Version: "3.1"}, EPSS: 0.5,
		Affected: []model.AffectedPackage{{Purl: "pkg:npm/minimist", Ranges: []model.SemverRange{{Introduced: "0", Fixed: "0.2.4"}, {Introduced: "1.0.0", Fixed: "1.2.6"}}}},
	},
	vuln("CVE-2018-18074", "pkg:pypi/requests", "0", "2.20.0", model.SevHigh, 7.5, false, 0.04),
	vuln("CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core", "2.0-beta9", "2.15.0", model.SevCritical, 10, true, 0.97),
	vuln("CVE-2020-26235", "pkg:cargo/time", "0", "0.2.23", model.SevMedium, 6.2, false, 0.001),
	vuln("RUSTSEC-2019-0009", "pkg:cargo/smallvec", "0", "0.6.10", model.SevCritical, 9.8, false, 0.02),
	vuln("CVE-2018-16471", "pkg:gem/rack", "0", "2.0.6", model.SevMedium, 6.1, false, 0.05),
	vuln("CVE-2022-29248", "pkg:composer/guzzlehttp/guzzle", "0", "6.5.7", model.SevMedium, 5.9, false, 0.01),
	vuln("CVE-2024-21907", "pkg:nuget/Newtonsoft.Json", "0", "13.0.1", model.SevHigh, 7.5, false, 0.01),
	vuln("CVE-2021-3711", "pkg:apk/alpine/libcrypto1.1", "0", "1.1.1l-r0", model.SevCritical, 9.8, false, 0.1),
	vuln("CVE-2018-25032", "pkg:deb/debian/zlib1g", "0", "1:1.2.11.dfsg-2+deb11u1", model.SevHigh, 7.5, false, 0.2),
}

func vuln(id, purl, intro, fixed string, sev model.Severity, cvss float64, kev bool, epss float64) model.Vuln {
	return model.Vuln{
		ID: id, Summary: id + " summary", Severity: sev, KnownExploited: kev, EPSS: epss,
		CVSS:     model.CVSS{Score: cvss, Vector: "CVSS:3.1/AV:N", Version: "3.1"},
		Affected: []model.AffectedPackage{{Purl: purl, Ranges: []model.SemverRange{{Introduced: intro, Fixed: fixed}}, FixedIn: []string{fixed}}},
	}
}

func seed(t testing.TB, vs []model.Vuln) *cvesource.DB {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "intel"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if vs != nil {
		var sb strings.Builder
		for _, v := range vs {
			b, _ := json.Marshal(v)
			sb.Write(b)
			sb.WriteByte('\n')
		}
		if err := s.Replace(context.Background(), store.ImportInfo{Version: "t1", CreatedAt: time.Now()}, strings.NewReader(sb.String())); err != nil {
			t.Fatal(err)
		}
	}
	d, err := cvesource.New(cvesource.Options{Store: s})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func newAdapter(t testing.TB, o Options) *Adapter {
	t.Helper()
	if o.Source == nil {
		o.Source = seed(t, fixtureVulns)
	}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// recSink records every call, so a test can prove nothing was written.
type recSink struct {
	mu       sync.Mutex
	calls    int
	findings []findings.Finding
	errs     [][2]string
	batches  []batch.Batch
}

func (s *recSink) Findings(fs []findings.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.findings = append(s.findings, fs...)
	return nil
}
func (s *recSink) ScannerError(in, cause string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.errs = append(s.errs, [2]string{in, cause})
	return nil
}
func (s *recSink) Seen(string) {}
func (s *recSink) Batch(b batch.Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.batches = append(s.batches, b)
	return nil
}

func (s *recSink) byRule(id string) []findings.Finding {
	var out []findings.Finding
	for _, f := range s.findings {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}

func repo(name string) scanners.Target {
	return scanners.Target{Type: scanners.TargetRepository, ID: "repo-" + name, Path: filepath.Join(testdata, "repos", name)}
}

func pk(purl, name, version string) bom.Package {
	p := bom.Package{Name: name, Purl: &purl}
	if version != "" {
		p.Version = &version
	}
	return p
}

type details2 struct {
	Purl          string
	Version       string
	VulnID        string `json:"vuln_id"`
	Aliases       []string
	State         string
	CVSS          *float64
	CVSSVector    *string  `json:"cvss_vector"`
	FixedVersions []string `json:"fixed_versions"`
	KEV           bool
	EPSS          *float64
	LayerDigest   string `json:"layer_digest"`
}

func parseDetails(t *testing.T, f findings.Finding) details2 {
	t.Helper()
	var d details2
	if err := json.Unmarshal(f.Details, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestInfoAndApplies(t *testing.T) {
	a := newAdapter(t, Options{})
	i := a.Info()
	if a.Kind() != scanners.KindVulnerability || i.Name != "vulnmatch" || i.Version == "" || i.Libraries["grype"] == "" {
		t.Fatalf("info %+v kind %s", i, a.Kind())
	}
	if !a.Applies(scanners.TargetHost) || !a.Applies(scanners.TargetImage) || !a.Applies(scanners.TargetRepository) || a.Applies(scanners.TargetCluster) {
		t.Error("Applies")
	}
	if _, err := New(Options{}); err == nil {
		t.Error("New without a source succeeded")
	}
}

// Each fixture repository gives the findings listed in testdata/README.md,
// with the discriminator purl@version#vuln_id, severity, fixed versions, KEV
// and EPSS from the seeded advisory, and an affected_by edge to the vulnerability.
func TestFixtureFindings(t *testing.T) {
	tests := []struct {
		dir, purl, version, vuln string
		sev                      findings.Severity
		fixed                    []string
		kev                      bool
		epss                     float64
	}{
		{"go", "pkg:golang/golang.org/x/text", "v0.3.5", "CVE-2021-38561", findings.SevHigh, []string{"0.3.7"}, false, 0.01},
		{"go", "pkg:golang/gopkg.in/yaml.v2", "v2.2.2", "CVE-2019-11254", findings.SevMedium, []string{"2.2.8"}, false, 0.02},
		{"npm", "pkg:npm/lodash", "4.17.20", "CVE-2021-23337", findings.SevHigh, []string{"4.17.21"}, false, 0.03},
		{"npm", "pkg:npm/minimist", "1.2.5", "CVE-2021-44906", findings.SevCritical, []string{"1.2.6"}, false, 0.5},
		{"python", "pkg:pypi/requests", "2.19.0", "CVE-2018-18074", findings.SevHigh, []string{"2.20.0"}, false, 0.04},
		{"java", "pkg:maven/org.apache.logging.log4j/log4j-core", "2.14.1", "CVE-2021-44228", findings.SevCritical, []string{"2.15.0"}, true, 0.97},
		{"rust", "pkg:cargo/time", "0.1.43", "CVE-2020-26235", findings.SevMedium, []string{"0.2.23"}, false, 0.001},
		{"rust", "pkg:cargo/smallvec", "0.6.9", "RUSTSEC-2019-0009", findings.SevCritical, []string{"0.6.10"}, false, 0.02},
		{"ruby", "pkg:gem/rack", "2.0.5", "CVE-2018-16471", findings.SevMedium, []string{"2.0.6"}, false, 0.05},
		{"php", "pkg:composer/guzzlehttp/guzzle", "6.3.0", "CVE-2022-29248", findings.SevMedium, []string{"6.5.7"}, false, 0.01},
		{"dotnet", "pkg:nuget/Newtonsoft.Json", "12.0.1", "CVE-2024-21907", findings.SevHigh, []string{"13.0.1"}, false, 0.01},
		{"apk", "pkg:apk/alpine/libcrypto1.1", "1.1.1k-r0", "CVE-2021-3711", findings.SevCritical, []string{"1.1.1l-r0"}, false, 0.1},
		{"deb", "pkg:deb/debian/zlib1g", "1:1.2.11.dfsg-2", "CVE-2018-25032", findings.SevHigh, []string{"1:1.2.11.dfsg-2+deb11u1"}, false, 0.2},
	}
	a := newAdapter(t, Options{})
	sinks := map[string]*recSink{}
	for _, tt := range tests {
		if sinks[tt.dir] == nil {
			sinks[tt.dir] = &recSink{}
			if err := a.Run(context.Background(), repo(tt.dir), sinks[tt.dir]); err != nil {
				t.Fatalf("%s: %v", tt.dir, err)
			}
		}
	}
	for _, tt := range tests {
		t.Run(tt.vuln, func(t *testing.T) {
			s := sinks[tt.dir]
			tg := repo(tt.dir)
			want := findings.ID(tt.vuln, tg.ID, tt.purl+"@"+tt.version+"#"+tt.vuln)
			var got *findings.Finding
			for i, f := range s.findings {
				if f.ID == want {
					got = &s.findings[i]
				}
			}
			if got == nil {
				t.Fatalf("no finding %s; have %d findings", want, len(s.findings))
			}
			if got.Type != findings.TypeVulnerability || got.Category != schema.OvVuln || got.RuleID != tt.vuln ||
				got.AssetID != tg.ID || got.Severity != tt.sev || got.UnmappedSeverity || got.Status != findings.StatusOpen ||
				got.Source != string(scanners.KindVulnerability) {
				t.Fatalf("finding %+v", *got)
			}
			if got.RiskScore == nil || *got.RiskScore < 0 || *got.RiskScore > 100 {
				t.Fatalf("risk score %v", got.RiskScore)
			}
			d := parseDetails(t, *got)
			if d.State != "affected" || d.Version != tt.version || d.VulnID != tt.vuln || d.KEV != tt.kev ||
				d.EPSS == nil || *d.EPSS != tt.epss || !slices.Equal(d.FixedVersions, tt.fixed) || d.Aliases == nil || d.CVSS == nil || d.CVSSVector == nil {
				t.Fatalf("details %s", got.Details)
			}
			if d.LayerDigest != "" {
				t.Errorf("repository finding has layer %q", d.LayerDigest)
			}
			// Exposure and criticality are unknown and the package is not
			// known to be reachable (7.7).
			if want := risk.Compute(risk.Inputs{CVSS: *d.CVSS, EPSS: tt.epss, KEV: tt.kev}); *got.RiskScore != want {
				t.Errorf("risk score %v, want %v", *got.RiskScore, want)
			}

			// The affected_by relation starts at the package entity the Syft
			// adapter writes and ends at the correlator's vulnerability entity.
			vid, err := correlate.VulnEntityID(tt.vuln)
			if err != nil {
				t.Fatal(err)
			}
			var vb *batch.Batch
			for i := range s.batches {
				if strings.HasPrefix(s.batches[i].Collector, Name+":") {
					vb = &s.batches[i]
				}
			}
			if vb == nil {
				t.Fatal("no vulnerability batch")
			}
			if !slices.ContainsFunc(vb.Relations, func(r batch.Relation) bool { return r.Type == correlate.RelAffectedBy && r.To == vid }) {
				t.Errorf("no affected_by edge to %s", tt.vuln)
			}
			if !slices.ContainsFunc(vb.Entities, func(e batch.Entity) bool { return e.Type == correlate.KindVulnerability && e.Identity["id"] == tt.vuln }) {
				t.Errorf("no vulnerability entity %s", tt.vuln)
			}
		})
	}
}

// The vulnerability entity has the identity and attributes of the correlator,
// so the two merge.
func TestEntityMatchesCorrelator(t *testing.T) {
	src := seed(t, fixtureVulns)
	a := newAdapter(t, Options{Source: src})
	s := bom.SBOM{Packages: []bom.Package{pk("pkg:npm/lodash@4.17.20", "lodash", "4.17.20")}}
	res, err := a.Match(context.Background(), repo("npm"), s)
	if err != nil || len(res.Batch.Entities) != 1 || len(res.Batch.Relations) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	h, _ := identity.Hash("package", map[string]string{"connection": "syft", "scope": "repo-npm", "purl": "pkg:npm/lodash@4.17.20"})
	vid, _ := correlate.VulnEntityID("CVE-2021-23337")
	if r := res.Batch.Relations[0]; r.From != string(h) || r.To != vid || r.Type != "affected_by" {
		t.Fatalf("relation %+v", r)
	}

	lk := lookupFunc(func(name string) ([]model.Vuln, error) {
		var out []model.Vuln
		for _, v := range fixtureVulns {
			if v.Affected[0].Purl == name {
				out = append(out, v)
			}
		}
		return out, nil
	})
	want, err := correlate.Plan([]correlate.Pkg{{ID: string(h), Purl: "pkg:npm/lodash@4.17.20"}}, lk)
	if err != nil || len(want.Entities) != 1 {
		t.Fatalf("plan %+v %v", want, err)
	}
	got := res.Batch.Entities[0]
	if got.Type != want.Entities[0].Type || fmt.Sprint(got.Identity) != fmt.Sprint(want.Entities[0].Identity) ||
		fmt.Sprint(got.Attributes) != fmt.Sprint(want.Entities[0].Attributes) {
		t.Fatalf("entity differs from the correlator's:\n got %+v\nwant %+v", got, want.Entities[0])
	}
}

type lookupFunc func(string) ([]model.Vuln, error)

func (f lookupFunc) ByPurl(n string) ([]model.Vuln, error) { return f(n) }

func TestNotAffectedGivesNoFinding(t *testing.T) {
	a := newAdapter(t, Options{})
	s := bom.SBOM{Packages: []bom.Package{
		pk("pkg:npm/lodash@4.17.21", "lodash", "4.17.21"),          // the fixed version
		pk("pkg:npm/lodash@4.18.0", "lodash", "4.18.0"),            // above the fix
		pk("pkg:npm/minimist@0.2.5", "minimist", "0.2.5"),          // between the two ranges
		pk("pkg:npm/minimist@1.2.6", "minimist", "1.2.6"),          // fixed
		pk("pkg:npm/unrelated@1.0.0", "unrelated", "1.0.0"),        // no advisory
		pk("pkg:pypi/requests@2.20.0rc1", "requests", "2.20.0rc1"), // PEP 440: 2.20.0rc1 < 2.20.0, so still affected
	}}
	res, err := a.Match(context.Background(), repo("npm"), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "CVE-2018-18074" {
		t.Fatalf("findings %+v", res.Findings)
	}
}

func TestUnknownVersionGivesInfo(t *testing.T) {
	a := newAdapter(t, Options{})
	s := bom.SBOM{Packages: []bom.Package{pk("pkg:npm/lodash", "lodash", ""), pk("pkg:npm/minimist", "minimist", "")}}
	res, err := a.Match(context.Background(), repo("npm"), s)
	if err != nil || len(res.Findings) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, f := range res.Findings {
		d := parseDetails(t, f)
		if f.Severity != findings.SevInfo || d.State != "unknown" || f.UnmappedSeverity {
			t.Errorf("%s: severity %s state %s", f.RuleID, f.Severity, d.State)
		}
		if f.RiskScore == nil || *f.RiskScore >= 10 {
			t.Errorf("%s: unknown score %v belongs outside the info bucket", f.RuleID, f.RiskScore)
		}
	}
	if len(res.Batch.Relations) != 0 {
		t.Errorf("unknown matches wrote %d relations", len(res.Batch.Relations))
	}
}

func TestImageLayerDigest(t *testing.T) {
	a := newAdapter(t, Options{})
	tg := scanners.Target{Type: scanners.TargetImage, ID: "img-1", Path: filepath.Join(testdata, "images", "sample.tar")}
	s := &recSink{}
	if err := a.Run(context.Background(), tg, s); err != nil {
		t.Fatal(err)
	}
	layers := map[string]string{}
	for _, f := range s.findings {
		d := parseDetails(t, f)
		if d.LayerDigest == "" || !slices.ContainsFunc(f.Evidence, func(e findings.EvidenceRef) bool { return e.Kind == "layer" && e.Ref == d.LayerDigest }) {
			t.Errorf("%s: layer digest missing: %s", f.RuleID, f.Details)
		}
		layers[f.RuleID] = d.LayerDigest
	}
	if len(layers) != 2 || layers["CVE-2021-3711"] == "" || layers["CVE-2021-3711"] == layers["CVE-2021-23337"] {
		t.Fatalf("layers %v", layers)
	}

	// A package with no layer digest still gets its finding, with the digest empty.
	res, err := a.Match(context.Background(), tg, bom.SBOM{Packages: []bom.Package{pk("pkg:npm/lodash@4.17.20", "lodash", "4.17.20")}})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if d := parseDetails(t, res.Findings[0]); d.LayerDigest != "" {
		t.Errorf("layer %q", d.LayerDigest)
	}
}

func TestSourceUnavailableWritesNothing(t *testing.T) {
	empty := seed(t, nil) // store opened, no data installed
	tests := map[string]cvesource.Source{"no data installed": empty}
	nostore, err := cvesource.New(cvesource.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tests["no store"] = nostore
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			a := newAdapter(t, Options{Source: src})
			s := &recSink{}
			err := a.Run(context.Background(), repo("npm"), s)
			if !errors.Is(err, ErrCVESourceUnavailable) || !strings.Contains(err.Error(), "CVE_Source unavailable") {
				t.Fatalf("err = %v", err)
			}
			if s.calls != 0 {
				t.Fatalf("sink got %d calls", s.calls)
			}
		})
	}
}

func writeVEX(t *testing.T, doc string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const vexDocument = `{
 "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/vex/1", "version": 1,
 "statements": [
  {"vulnerability": {"name": "CVE-2021-23337"}, "products": [{"@id": "pkg:npm/lodash@4.17.20"}],
   "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
  {"vulnerability": {"name": "CVE-2021-44906"}, "products": [{"@id": "pkg:npm/minimist@9.9.9"}], "status": "not_affected"},
  {"vulnerability": {"name": "CVE-2018-18074"}, "products": [{"@id": "pkg:pypi/requests"}], "status": "under_investigation"}
 ]}`

func TestVEXSuppression(t *testing.T) {
	vp := writeVEX(t, vexDocument)
	a := newAdapter(t, Options{VEXPath: vp})
	s := &recSink{}
	if err := a.Run(context.Background(), repo("npm"), s); err != nil {
		t.Fatal(err)
	}
	if got := s.byRule("CVE-2021-23337"); len(got) != 0 {
		t.Fatalf("lodash finding not suppressed: %+v", got)
	}
	if len(s.byRule("CVE-2021-44906")) != 1 {
		t.Fatal("a statement for another version suppressed minimist")
	}
	for _, b := range s.batches {
		for _, r := range b.Relations {
			vid, _ := correlate.VulnEntityID("CVE-2021-23337")
			if r.To == vid {
				t.Error("suppressed finding kept its affected_by edge")
			}
		}
	}

	res, err := a.Match(context.Background(), repo("npm"), bom.SBOM{Packages: []bom.Package{pk("pkg:npm/lodash@4.17.20", "lodash", "4.17.20")}})
	if err != nil || len(res.Findings) != 0 || len(res.Suppressed) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	ev := res.Suppressed[0].Evidence
	if i := slices.IndexFunc(ev, func(e findings.EvidenceRef) bool { return e.Kind == "vex" }); i < 0 ||
		ev[i].Ref != vp || !strings.Contains(ev[i].Excerpt, "vulnerable_code_not_in_execute_path") {
		t.Fatalf("evidence %+v", ev)
	}
}

func TestVEXFileUnreadableKeepsFindings(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.json")
	a := newAdapter(t, Options{VEXPath: missing})
	s := &recSink{}
	if err := a.Run(context.Background(), repo("npm"), s); err != nil {
		t.Fatal(err)
	}
	if len(s.byRule("CVE-2021-23337")) != 1 || len(s.errs) != 1 || s.errs[0][0] != missing {
		t.Fatalf("findings %d errs %v", len(s.findings), s.errs)
	}
}

func TestHostSkipsUnreadablePath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	host := scanners.Target{Type: scanners.TargetHost, ID: "host-1", Path: repo("npm").Path}
	a := newAdapter(t, Options{HostPaths: []string{missing, repo("python").Path}})
	s := &recSink{}
	if err := a.Run(context.Background(), host, s); err != nil {
		t.Fatal(err)
	}
	if len(s.errs) != 1 || s.errs[0][0] != missing || !strings.Contains(s.errs[0][1], missing) {
		t.Fatalf("errors %v", s.errs)
	}
	if len(s.byRule("CVE-2021-23337")) != 1 || len(s.byRule("CVE-2018-18074")) != 1 {
		t.Fatalf("the readable paths were not scanned: %d findings", len(s.findings))
	}

	// No readable path at all fails the scan.
	a = newAdapter(t, Options{})
	s = &recSink{}
	err := a.Run(context.Background(), scanners.Target{Type: scanners.TargetHost, ID: "host-2", Path: missing}, s)
	if !errors.Is(err, scanners.ErrTargetUnreachable) || !strings.Contains(err.Error(), missing) {
		t.Fatalf("err = %v", err)
	}
	if len(s.findings) != 0 {
		t.Error("findings written")
	}
}

func TestHostSkipsPermissionDeniedPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	denied := filepath.Join(t.TempDir(), "denied")
	if err := os.Mkdir(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(denied, 0o700) })
	host := scanners.Target{Type: scanners.TargetHost, ID: "host-3", Path: repo("npm").Path}
	a := newAdapter(t, Options{HostPaths: []string{denied}})
	s := &recSink{}
	if err := a.Run(context.Background(), host, s); err != nil {
		t.Fatal(err)
	}
	if len(s.errs) != 1 || s.errs[0][0] != denied || len(s.byRule("CVE-2021-23337")) != 1 {
		t.Fatalf("errs %v findings %d", s.errs, len(s.findings))
	}
}

// Version ordering follows each ecosystem, not a generic dotted comparison.
func TestInRangesUsesEcosystemOrdering(t *testing.T) {
	tests := []struct {
		ptype, ver, intro, fixed string
		inside                   bool
	}{
		{"pypi", "1.0rc1", "0", "1.0", true},     // PEP 440 pre-release sorts before the release
		{"pypi", "1.0.post1", "0", "1.0", false}, // post-release sorts after
		{"pypi", "1.0", "0", "1.0.0", false},     // 1.0 == 1.0.0
		{"maven", "2.0-beta9", "2.0-beta9", "2.15.0", true},
		{"maven", "2.14.1", "2.0-beta9", "2.15.0", true},
		{"maven", "2.15.0", "2.0-beta9", "2.15.0", false},
		{"deb", "1:1.0-1", "0", "2.0-1", false}, // epoch 1 outranks 2.0
		{"deb", "1.2.11.dfsg-2", "0", "1.2.11.dfsg-2+deb11u1", true},
		{"apk", "1.1.1k-r0", "0", "1.1.1l-r0", true},
		{"golang", "v0.3.5", "0", "0.3.7", true},
		{"npm", "4.17.21", "0", "4.17.21", false},
		{"cargo", "0.1.43", "0", "0.2.23", true},
	}
	for _, tt := range tests {
		inside, decided := inRanges(tt.ptype, tt.ver, []cvesource.Range{{Introduced: tt.intro, Fixed: tt.fixed}})
		if !decided || inside != tt.inside {
			t.Errorf("%s %s in [%s,%s): inside=%v decided=%v, want %v", tt.ptype, tt.ver, tt.intro, tt.fixed, inside, decided, tt.inside)
		}
	}
	if _, decided := inRanges("unknowneco", "1", []cvesource.Range{{Fixed: "2"}}); decided {
		t.Error("an ecosystem with no comparator was decided")
	}
	if inside, decided := inRanges("npm", "1", nil); !inside || !decided {
		t.Error("no ranges means every version is affected")
	}
}

// 1,000 packages match within 5 s (Requirement 7.9). The store holds 100
// advisories; one package in ten is vulnerable.
func TestMatchThousandPackages(t *testing.T) {
	if testing.Short() {
		t.Skip("timing check")
	}
	var vs []model.Vuln
	for i := 0; i < 100; i++ {
		vs = append(vs, vuln(fmt.Sprintf("CVE-2024-%04d", i), fmt.Sprintf("pkg:npm/pkg-%d", i*10), "0", "2.0.0", model.SevHigh, 7.5, i%7 == 0, 0.1))
	}
	a := newAdapter(t, Options{Source: seed(t, vs)})
	var s bom.SBOM
	for i := 0; i < 1000; i++ {
		s.Packages = append(s.Packages, pk(fmt.Sprintf("pkg:npm/pkg-%d@1.0.0", i), fmt.Sprintf("pkg-%d", i), "1.0.0"))
	}
	sink := &recSink{}
	start := time.Now()
	res, err := a.match(context.Background(), repo("npm"), s, nil)
	if err == nil {
		err = sink.Batch(res.Batch)
	}
	if err == nil {
		err = sink.Findings(res.Findings)
	}
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("matched 1000 packages, %d findings, in %s", len(res.Findings), took)
	if len(res.Findings) != 100 {
		t.Fatalf("findings = %d, want 100", len(res.Findings))
	}
	if took >= 5*time.Second {
		t.Fatalf("took %s, want under 5s", took)
	}
}
