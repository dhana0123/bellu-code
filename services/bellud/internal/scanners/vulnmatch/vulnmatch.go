// Package vulnmatch is the vulnerability scanner adapter. It matches every
// package of an SBOM to known vulnerabilities in the CVE_Source and reports
// one Finding(type=vulnerability) per (package, vulnerability), plus an
// affected_by relation from the package to the vulnerability (Requirements
// 7.1 to 7.8, 7.11, 7.12).
//
// Matching approach. cvesource owns the candidate lookup (intel store and the
// local CVE graph, DB_Mode, no network). Grype's matchers are not used:
// they read Grype's own database through a vulnerability.Provider and depend on
// Grype namespaces, distro and CPE records that cvesource data does not carry.
// What is reused is Grype's version package, which orders versions with the
// native rules of each ecosystem (PEP 440, Maven, deb, apk, rpm, gem, Go,
// semantic). Under the `osvmatch` build tag OSV-Scanner's version library
// answers first for PyPI, Maven, NuGet, RubyGems and Packagist. Both run
// in-process and offline.
package vulnmatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/correlate"
	"github.com/bellu/bellucode/services/bellud/internal/cvesource"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
	"github.com/bellu/bellucode/services/bellud/internal/risk"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/syft"
)

// Name is the adapter name. It is also the Finding source revision prefix.
const Name = "vulnmatch"

// adapterVersion changes when matching output changes for the same inputs.
const adapterVersion = "1"

// ErrCVESourceUnavailable means no CVE data could be read when the scan
// started (Requirement 7.11).
var ErrCVESourceUnavailable = errors.New("vulnmatch: CVE_Source unavailable")

// syftConnection is the connection identity attribute of the package entities
// the Syft adapter writes (syft/graph.go). affected_by edges start there.
const syftConnection = "syft"

// maxUnknownScore keeps the Risk_Score of an `unknown` match in the `info`
// bucket (below 10), matching its severity (Requirement 7.10).
const maxUnknownScore = 9.99

// SBOMScanner produces the package list of a target. *syft.Adapter is the
// default.
//
// TODO(14.2): read the latest sbom_snapshot row instead of scanning again once
// snapshot persistence lands.
type SBOMScanner interface {
	Scan(ctx context.Context, t scanners.Target) (bom.SBOM, error)
}

// Options configures New.
type Options struct {
	// Source is the CVE_Source. Required.
	Source cvesource.Source
	// SBOM lists the packages of a target. Default syft.New().
	SBOM SBOMScanner
	// VEXPath is an optional OpenVEX JSON file. `not_affected` statements
	// suppress matching findings (Requirement 7.8).
	VEXPath string
	// HostPaths are extra roots scanned for a host target besides Target.Path
	// (the paths the host collector reports). An unreadable one is skipped with
	// an error row naming it (Requirement 7.12).
	HostPaths []string
	// Workers bounds concurrent lookups. Default min(8, CPU count).
	Workers int
}

// Adapter implements scanners.Adapter for vulnerability matching.
type Adapter struct{ o Options }

var _ scanners.Adapter = (*Adapter)(nil)

// New returns the adapter. It fails when no CVE_Source is given.
func New(o Options) (*Adapter, error) {
	if o.Source == nil {
		return nil, errors.New("vulnmatch: a CVE_Source is required")
	}
	if o.SBOM == nil {
		o.SBOM = syft.New()
	}
	if o.Workers <= 0 {
		o.Workers = min(8, runtime.NumCPU())
	}
	return &Adapter{o: o}, nil
}

// Kind implements scanners.Adapter.
func (*Adapter) Kind() scanners.Kind { return scanners.KindVulnerability }

// Info implements scanners.Adapter.
func (*Adapter) Info() scanners.Info {
	libs := map[string]string{
		"grype":     moduleVersion("github.com/anchore/grype", "v0.122.1"),
		"cvesource": "db",
	}
	if OSVEnabled {
		libs["osv-scalibr"] = moduleVersion("github.com/google/osv-scalibr", "unknown")
	}
	return scanners.Info{Name: Name, Version: adapterVersion, License: "Apache-2.0", Libraries: libs}
}

func moduleVersion(path, fallback string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return fallback
	}
	for _, d := range bi.Deps {
		if d.Path == path && d.Version != "" {
			return d.Version
		}
	}
	return fallback
}

// Applies implements scanners.Adapter.
func (*Adapter) Applies(t scanners.TargetType) bool {
	return t == scanners.TargetRepository || t == scanners.TargetImage || t == scanners.TargetHost
}

// Digest implements scanners.Adapter. The result of a match depends on the CVE
// data as well as the content, and cvesource exposes no data revision, so the
// digest is empty and the job always runs.
func (*Adapter) Digest(context.Context, scanners.Target) (string, error) { return "", nil }

// Run lists the packages of the target, matches them and writes the graph
// batch and the findings. When the CVE_Source is unavailable at start it
// returns ErrCVESourceUnavailable before any write, so findings and relations
// of earlier runs stay unchanged (Requirement 7.11).
func (a *Adapter) Run(ctx context.Context, t scanners.Target, out scanners.Sink) error {
	if err := a.checkSource(); err != nil {
		return err
	}
	sbom, err := a.collect(ctx, t, out)
	if err != nil {
		return err
	}
	var vex *vexSet
	if a.o.VEXPath != "" {
		if vex, err = loadVEX(a.o.VEXPath); err != nil {
			// Findings still go out, unsuppressed, and the row names the file.
			if rerr := out.ScannerError(a.o.VEXPath, err.Error()); rerr != nil {
				return errors.Join(err, rerr)
			}
		}
	}
	res, err := a.match(ctx, t, sbom, vex)
	if err != nil {
		return a.fail(out, t, err)
	}
	for _, e := range res.Errors {
		if err := out.ScannerError(e.Input, e.Cause); err != nil {
			return err
		}
	}
	// The package entities that affected_by points at come from the SBOM
	// batch; applying it here is the same write the sbom scan makes.
	sb, err := syft.Batch(t, sbom)
	if err != nil {
		return a.fail(out, t, err)
	}
	if err := out.Batch(sb); err != nil {
		return a.fail(out, t, err)
	}
	if len(res.Batch.Relations) > 0 {
		if err := out.Batch(res.Batch); err != nil {
			return a.fail(out, t, err)
		}
	}
	if len(res.Findings) == 0 {
		return nil
	}
	return out.Findings(res.Findings)
}

func (a *Adapter) fail(out scanners.Sink, t scanners.Target, err error) error {
	err = fmt.Errorf("vulnmatch: asset %q: %w", assetName(t), err)
	if rerr := out.ScannerError(assetName(t), err.Error()); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

// checkSource fails when the CVE_Source has no readable data. Status reports
// an unreadable store as not installed.
func (a *Adapter) checkSource() error {
	st := a.o.Source.Status()
	if !st.DBInstalled {
		return fmt.Errorf("%w: no readable local CVE data (mode %s)", ErrCVESourceUnavailable, st.Mode)
	}
	return nil
}

// collect returns the SBOM of the target. A host scan reads Target.Path and
// every HostPaths root; an unreadable root gets an error row naming it and the
// scan continues with the others (Requirement 7.12). It fails when no root
// could be read.
func (a *Adapter) collect(ctx context.Context, t scanners.Target, out scanners.Sink) (bom.SBOM, error) {
	if t.Type != scanners.TargetHost {
		s, err := a.o.SBOM.Scan(ctx, t)
		if err != nil {
			return bom.SBOM{}, a.fail(out, t, err)
		}
		return s, nil
	}
	paths := append([]string{t.Path}, a.o.HostPaths...)
	merged := bom.SBOM{Subject: assetName(t)}
	var errs []error
	for _, p := range paths {
		pt := t
		pt.Path = p
		s, err := a.o.SBOM.Scan(ctx, pt)
		if err != nil {
			errs = append(errs, fmt.Errorf("skipped path %s: %w", p, err))
			if rerr := out.ScannerError(p, "skipped path "+p+": "+err.Error()); rerr != nil {
				return bom.SBOM{}, rerr
			}
			continue
		}
		merged.Packages = append(merged.Packages, s.Packages...)
	}
	if len(errs) == len(paths) {
		return bom.SBOM{}, fmt.Errorf("vulnmatch: asset %q: no host path could be read: %w", assetName(t), errors.Join(errs...))
	}
	return merged, nil
}

func assetName(t scanners.Target) string {
	if t.ID != "" {
		return t.ID
	}
	return t.Path
}

// InputError is a package that could not be matched.
type InputError struct{ Input, Cause string }

// Result is the output of Match.
type Result struct {
	// Findings are the open findings, sorted by id.
	Findings []findings.Finding
	// Suppressed are matches a VEX `not_affected` statement removed. They carry
	// the VEX source in evidence and are not reported to the findings store.
	Suppressed []findings.Finding
	// Batch holds the vulnerability entities and affected_by relations of the
	// `affected` matches.
	Batch  batch.Batch
	Errors []InputError
}

// pkgRef is one distinct (purl name, version) of the SBOM.
type pkgRef struct {
	name, purlName, ptype, version, layer string
	purls                                 []string // full purls, one package entity each
}

func (p *pkgRef) key() string { return p.purlName + "@" + p.version }

// Match matches the SBOM against the CVE_Source and builds findings and the
// graph batch. It writes nothing. It reads the VEX file of Options.VEXPath
// and fails when that file cannot be read.
func (a *Adapter) Match(ctx context.Context, t scanners.Target, s bom.SBOM) (Result, error) {
	var vex *vexSet
	if a.o.VEXPath != "" {
		var err error
		if vex, err = loadVEX(a.o.VEXPath); err != nil {
			return Result{}, err
		}
	}
	return a.match(ctx, t, s, vex)
}

// match is Match with the VEX set already loaded; vex may be nil.
//
// Lookups run once per distinct purl name and once per distinct
// (purl name, version), spread over a worker pool, so the cost does not grow
// with the number of packages that share a name.
func (a *Adapter) match(ctx context.Context, t scanners.Target, s bom.SBOM, vex *vexSet) (Result, error) {
	var res Result
	refs := dedupe(s)

	type job struct {
		purl, version string
		out           []cvesource.Vuln
		err           error
	}
	var jobs []*job
	byName := map[string]*job{}
	byKey := map[string]*job{}
	for _, p := range refs {
		if byName[p.purlName] == nil {
			byName[p.purlName] = &job{purl: p.purlName}
			jobs = append(jobs, byName[p.purlName])
		}
		if p.version != "" {
			j := &job{purl: p.purlName, version: p.version}
			byKey[p.key()] = j
			jobs = append(jobs, j)
		}
	}
	work := make(chan *job)
	var wg sync.WaitGroup
	for range min(a.o.Workers, max(len(jobs), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				r, err := a.o.Source.Lookup(ctx, cvesource.LookupQuery{Purl: j.purl, Version: j.version})
				j.out, j.err = r.Data, err
			}
		}()
	}
feed:
	for _, j := range jobs {
		select {
		case work <- j:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return res, err
	}

	type matched struct {
		pkg   *pkgRef
		vuln  cvesource.Vuln
		state string
		fixed []string
	}
	var ms []matched
	for _, p := range refs {
		var jerr error
		cands := map[string]cand{}
		if j := byKey[p.key()]; j != nil {
			jerr = errors.Join(jerr, j.err)
			for _, v := range j.out {
				cands[v.ID] = cand{v: v, versioned: true}
			}
		}
		if j := byName[p.purlName]; j != nil {
			jerr = errors.Join(jerr, j.err)
			for _, v := range j.out {
				if _, ok := cands[v.ID]; !ok {
					cands[v.ID] = cand{v: v}
				}
			}
		}
		if jerr != nil {
			if errors.Is(jerr, cvesource.ErrInvalidQuery) {
				res.Errors = append(res.Errors, InputError{p.key(), "package skipped: " + jerr.Error()})
				continue
			}
			return res, fmt.Errorf("%w: lookup %s: %v", ErrCVESourceUnavailable, p.key(), jerr)
		}
		for _, c := range cands {
			state, ok := decide(p, c)
			if !ok {
				continue
			}
			ms = append(ms, matched{p, c.v, state, upgrades(p, c.v.FixedVersions)})
		}
	}
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].pkg.key() != ms[j].pkg.key() {
			return ms[i].pkg.key() < ms[j].pkg.key()
		}
		return ms[i].vuln.ID < ms[j].vuln.ID
	})

	assetEntity := map[string]model.Vuln{}
	fixedFor := map[string][]string{}
	type edge struct{ from, to string }
	seenEdge := map[edge]bool{}
	for _, m := range ms {
		f := a.finding(t, m.pkg, m.vuln, m.state, m.fixed)
		if reason, ok := vex.notAffected(m.pkg.purls[0], m.vuln.ID, m.vuln.Aliases); ok {
			f.Status = findings.StatusIgnored
			f.Evidence = append(f.Evidence, findings.EvidenceRef{
				Kind: "vex", Ref: vex.source, Excerpt: vexExcerpt(vex, reason),
			})
			res.Suppressed = append(res.Suppressed, f)
			continue
		}
		res.Findings = append(res.Findings, f)
		if m.state != cvesource.StateAffected {
			continue
		}
		toID, err := correlate.VulnEntityID(m.vuln.ID)
		if err != nil {
			return res, err
		}
		assetEntity[m.vuln.ID] = toModel(m.vuln)
		fixedFor[m.vuln.ID] = append(fixedFor[m.vuln.ID], m.fixed...)
		for _, purl := range m.pkg.purls {
			h, err := identity.Hash("package", map[string]string{"connection": syftConnection, "scope": assetName(t), "purl": purl})
			if err != nil {
				return res, fmt.Errorf("package %q identity: %w", purl, err)
			}
			e := edge{string(h), toID}
			if seenEdge[e] {
				continue
			}
			seenEdge[e] = true
			res.Batch.Relations = append(res.Batch.Relations, batch.Relation{Type: correlate.RelAffectedBy, From: e.from, To: e.to})
		}
	}
	sort.Slice(res.Findings, func(i, j int) bool { return res.Findings[i].ID < res.Findings[j].ID })
	sort.Slice(res.Suppressed, func(i, j int) bool { return res.Suppressed[i].ID < res.Suppressed[j].ID })
	sort.Slice(res.Batch.Relations, func(i, j int) bool {
		x, y := res.Batch.Relations[i], res.Batch.Relations[j]
		if x.From != y.From {
			return x.From < y.From
		}
		return x.To < y.To
	})
	if len(res.Batch.Relations) > 0 {
		res.Batch.Collector = Name + ":" + assetName(t)
		ids := make([]string, 0, len(assetEntity))
		for id := range assetEntity {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			res.Batch.Entities = append(res.Batch.Entities, correlate.VulnEntity(assetEntity[id], fixedFor[id]))
		}
	}
	return res, nil
}

// dedupe lists the distinct (purl name, version) pairs of the SBOM in a stable
// order. A package without a purl has no lookup key and is left out.
func dedupe(s bom.SBOM) []*pkgRef {
	seen := map[string]*pkgRef{}
	var out []*pkgRef
	for _, p := range s.Packages {
		if p.Purl == nil || strings.TrimSpace(*p.Purl) == "" {
			continue
		}
		name := normalizePurl(*p.Purl)
		name, purlVersion := splitVersion(name)
		ver := purlVersion
		if p.Version != nil {
			ver = strings.TrimSpace(*p.Version)
		}
		ref := &pkgRef{name: p.Name, purlName: name, ptype: purlType(name), version: ver}
		k := ref.key()
		if have := seen[k]; have != nil {
			if !slices.Contains(have.purls, *p.Purl) {
				have.purls = append(have.purls, *p.Purl)
			}
			if have.layer == "" {
				have.layer = p.Properties["layer_digest"]
			}
			continue
		}
		ref.purls = []string{*p.Purl}
		ref.layer = p.Properties["layer_digest"]
		seen[k] = ref
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	for _, r := range out {
		sort.Strings(r.purls)
	}
	return out
}

func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	t, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(t)
}

// cand is a lookup result for one package. versioned means it came from the
// lookup with the installed version, which cvesource already range-checked.
type cand struct {
	v         cvesource.Vuln
	versioned bool
}

// decide returns the match state of a candidate, or ok false when the package
// is not affected.
func decide(p *pkgRef, c cand) (state string, ok bool) {
	if p.version == "" {
		// Without a version no range can be evaluated.
		return cvesource.StateUnknown, true
	}
	if c.v.Origin != cvesource.OriginIntelStore {
		// Local CVE graph records carry their own state.
		switch c.v.AffectedState {
		case cvesource.StateAffected, cvesource.StateUnknown:
			return c.v.AffectedState, c.versioned
		}
		return "", false
	}
	inside, decided := inRanges(p.ptype, p.version, c.v.Ranges)
	switch {
	case decided && inside:
		return cvesource.StateAffected, true
	case decided:
		return "", false
	}
	// No comparator could order the version. cvesource's own comparison stands.
	return cvesource.StateAffected, c.versioned
}

// upgrades keeps the fixed versions above the installed version, so a package
// on the 2.x line is not pointed at a 1.x fix. A version that cannot be
// ordered is kept.
func upgrades(p *pkgRef, fixed []string) []string {
	out := []string{}
	for _, f := range fixed {
		if c, ok := compare(p.ptype, p.version, f); ok && c >= 0 {
			continue
		}
		out = append(out, f)
	}
	return out
}

func toModel(v cvesource.Vuln) model.Vuln {
	return model.Vuln{
		ID: v.ID, Summary: v.Summary, Severity: model.Severity(v.Severity),
		CVSS:           model.CVSS{Score: v.CVSSScore, Vector: v.CVSSVector, Version: v.CVSSVersion},
		KnownExploited: v.KEV, EPSS: v.EPSS,
	}
}

func vexExcerpt(v *vexSet, justification string) string {
	s := "status=not_affected"
	if justification != "" {
		s += " justification=" + justification
	}
	if v.docID != "" {
		s += " doc=" + v.docID
	}
	return s
}

// details is the type-specific JSON of a vulnerability Finding (Requirement
// 7.2): absent CVSS and EPSS are null, absent lists are empty.
type details struct {
	Purl          string            `json:"purl"`
	Version       string            `json:"version"`
	VulnID        string            `json:"vuln_id"`
	Aliases       []string          `json:"aliases"`
	State         string            `json:"state"`
	CVSS          *float64          `json:"cvss"`
	CVSSVector    *string           `json:"cvss_vector"`
	AffectedRange []cvesource.Range `json:"affected_range"`
	FixedVersions []string          `json:"fixed_versions"`
	KEV           bool              `json:"kev"`
	EPSS          *float64          `json:"epss"`
	LayerDigest   string            `json:"layer_digest"`
}

func (a *Adapter) finding(t scanners.Target, p *pkgRef, v cvesource.Vuln, state string, fixed []string) findings.Finding {
	raw := strings.ToLower(strings.TrimSpace(v.Severity))
	switch raw {
	case "":
		raw = "unknown"
	case "info":
		raw = "negligible" // the common scale's info; the Grype table calls it negligible
	}
	sev, unmapped := findings.MapSeverity("cvss", raw)
	in := risk.Inputs{CVSS: v.CVSSScore, EPSS: v.EPSS, KEV: v.KEV} // exposure and criticality unknown, not reachable
	score := risk.Compute(in)
	if state == cvesource.StateUnknown {
		sev, score = findings.SevInfo, min(score, maxUnknownScore)
	}

	d := details{
		Purl: p.purls[0], Version: p.version, VulnID: v.ID, Aliases: append([]string{}, v.Aliases...), State: state,
		AffectedRange: append([]cvesource.Range{}, v.Ranges...), FixedVersions: append([]string{}, fixed...),
		KEV: v.KEV, LayerDigest: p.layer,
	}
	if v.CVSSScore > 0 || v.CVSSVector != "" {
		d.CVSS = &v.CVSSScore
	}
	if v.CVSSVector != "" {
		d.CVSSVector = &v.CVSSVector
	}
	if v.EPSS > 0 {
		d.EPSS = &v.EPSS
	}
	body, _ := json.Marshal(d) // plain fields only

	ev := []findings.EvidenceRef{
		{Kind: "package", Ref: p.purls[0], Excerpt: strings.TrimSpace(p.name + " " + p.version)},
		{Kind: "installed_version", Ref: p.purls[0], Excerpt: p.version},
	}
	if len(fixed) > 0 {
		ev = append(ev, findings.EvidenceRef{Kind: "fixed_versions", Ref: p.purls[0], Excerpt: strings.Join(fixed, ", ")})
	}
	if p.layer != "" {
		ev = append(ev, findings.EvidenceRef{Kind: "layer", Ref: p.layer})
	}
	signal := fmt.Sprintf("kev=%t", v.KEV)
	if d.EPSS != nil {
		signal += fmt.Sprintf(" epss=%g", *d.EPSS)
	}
	ev = append(ev, findings.EvidenceRef{Kind: "exploit_signal", Ref: v.ID, Excerpt: signal})

	title := v.ID + " in " + strings.TrimSpace(p.name+" "+p.version)
	desc := v.Summary
	if state == cvesource.StateUnknown {
		desc = strings.TrimSpace("The installed version is not known, so the affected range cannot be checked. " + desc)
	}
	return findings.Finding{
		ID:               findings.ID(v.ID, t.ID, discriminator(p, v.ID)),
		RuleID:           v.ID,
		Title:            truncate(title, findings.MaxTitle),
		Description:      truncate(desc, findings.MaxDescription),
		Category:         schema.OvVuln,
		Type:             findings.TypeVulnerability,
		Severity:         sev,
		Status:           findings.StatusOpen,
		AssetID:          t.ID,
		Evidence:         ev,
		Source:           string(scanners.KindVulnerability), // ResolveMissing keys on (asset, kind)
		SourceRevision:   Name + "@" + adapterVersion,
		RiskScore:        &score,
		UnmappedSeverity: unmapped && state != cvesource.StateUnknown,
		Details:          body,
	}
}

// discriminator is `purl@version#vuln_id`, with the purl taken without its
// version and qualifiers.
func discriminator(p *pkgRef, vulnID string) string {
	return p.purlName + "@" + p.version + "#" + vulnID
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
