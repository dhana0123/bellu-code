// Package cvesource is the CVE_Source (Requirement 17). In DB_Mode it answers
// lookups from the local intel store and the installed Local_CVE_Graph
// (cvelocal) and never touches the network. Graph_Mode (graph.go) reads BSKG
// through bskg.Client and reports a cve_graph_unavailable gap with its cause
// when BSKG fails. This package must not construct an http client.
package cvesource

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/cvelocal"
	"github.com/bellu/bellucode/services/bellud/internal/intel/model"
	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// Mode is db, graph or both.
type Mode = config.CVEMode

const (
	ModeDB    = config.CVEModeDB
	ModeGraph = config.CVEModeGraph
	ModeBoth  = config.CVEModeBoth
)

// Affected states returned by a purl+version lookup (Requirements 7.3, 7.10).
const (
	StateAffected = "affected"
	StateUnknown  = "unknown"
)

// Gap kinds and causes (Requirement 17.6).
const (
	GapGraphUnavailable = "cve_graph_unavailable"

	CauseNotConfigured = "not_configured"
	CauseUnreachable   = "unreachable"
	CauseUnauthorized  = "unauthorized"
	CauseRateLimited   = "rate_limited"
	CauseTimeout       = "timeout"
)

// Warning codes.
const (
	WarnStaleDB      = "stale_db"        // Requirement 17.7: data older than cve.stale_limit
	WarnMissingDB    = "missing_db"      // Requirement 17.7: no local data
	WarnBSKGStale    = "bskg_stale"      // Requirement 17.16
	WarnBSKGSample   = "bskg_sample"     // Requirement 17.16
	WarnCPENotIndexd = "cpe_not_indexed" // the local data carries no CPE index
)

// Origins of a record, used in Vuln.Origin.
const (
	OriginIntelStore = "intel_store"
	OriginCVEGraph   = "cve_graph"
	OriginBSKG       = "bskg"
)

// ErrInvalidQuery wraps every rejected lookup input.
var ErrInvalidQuery = errors.New("invalid cve query")

// ErrGraphModeDisabled is returned by Graph when the effective mode is db.
var ErrGraphModeDisabled = errors.New("cve graph queries need cve.mode graph or both")

// Gap reports data that could not be obtained.
type Gap struct {
	Kind  string // cve_graph_unavailable
	Cause string
}

// Warning reports a condition the caller should show.
type Warning struct {
	Code    string
	Message string
}

// Result carries data with its gaps and warnings (Requirements 17.6, 17.7, 17.15).
type Result[T any] struct {
	Data      T
	Gaps      []Gap
	Warnings  []Warning
	FieldFrom map[string]Mode // which mode produced each field
	Truncated bool
}

// LookupQuery selects one lookup. Exactly one of ID, Purl or CPE is set.
// Version overrides a version carried by Purl.
type LookupQuery struct {
	ID      string // canonical id or alias
	Purl    string // pkg:type/name[@version]
	Version string
	CPE     string // CPE 2.3 formatted string or 2.2 URI
}

// Range is an affected version interval [Introduced, Fixed).
type Range struct{ Introduced, Fixed string }

// Vuln is one lookup match with the fields Requirement 7.2 needs.
type Vuln struct {
	ID            string
	Aliases       []string
	Summary       string
	Severity      string
	CVSSScore     float64
	CVSSVector    string
	CVSSVersion   string
	Ranges        []Range // affected ranges (the matched package's for a purl lookup)
	FixedVersions []string
	KEV           bool
	EPSS          float64
	Published     time.Time
	Modified      time.Time
	// AffectedState is affected or unknown for a purl lookup, empty otherwise.
	AffectedState string
	Origin        string // intel_store or cve_graph
}

// Status describes the source (the design's "mode, db age, bskg reachability, last gap").
type Status struct {
	Mode          Mode
	DBInstalled   bool
	DBAge         time.Duration // whole hours, freshest local source; zero when missing
	DBStale       bool
	StaleLimit    time.Duration
	BSKGReachable bool // the last BSKG call succeeded
	LastGap       *Gap
}

// Source is the CVE_Source interface from the design.
type Source interface {
	Lookup(ctx context.Context, q LookupQuery) (Result[[]Vuln], error)
	Graph(ctx context.Context, q GraphQuery) (Result[GraphSlice], error)
	Detail(ctx context.Context, id string, mode Mode) (Result[VulnDetail], error)
	Status() Status
}

// Options configures New.
type Options struct {
	Store      *store.Store       // intel store; may be nil
	Graph      cvelocal.CVESource // installed Local_CVE_Graph; may be nil
	Mode       Mode               // default db
	StaleLimit time.Duration      // default config.DefaultCVEStaleLimit
	Now        func() time.Time
	// BSKG serves Graph_Mode. Nil means not_configured.
	BSKG *bskg.Client
	// GraphCacheTTL is the Graph_Mode cache lifetime; default config.DefaultGraphCacheTTL.
	GraphCacheTTL time.Duration
	// Audit is the workspace database that receives the audit row of a mode
	// change (Requirement 21.9). Nil makes SetModeAudited fail.
	Audit *sqlite.Store
}

// DB is the DB_Mode implementation of Source.
type DB struct {
	store *store.Store
	graph cvelocal.CVESource
	limit time.Duration
	now   func() time.Time

	bskg      *bskg.Client
	audit     *sqlite.Store
	cache     *lruCache
	mu        sync.Mutex
	mode      Mode
	lastGap   *Gap
	reachable bool
}

var _ Source = (*DB)(nil)

// New builds a Source. An invalid Mode is an error naming cve.mode.
func New(o Options) (*DB, error) {
	mode, err := config.ParseCVEMode(config.CVEModeDB, string(orDefault(o.Mode)))
	if err != nil {
		return nil, err
	}
	d := &DB{store: o.Store, graph: o.Graph, mode: mode, limit: o.StaleLimit, now: o.Now}
	d.bskg = o.BSKG
	d.audit = o.Audit
	ttl := o.GraphCacheTTL
	if ttl <= 0 {
		ttl = config.DefaultGraphCacheTTL
	}
	d.cache = newLRU(256, ttl)
	if d.limit <= 0 {
		d.limit = config.DefaultCVEStaleLimit
	}
	if d.now == nil {
		d.now = time.Now
	}
	return d, nil
}

func orDefault(m Mode) Mode {
	if m == "" {
		return ModeDB
	}
	return m
}

// SetMode changes the effective mode. An invalid value returns an error naming
// cve.mode and the allowed values and keeps the previous mode (Requirement 17.13).
// It writes no audit row; the settings API uses SetModeAudited.
func (d *DB) SetMode(v string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, err := config.ParseCVEMode(d.mode, v)
	d.mode = m
	return err
}

// ErrAuditWrite is returned when a mode change cannot be audited; the mode is unchanged.
var ErrAuditWrite = errors.New("audit_write_failed")

// SetModeAudited validates v, appends the cve.mode audit row (old and new mode)
// and only then switches the mode. An invalid value or a failed audit write
// keeps the previous mode (Requirements 17.13, 21.9, 21.13).
func (d *DB) SetModeAudited(ctx context.Context, v, actor string) (Mode, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, err := config.ParseCVEMode(d.mode, v)
	if err != nil {
		return d.mode, err
	}
	if d.audit == nil {
		return d.mode, fmt.Errorf("%w: no workspace database", ErrAuditWrite)
	}
	ws := d.audit.WorkspaceID()
	err = d.audit.Write(ctx, ws, func(tx *sql.Tx) error {
		return sqlite.AppendAudit(ctx, tx, ws, sqlite.AuditEntry{
			Actor: actor, Action: "cve.mode.set", Target: "cve.mode", Outcome: string(d.mode) + "->" + string(m),
		})
	})
	if err != nil {
		return d.mode, fmt.Errorf("%w: %v", ErrAuditWrite, err)
	}
	d.mode = m
	return m, nil
}

// Mode returns the effective mode.
func (d *DB) Mode() Mode {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mode
}

// dataAge returns the age of the freshest local source. ok is false when no
// local data is installed.
func (d *DB) dataAge() (age time.Duration, ok bool, err error) {
	var best time.Time
	if d.store != nil {
		m, err := d.store.Meta()
		if err != nil {
			return 0, false, err
		}
		if m.Active() {
			t := m.CreatedAt
			if t.IsZero() {
				t = m.SyncedAt
			}
			best, ok = t, true
		}
	}
	if d.graph != nil {
		if t := d.graph.Info().BuiltAt; !ok || t.After(best) {
			best, ok = t, true
		}
	}
	if !ok {
		return 0, false, nil
	}
	return max(d.now().Sub(best).Truncate(time.Hour), 0), true, nil
}

func (d *DB) staleWarning() ([]Warning, error) {
	age, ok, err := d.dataAge()
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return []Warning{{WarnMissingDB, "local CVE data is missing"}}, nil
	case age > d.limit:
		return []Warning{{WarnStaleDB, fmt.Sprintf("local CVE data is %d days old (limit %d days)", int(age/(24*time.Hour)), int(d.limit/(24*time.Hour)))}}, nil
	}
	return nil, nil
}

// Status reports the mode and the local data age. It reads local files only.
func (d *DB) Status() Status {
	d.mu.Lock()
	st := Status{Mode: d.mode, StaleLimit: d.limit, LastGap: d.lastGap, BSKGReachable: d.reachable}
	d.mu.Unlock()
	if age, ok, err := d.dataAge(); err == nil && ok {
		st.DBInstalled, st.DBAge, st.DBStale = true, age, age > d.limit
	}
	return st
}

// Lookup answers from local data only. A miss is an empty result, not an error.
func (d *DB) Lookup(ctx context.Context, q LookupQuery) (Result[[]Vuln], error) {
	res := Result[[]Vuln]{Data: []Vuln{}, FieldFrom: map[string]Mode{}}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	set := 0
	for _, s := range []string{q.ID, q.Purl, q.CPE} {
		if strings.TrimSpace(s) != "" {
			set++
		}
	}
	if set != 1 {
		return res, fmt.Errorf("%w: set exactly one of id, purl or cpe", ErrInvalidQuery)
	}
	var err error
	switch {
	case strings.TrimSpace(q.ID) != "":
		res.Data, err = d.byID(ctx, strings.TrimSpace(q.ID))
	case strings.TrimSpace(q.Purl) != "":
		res.Data, err = d.byPurl(ctx, q.Purl, q.Version)
	default:
		var warn []Warning
		if warn, err = lookupCPE(q.CPE); err == nil {
			res.Warnings = append(res.Warnings, warn...)
		}
	}
	if err != nil {
		return res, err
	}
	w, err := d.staleWarning()
	if err != nil {
		return res, err
	}
	res.Warnings = append(res.Warnings, w...)
	if len(res.Data) > 0 {
		res.FieldFrom["lookup"] = ModeDB
	}
	return res, nil
}

func (d *DB) byID(ctx context.Context, id string) ([]Vuln, error) {
	out := []Vuln{}
	if d.store != nil {
		v, ok, err := d.store.Get(id)
		if err != nil {
			return nil, err
		}
		if ok {
			return append(out, fromStore(v, nil, "")), nil
		}
	}
	if d.graph != nil {
		v, err := d.graph.ByID(ctx, id)
		if err != nil && !errors.Is(err, cvelocal.ErrInvalidInput) {
			return nil, err
		}
		if v != nil {
			out = append(out, fromGraph(*v, nil, ""))
		}
	}
	return out, nil
}

func (d *DB) byPurl(ctx context.Context, purl, version string) ([]Vuln, error) {
	p := strings.TrimSpace(purl)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if len(p) < 4 || !strings.EqualFold(p[:4], "pkg:") {
		return nil, fmt.Errorf("%w: purl must start with pkg:", ErrInvalidQuery)
	}
	name, ver := model.SplitPurl(p)
	if v := strings.TrimSpace(version); v != "" {
		ver = v
	}
	if !strings.Contains(name, "/") {
		return nil, fmt.Errorf("%w: purl needs a type and a name", ErrInvalidQuery)
	}
	seen := map[string]bool{}
	out := []Vuln{}
	if d.store != nil {
		vs, err := d.store.ByPurl(name)
		if err != nil {
			return nil, err
		}
		for _, v := range vs {
			// Without a version the range cannot be evaluated: report unknown.
			state := StateAffected
			ok, ap := model.MatchPackage(v.Affected, name, ver)
			if ver == "" {
				state = StateUnknown
				for _, c := range v.Affected {
					if ok = strings.TrimSpace(c.Purl) == name; ok {
						ap = c
						break
					}
				}
			}
			if !ok {
				continue
			}
			seen[v.ID] = true
			out = append(out, fromStore(v, &ap, state))
		}
	}
	if d.graph != nil && ver != "" {
		as, err := d.graph.ByPackage(ctx, p, ver)
		if err != nil && !errors.Is(err, cvelocal.ErrInvalidInput) {
			return nil, err
		}
		for _, a := range as {
			if seen[a.CanonicalID] {
				continue
			}
			seen[a.CanonicalID] = true
			v, err := d.graph.ByID(ctx, a.CanonicalID)
			if err != nil {
				return nil, err
			}
			g := cvelocal.Vulnerability{ID: a.CanonicalID, Summary: a.Summary}
			if v != nil {
				g = *v
			}
			out = append(out, fromGraph(g, &a, a.State))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// lookupCPE validates a CPE. Neither the intel store nor the Local_CVE_Graph
// carries CPE data, so a valid CPE finds nothing and the result says why.
func lookupCPE(cpe string) ([]Warning, error) {
	c := strings.TrimSpace(cpe)
	var part, vendor, product string
	switch {
	case strings.HasPrefix(strings.ToLower(c), "cpe:2.3:"):
		f := strings.Split(c, ":")
		if len(f) != 13 {
			return nil, fmt.Errorf("%w: cpe 2.3 needs 13 fields", ErrInvalidQuery)
		}
		part, vendor, product = f[2], f[3], f[4]
	case strings.HasPrefix(strings.ToLower(c), "cpe:/"):
		f := strings.Split(c[5:], ":")
		if len(f) < 3 {
			return nil, fmt.Errorf("%w: cpe 2.2 needs part, vendor and product", ErrInvalidQuery)
		}
		part, vendor, product = f[0], f[1], f[2]
	default:
		return nil, fmt.Errorf("%w: cpe must start with cpe:2.3: or cpe:/", ErrInvalidQuery)
	}
	if (part != "a" && part != "o" && part != "h") || vendor == "" || product == "" {
		return nil, fmt.Errorf("%w: cpe needs part a, o or h, a vendor and a product", ErrInvalidQuery)
	}
	return []Warning{{WarnCPENotIndexd, "local CVE data has no CPE index; use a purl or CVE id"}}, nil
}

func fromStore(v model.Vuln, ap *model.AffectedPackage, state string) Vuln {
	out := Vuln{
		ID: v.ID, Aliases: nonNil(v.Aliases), Summary: v.Summary, Severity: string(v.Severity),
		CVSSScore: v.CVSS.Score, CVSSVector: v.CVSS.Vector, CVSSVersion: v.CVSS.Version,
		KEV: v.KnownExploited, EPSS: v.EPSS, Published: v.Published, Modified: v.Modified,
		AffectedState: state, Origin: OriginIntelStore, Ranges: []Range{}, FixedVersions: []string{},
	}
	pkgs := v.Affected
	if ap != nil {
		pkgs = []model.AffectedPackage{*ap}
	}
	for _, p := range pkgs {
		for _, r := range p.Ranges {
			out.Ranges = append(out.Ranges, Range{r.Introduced, r.Fixed})
			out.FixedVersions = addUnique(out.FixedVersions, r.Fixed)
		}
		for _, f := range p.FixedIn {
			out.FixedVersions = addUnique(out.FixedVersions, f)
		}
	}
	return out
}

func fromGraph(v cvelocal.Vulnerability, a *cvelocal.Affects, state string) Vuln {
	out := Vuln{
		ID: v.ID, Aliases: nonNil(v.Aliases), Summary: v.Summary, AffectedState: state,
		Origin: OriginCVEGraph, Ranges: []Range{}, FixedVersions: []string{},
	}
	if v.Modified != "" {
		out.Modified, _ = time.Parse(time.RFC3339, v.Modified)
	}
	if v.Published != "" {
		out.Published, _ = time.Parse(time.RFC3339, v.Published)
	}
	for i, s := range v.Severities {
		if i == 0 || s.Score > out.CVSSScore {
			out.CVSSScore, out.CVSSVector, out.CVSSVersion = s.Score, s.Vector, s.Version
			out.Severity = strings.ToLower(s.Rating)
		}
	}
	if v.KEV != nil {
		out.KEV = true
	}
	if v.EPSS != nil {
		out.EPSS = v.EPSS.Score
	}
	if a != nil {
		if a.Range != nil {
			out.Ranges = append(out.Ranges, Range{a.Range.Introduced, a.Range.Fixed})
		}
		out.FixedVersions = addUnique(out.FixedVersions, a.FixedVersion)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string{}, s...)
}

func addUnique(s []string, v string) []string {
	if v == "" {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func (d *DB) gap(cause string) Gap {
	g := Gap{Kind: GapGraphUnavailable, Cause: cause}
	d.mu.Lock()
	d.lastGap = &g
	d.reachable = false
	d.mu.Unlock()
	return g
}
