// Package cvelocal is the read adapter that serves Graph 2 (the Local_CVE_Graph)
// from the installed snapshot. It wraps pkg/intel over the installed graph.db,
// opened read-only, and adds Stable_IDs, lexical search, and CWE lookups. It
// reads local files only and makes no network calls; it must not import
// net/http.
package cvelocal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/intel"

	_ "modernc.org/sqlite" // registers the "sqlite" driver used for the search handle
)

// Limits from Requirement 3.
const (
	MaxQueryLen   = 500
	MaxSearchHits = 100
	maxIDLen      = 256
	maxVersionLen = 128
)

// Stable_ID prefixes.
const (
	VulnPrefix = "bid:vuln:"
	PkgPrefix  = "bid:pkg:"
)

var (
	// ErrInvalidInput is wrapped by every input rejection. The message names the input.
	ErrInvalidInput = errors.New("invalid input")
	// ErrNotInstalled means no Local_CVE_Graph snapshot is installed.
	ErrNotInstalled = intel.ErrNotInstalled
	// ErrHistoryUnavailable means the snapshot has no history, so as-of reads cannot be served.
	ErrHistoryUnavailable = intel.ErrHistoryUnavailable
)

func invalid(input, why string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidInput, input, why)
}

// SnapshotInfo describes the installed snapshot (Requirement 3.7).
type SnapshotInfo struct {
	SnapshotID  string
	BuiltAt     time.Time
	InstalledAt time.Time
	Age         time.Duration // now - BuiltAt, whole hours, never negative
}

// WeaknessNode is a CWE node. Name, Description, Parents and Children are filled
// when the snapshot carries them and are empty otherwise.
type WeaknessNode struct {
	ID          string // "CWE-79"
	Name        string
	Description string
	Parents     []string
	Children    []string
}

// Vulnerability is a vulnerability with its Stable_ID and related facts.
type Vulnerability struct {
	StableID    string // bid:vuln:<canonical_id>
	ID          string // canonical id
	Summary     string
	Published   string
	Modified    string
	Withdrawn   string
	TrustState  string
	Aliases     []string
	Severities  []intel.SeverityAssessment
	Weaknesses  []WeaknessNode // CWE text; empty when absent
	Patches     []intel.Patch  // empty when absent
	Exploits    []intel.Exploit
	KEV         *intel.KEVEntry
	EPSS        *intel.EPSSAssessment
	Discrepancy bool
	Relevance   float64 // set by Search only
}

// Affects is one vulnerability that affects a package version.
type Affects struct {
	VulnerabilityID string // bid:vuln:<canonical_id>
	CanonicalID     string
	Summary         string
	PackageID       string // bid:pkg:<normalised purl without version>
	VersionID       string // PackageID + "@" + version
	State           string // "affected" or "unknown"
	FixedVersion    string
	TrustState      string
	Range           *intel.AffectedRange
}

// CVESource is the read interface over the Local_CVE_Graph. A lookup that matches
// nothing returns a nil or empty result and a nil error. Invalid input returns an
// error wrapping ErrInvalidInput.
type CVESource interface {
	ByID(ctx context.Context, id string) (*Vulnerability, error)
	ByPackage(ctx context.Context, purl, version string) ([]Affects, error)
	Search(ctx context.Context, q string, limit int) ([]Vulnerability, error)
	Weakness(ctx context.Context, cwe string) (*WeaknessNode, error)
	AsOf(ctx context.Context, t time.Time) (CVESource, error)
	Info() SnapshotInfo
}

// Option configures Open.
type Option func(*config)

type config struct{ now func() time.Time }

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// Source implements CVESource over one installed graph.db.
type Source struct {
	client intel.Client
	db     *sql.DB
	info   SnapshotInfo
	now    func() time.Time

	asOf  time.Time // zero when reading the current state
	empty bool      // as-of precedes the earliest record
	root  *Source   // owner of the handles; nil for the root itself
}

var _ CVESource = (*Source)(nil)

// Open opens <dataDir>/current/graph.db read-only. It returns ErrNotInstalled when
// no snapshot is installed.
func Open(dataDir string, opts ...Option) (*Source, error) {
	cfg := config{now: time.Now}
	for _, o := range opts {
		o(&cfg)
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, invalid("dataDir", "must not be empty")
	}
	cur := filepath.Join(dataDir, "current")
	path := filepath.Join(cur, "graph.db")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotInstalled, path)
		}
		return nil, err
	}
	client, err := intel.Open(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Opaque: (&url.URL{Path: path}).EscapedPath(),
		RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	s := &Source{client: client, db: db, now: cfg.now}
	if s.info, err = readInfo(db, cur, path); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handles. Sources from AsOf share the parent's
// handles and must not outlive it.
func (s *Source) Close() error {
	if s.root != nil {
		return nil
	}
	return errors.Join(s.client.Close(), s.db.Close())
}

// Info returns the snapshot id, build time, install time, and age.
func (s *Source) Info() SnapshotInfo {
	i := s.info
	age := s.now().Sub(i.BuiltAt).Truncate(time.Hour)
	i.Age = max(age, 0)
	return i
}

func readInfo(db *sql.DB, cur, path string) (SnapshotInfo, error) {
	var info SnapshotInfo
	var created string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key='created_at'`).Scan(&created); err == nil {
		info.BuiltAt = parseTime(created)
	}
	// current is a symlink to snapshots/<id>.
	if dir, err := filepath.EvalSymlinks(cur); err == nil {
		info.SnapshotID = filepath.Base(dir)
	}
	if fi, err := os.Stat(path); err == nil {
		info.InstalledAt = fi.ModTime()
	}
	if info.SnapshotID == "" {
		return info, fmt.Errorf("%w: cannot determine snapshot id of %s", ErrNotInstalled, cur)
	}
	return info, nil
}

func (s *Source) base() *Source {
	if s.root != nil {
		return s.root
	}
	return s
}

// ByID returns the vulnerability whose canonical id equals id, or nil.
// Aliases do not match.
func (s *Source) ByID(ctx context.Context, id string) (*Vulnerability, error) {
	want, err := parseVulnID(id)
	if err != nil {
		return nil, err
	}
	if s.empty {
		return nil, nil
	}
	return s.load(ctx, want)
}

// load returns the vulnerability with canonical id want, or nil.
func (s *Source) load(ctx context.Context, want string) (*Vulnerability, error) {
	var opts []intel.Option
	if !s.asOf.IsZero() {
		opts = append(opts, intel.WithAsOf(s.asOf))
	}
	v, err := s.client.GetVulnerability(ctx, want, opts...)
	if errors.Is(err, intel.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if v.ID != want {
		return nil, nil // reached through an alias
	}
	out := &Vulnerability{
		StableID: VulnPrefix + v.ID, ID: v.ID, Summary: v.Summary, Published: v.Published,
		Modified: v.Modified, Withdrawn: v.Withdrawn, TrustState: v.TrustState,
		Aliases: v.Aliases, Severities: v.Severities, KEV: v.KEV, EPSS: v.EPSS,
		Discrepancy: v.Discrepancy != nil && v.Discrepancy.Present,
		Weaknesses:  []WeaknessNode{}, Patches: []intel.Patch{}, Exploits: []intel.Exploit{},
	}
	for _, c := range v.Weaknesses {
		w, err := s.weakness(ctx, c)
		if err != nil {
			return nil, err
		}
		if w == nil {
			w = &WeaknessNode{ID: c}
		}
		out.Weaknesses = append(out.Weaknesses, *w)
	}
	// Patches and exploits are not versioned in the graph, so they are read
	// without an as-of option. The vulnerability itself was already as-of gated.
	if out.Patches, err = s.client.GetPatches(ctx, v.ID); err != nil {
		return nil, err
	}
	if out.Exploits, err = s.client.GetExploits(ctx, v.ID); err != nil {
		return nil, err
	}
	return out, nil
}

// ByPackage returns every vulnerability whose affected entry for the purl
// contains version. version may be empty when the purl carries one.
func (s *Source) ByPackage(ctx context.Context, purl, version string) ([]Affects, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return nil, err
	}
	if version == "" {
		version = p.version
	}
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	if s.empty {
		return []Affects{}, nil
	}
	ms, err := s.client.GetPackageVulnerabilities(ctx, p.ecosystem, p.name, version)
	if err != nil {
		return nil, err
	}
	out := []Affects{}
	for _, m := range ms {
		if !s.asOf.IsZero() {
			v, err := s.load(ctx, m.Vulnerability.ID)
			if err != nil {
				return nil, err
			}
			if v == nil {
				continue
			}
		}
		out = append(out, Affects{
			VulnerabilityID: VulnPrefix + m.Vulnerability.ID, CanonicalID: m.Vulnerability.ID,
			Summary: m.Vulnerability.Summary, PackageID: p.stableID(), VersionID: p.stableID() + "@" + version,
			State: string(m.State), FixedVersion: m.FixedVersion, TrustState: m.TrustState, Range: m.Range,
		})
	}
	return out, nil
}

// AsOf returns a source that answers as the graph stood at t. A t before the
// earliest history record yields a source that returns only empty results.
// It returns ErrHistoryUnavailable when the snapshot carries no history.
func (s *Source) AsOf(ctx context.Context, t time.Time) (CVESource, error) {
	if t.IsZero() {
		return nil, invalid("as-of", "timestamp is zero")
	}
	if t.After(s.now()) {
		return nil, invalid("as-of", t.UTC().Format(time.RFC3339)+" is in the future")
	}
	b := s.base()
	var has string
	err := b.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='has_history'`).Scan(&has)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && strings.TrimSpace(has) != "true") {
		return nil, ErrHistoryUnavailable
	}
	if err != nil {
		return nil, err
	}
	var earliest sql.NullString
	if err := b.db.QueryRowContext(ctx, `SELECT MIN(recorded_at) FROM history`).Scan(&earliest); err != nil {
		return nil, err
	}
	out := &Source{client: b.client, db: b.db, info: b.info, now: b.now, asOf: t, root: b}
	if !earliest.Valid {
		out.empty = true
		return out, nil
	}
	if first := parseTime(earliest.String); !first.IsZero() && t.Before(first) {
		out.empty = true
	}
	return out, nil
}

// parseTime reads the timestamp layouts the graph writes; zero on failure.
func parseTime(s string) time.Time {
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(l, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// Weakness returns the CWE node, or nil when the snapshot has none.
func (s *Source) Weakness(ctx context.Context, cwe string) (*WeaknessNode, error) {
	if _, err := parseCWE(cwe); err != nil {
		return nil, err
	}
	if s.empty {
		return nil, nil
	}
	return s.weakness(ctx, cwe)
}

func (s *Source) weakness(ctx context.Context, cwe string) (*WeaknessNode, error) {
	n, err := parseCWE(cwe)
	if err != nil {
		return nil, nil // a stored CWE label that is not CWE-<n> (e.g. NVD-CWE-Other)
	}
	b := s.base()
	id := "cwe:" + n
	var props string
	err = b.db.QueryRowContext(ctx, `SELECT props FROM nodes WHERE id=? AND type='Weakness'`, id).Scan(&props)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m, err := decodeProps(props)
	if err != nil {
		return nil, fmt.Errorf("node %s: %w", id, err)
	}
	w := &WeaknessNode{ID: "CWE-" + n, Name: str(m, "name"), Description: str(m, "description"),
		Parents: []string{}, Children: []string{}}
	// ChildOf is stored child -> parent.
	if w.Parents, err = b.cweLinks(ctx, `SELECT dst FROM edges WHERE src=? AND type='CHILD_OF' ORDER BY dst`, id); err != nil {
		return nil, err
	}
	if w.Children, err = b.cweLinks(ctx, `SELECT src FROM edges WHERE dst=? AND type='CHILD_OF' ORDER BY src`, id); err != nil {
		return nil, err
	}
	return w, nil
}

func (s *Source) cweLinks(ctx context.Context, q, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, "CWE-"+strings.TrimPrefix(n, "cwe:"))
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// input parsing

func parseVulnID(id string) (string, error) {
	t := strings.TrimPrefix(strings.TrimSpace(id), VulnPrefix)
	if t == "" {
		return "", invalid("id", "must not be empty")
	}
	if len(t) > maxIDLen || strings.IndexFunc(t, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", invalid("id", "malformed")
	}
	return strings.ToUpper(t), nil
}

func checkVersion(v string) error {
	if strings.TrimSpace(v) == "" {
		return invalid("version", "must not be empty")
	}
	if len(v) > maxVersionLen || strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return invalid("version", "not parseable")
	}
	return nil
}

// parseCWE accepts "CWE-79", "cwe-79", or "79" and returns "79".
func parseCWE(s string) (string, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", invalid("cwe", "must not be empty")
	}
	if len(t) > 4 && strings.EqualFold(t[:4], "cwe-") {
		t = t[4:]
	}
	if t == "" || len(t) > 9 || strings.TrimLeft(t, "0123456789") != "" {
		return "", invalid("cwe", "malformed")
	}
	if n := strings.TrimLeft(t, "0"); n != "" {
		return n, nil
	}
	return "0", nil
}
