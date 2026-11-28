package cvesource

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/config"
)

// DefaultGraphLimit is the node cap of a Graph slice when GraphQuery.Limit is 0.
const DefaultGraphLimit = 100

// GraphQuery selects a neighbourhood. ID is a CVE or CWE id.
type GraphQuery struct {
	ID        string
	Type      string // Vulnerability or Weakness; inferred from ID when empty
	Depth     int    // 1 or 2; default 1
	Limit     int    // node cap, default DefaultGraphLimit
	RelTypes  []string
	NodeTypes []string
}

// Node and Edge use the shape of the BSKG neighborhood response, so the app
// draws a slice the same way it draws a Security_Graph API slice (17.14).
type Node struct {
	ID         string         `json:"id"` // Label:key
	Type       string         `json:"type"`
	Key        string         `json:"key"`
	Label      string         `json:"label"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Edge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	ViewID string `json:"viewID,omitempty"`
}

// GraphSlice is a neighbourhood. The start node is first.
type GraphSlice struct {
	Nodes []Node
	Edges []Edge
}

// Ref names a related entity.
type Ref struct{ ID, Type, Key, Label string }

// VulnDetail is the detail view of one vulnerability. The lists come from
// BSKG and are empty in db mode.
type VulnDetail struct {
	Vuln     Vuln
	CWEs     []Ref
	Exploits []Ref
	Affected []Ref // products and vendors
	Related  []Ref // related vulnerabilities
	// Conflicts lists, in both mode, every compared field whose DB and BSKG
	// values differ, keyed by field name (17.5).
	Conflicts map[string]Conflict
}

// Conflict holds the two values of one field, named by source.
type Conflict struct{ DB, Graph any }

// mergeBoth applies the Both_Mode rule (17.5). Scoring fields (severity,
// cvssScore, kev, epss) come from the source with the later Modified time; on
// a tie or a missing time the DB value wins. The summary always stays the DB
// value. It records each differing field in conflicts and its source in from.
func mergeBoth(db, g Vuln, from map[string]Mode) (Vuln, map[string]Conflict) {
	out := db
	pick := ModeDB
	if !db.Modified.IsZero() && !g.Modified.IsZero() && g.Modified.After(db.Modified) {
		pick = ModeGraph
	}
	conf := map[string]Conflict{}
	note := func(name string, differ bool, dv, gv any, scoring bool) {
		from[name] = ModeDB
		if !differ {
			return
		}
		conf[name] = Conflict{DB: dv, Graph: gv}
		if scoring {
			from[name] = pick
		}
	}
	note("summary", db.Summary != "" && g.Summary != "" && db.Summary != g.Summary, db.Summary, g.Summary, false)
	note("severity", db.Severity != "" && g.Severity != "" && db.Severity != g.Severity, db.Severity, g.Severity, true)
	note("cvssScore", db.CVSSScore != 0 && g.CVSSScore != 0 && db.CVSSScore != g.CVSSScore, db.CVSSScore, g.CVSSScore, true)
	note("kev", db.KEV != g.KEV, db.KEV, g.KEV, true)
	note("epss", db.EPSS != 0 && g.EPSS != 0 && db.EPSS != g.EPSS, db.EPSS, g.EPSS, true)
	if pick == ModeGraph {
		if c, ok := conf["severity"]; ok {
			out.Severity = c.Graph.(string)
		}
		if c, ok := conf["cvssScore"]; ok {
			out.CVSSScore = c.Graph.(float64)
		}
		if c, ok := conf["kev"]; ok {
			out.KEV = c.Graph.(bool)
		}
		if c, ok := conf["epss"]; ok {
			out.EPSS = c.Graph.(float64)
		}
	}
	if len(conf) == 0 {
		conf = nil
	}
	return out, conf
}

// lruCache is an in-memory LRU whose entries expire at read time (17.17).
type lruCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	rev   string // last seen BSKG revision
	order *list.List
	items map[string]*list.Element
}

type cacheEntry struct {
	key string
	res bskg.Result
	at  time.Time
}

func newLRU(max int, ttl time.Duration) *lruCache {
	return &lruCache{max: max, ttl: ttl, order: list.New(), items: map[string]*list.Element{}}
}

func cacheKey(rev, path, query string) string {
	h := sha256.Sum256([]byte(rev + "\x00GET\x00" + path + "\x00" + query))
	return hex.EncodeToString(h[:])
}

func (c *lruCache) get(path, query string, now time.Time) (bskg.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[cacheKey(c.rev, path, query)]
	if !ok {
		return bskg.Result{}, false
	}
	e := el.Value.(*cacheEntry)
	if now.Sub(e.at) >= c.ttl {
		c.order.Remove(el)
		delete(c.items, e.key)
		return bskg.Result{}, false
	}
	c.order.MoveToFront(el)
	return e.res, true
}

// put stores res. A revision different from the last seen one drops every entry.
func (c *lruCache) put(path, query string, res bskg.Result, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if res.Revision != c.rev {
		c.order.Init()
		c.items = map[string]*list.Element{}
		c.rev = res.Revision
	}
	k := cacheKey(c.rev, path, query)
	if el, ok := c.items[k]; ok {
		c.order.Remove(el)
	}
	c.items[k] = c.order.PushFront(&cacheEntry{key: k, res: res, at: now})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(*cacheEntry).key)
	}
}

// fetch serves a BSKG request from the cache or from call, and records
// reachability on a live response.
func (d *DB) fetch(path, query string, call func() (bskg.Result, error)) (bskg.Result, error) {
	if r, ok := d.cache.get(path, query, d.now()); ok {
		return r, nil
	}
	r, err := call()
	if err != nil {
		return r, err
	}
	d.cache.put(path, query, r, d.now())
	d.mu.Lock()
	d.reachable = true
	d.mu.Unlock()
	return r, nil
}

func (d *DB) client() *bskg.Client {
	if d.bskg == nil {
		return bskg.New(bskg.Config{})
	}
	return d.bskg
}

// NewBSKGClient builds the Graph_Mode client from the cve config.
func NewBSKGClient(c config.CVE) *bskg.Client {
	return bskg.New(bskg.Config{URL: c.BSKGURL, Key: c.BSKGKey.Reveal(), Timeout: c.BSKGTimeout})
}

// outcome classifies an error from bskg.
type outcome int

const (
	outOK outcome = iota
	outNotFound
	outGap
	outInvalid
)

func classify(err error) (outcome, string) {
	var ve *bskg.ValidationError
	switch {
	case err == nil:
		return outOK, ""
	case errors.Is(err, bskg.ErrNotFound):
		return outNotFound, ""
	case errors.As(err, &ve):
		return outInvalid, ""
	}
	if c := bskg.Cause(err); c != "" {
		return outGap, c
	}
	return outGap, CauseUnreachable
}

func bskgWarnings(ws []string) []Warning {
	var out []Warning
	for _, w := range ws {
		code := WarnBSKGSample
		if strings.Contains(w, "stale") {
			code = WarnBSKGStale
		}
		out = append(out, Warning{Code: code, Message: w})
	}
	return out
}

func addWarnings(dst []Warning, more ...Warning) []Warning {
	for _, m := range more {
		dup := false
		for _, w := range dst {
			dup = dup || w.Code == m.Code
		}
		if !dup {
			dst = append(dst, m)
		}
	}
	return dst
}

type neighbourhood struct {
	Nodes     []Node `json:"nodes"`
	Edges     []Edge `json:"edges"`
	Truncated bool   `json:"truncated"`
}

func parseNeighbourhood(body []byte) (neighbourhood, error) {
	var n neighbourhood
	err := json.Unmarshal(body, &n)
	for i := range n.Edges {
		if e := &n.Edges[i]; e.ID == "" {
			e.ID = e.Source + "|" + e.Type + "|" + e.Target
		}
	}
	return n, err
}

// neighbours calls the client and returns the parsed slice.
func (d *DB) neighbours(ctx context.Context, typ, id string, depth int, rel, nodes []string) (neighbourhood, bskg.Result, error) {
	q := url.Values{"type": {typ}, "id": {id}, "depth": {strconv.Itoa(depth)}}
	if len(rel) > 0 {
		q.Set("relTypes", strings.Join(rel, ","))
	}
	if len(nodes) > 0 {
		q.Set("nodeTypes", strings.Join(nodes, ","))
	}
	r, err := d.fetch("/v1/graph/neighborhood", q.Encode(), func() (bskg.Result, error) {
		return d.client().Neighbourhood(ctx, typ, id, depth, rel, nodes)
	})
	if err != nil {
		return neighbourhood{}, r, err
	}
	n, err := parseNeighbourhood(r.Body)
	if err != nil {
		return n, r, &bskg.GapError{Cause: bskg.CauseUnreachable}
	}
	return n, r, nil
}

// Graph returns a neighbourhood from BSKG. In db mode it returns
// ErrGraphModeDisabled; on a BSKG failure it returns an empty slice and a gap.
func (d *DB) Graph(ctx context.Context, q GraphQuery) (Result[GraphSlice], error) {
	res := Result[GraphSlice]{FieldFrom: map[string]Mode{}}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if d.Mode() == ModeDB {
		return res, ErrGraphModeDisabled
	}
	id := strings.ToUpper(strings.TrimSpace(q.ID))
	if id == "" {
		return res, fmt.Errorf("%w: id is required", ErrInvalidQuery)
	}
	typ := q.Type
	if typ == "" {
		typ = "Vulnerability"
		if strings.HasPrefix(id, "CWE-") {
			typ = "Weakness"
		}
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultGraphLimit
	}
	depth := q.Depth
	if depth == 0 {
		depth = 1
	}
	n, r, err := d.neighbours(ctx, typ, id, depth, q.RelTypes, q.NodeTypes)
	switch o, cause := classify(err); o {
	case outInvalid:
		return res, fmt.Errorf("%w: %v", ErrInvalidQuery, err)
	case outGap:
		res.Gaps = []Gap{d.gap(cause)}
		return res, nil
	case outNotFound:
		return res, nil
	}
	res.Warnings = bskgWarnings(r.Warnings)
	res.Truncated = n.Truncated
	if len(n.Nodes) > limit {
		keep := map[string]bool{}
		for _, nd := range n.Nodes[:limit] {
			keep[nd.ID] = true
		}
		n.Nodes, res.Truncated = n.Nodes[:limit], true
		edges := n.Edges[:0]
		for _, e := range n.Edges {
			if keep[e.Source] && keep[e.Target] {
				edges = append(edges, e)
			}
		}
		n.Edges = edges
	}
	res.Data = GraphSlice{Nodes: nonNilSlice(n.Nodes), Edges: nonNilSlice(n.Edges)}
	res.FieldFrom["graph"] = ModeGraph
	return res, nil
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

type bskgVuln struct {
	CveID        string  `json:"cveID"`
	Description  string  `json:"description"`
	CVSSV3       float64 `json:"cvssV3"`
	Severity     string  `json:"severity"`
	Published    string  `json:"published"`
	LastModified string  `json:"lastModified"`
	KEV          bool    `json:"kev"`
	EPSS         float64 `json:"epss"`
	Weaknesses   []struct {
		CweID string `json:"cweID"`
		Name  string `json:"name"`
	} `json:"weaknesses"`
}

// bskgDetail is what BSKG returned for one id. Fields obtained before a gap are kept.
type bskgDetail struct {
	found    bool
	vuln     Vuln
	d        VulnDetail
	warnings []Warning
	cause    string // gap cause, empty when none
}

func refs(n neighbourhood, start string, types ...string) []Ref {
	out := []Ref{}
	for _, nd := range n.Nodes {
		if nd.ID == start {
			continue
		}
		for _, t := range types {
			if nd.Type == t {
				out = append(out, Ref{nd.ID, nd.Type, nd.Key, nd.Label})
			}
		}
	}
	return out
}

// fromBSKG reads one vulnerability with its CWE, exploits, affected products
// and related vulnerabilities. It stops at the first gap and keeps what it has.
func (d *DB) fromBSKG(ctx context.Context, id string) (bskgDetail, error) {
	var out bskgDetail
	id = strings.ToUpper(strings.TrimSpace(id))
	r, err := d.fetch("/v1/vulnerabilities/"+id, "", func() (bskg.Result, error) {
		return d.client().Vulnerability(ctx, id)
	})
	step := func(err error) (stop bool, ferr error) {
		switch o, cause := classify(err); o {
		case outInvalid:
			return true, err
		case outGap:
			out.cause = cause
			return true, nil
		case outNotFound:
			return true, nil
		}
		return false, nil
	}
	if stop, ferr := step(err); stop || ferr != nil {
		return out, ferr
	}
	var v bskgVuln
	if json.Unmarshal(r.Body, &v) != nil {
		out.cause = CauseUnreachable
		return out, nil
	}
	out.found = true
	out.warnings = bskgWarnings(r.Warnings)
	out.vuln = Vuln{
		ID: v.CveID, Aliases: []string{}, Summary: v.Description, Severity: strings.ToLower(v.Severity),
		CVSSScore: v.CVSSV3, KEV: v.KEV, EPSS: v.EPSS, Origin: OriginBSKG,
		Ranges: []Range{}, FixedVersions: []string{},
	}
	if v.CveID == "" {
		out.vuln.ID = id
	}
	out.vuln.Published, _ = time.Parse(time.RFC3339, v.Published)
	out.vuln.Modified, _ = time.Parse(time.RFC3339, v.LastModified)
	out.d.CWEs = []Ref{}
	for _, w := range v.Weaknesses {
		out.d.CWEs = append(out.d.CWEs, Ref{"Weakness:" + w.CweID, "Weakness", w.CweID, w.Name})
	}
	out.d.Exploits, out.d.Affected, out.d.Related = []Ref{}, []Ref{}, []Ref{}
	start := "Vulnerability:" + out.vuln.ID
	type call struct {
		types []string
		dst   *[]Ref
	}
	for _, c := range []call{
		{[]string{"Exploit"}, &out.d.Exploits},
		{[]string{"Product", "Vendor"}, &out.d.Affected},
		{[]string{"Vulnerability"}, &out.d.Related},
	} {
		n, nr, err := d.neighbours(ctx, "Vulnerability", id, 1, nil, c.types)
		if stop, ferr := step(err); stop || ferr != nil {
			return out, ferr
		}
		*c.dst = refs(n, start, c.types...)
		out.warnings = addWarnings(out.warnings, bskgWarnings(nr.Warnings)...)
	}
	return out, nil
}

// Detail returns one vulnerability. mode "" means the effective mode.
//   - db: the DB_Mode record, no network.
//   - graph: the BSKG record; on a BSKG gap the DB_Mode record and the gap.
//   - both: the DB_Mode record enriched with CWE, exploits, affected products
//     and related vulnerabilities from BSKG; FieldFrom says which mode made each
//     field. A BSKG gap keeps the DB data and adds the gap.
func (d *DB) Detail(ctx context.Context, id string, mode Mode) (Result[VulnDetail], error) {
	res := Result[VulnDetail]{FieldFrom: map[string]Mode{}}
	m := d.Mode()
	if mode != "" {
		var err error
		if m, err = config.ParseCVEMode(m, string(mode)); err != nil {
			return res, err
		}
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	useDB := func() error {
		lr, err := d.Lookup(ctx, LookupQuery{ID: id})
		if err != nil {
			return err
		}
		res.Warnings = addWarnings(res.Warnings, lr.Warnings...)
		if len(lr.Data) > 0 {
			res.Data.Vuln = lr.Data[0]
			res.FieldFrom["detail"] = ModeDB
		}
		return nil
	}
	if m != ModeGraph {
		if err := useDB(); err != nil {
			return res, err
		}
	}
	if m == ModeDB {
		return res, nil
	}
	b, err := d.fromBSKG(ctx, id)
	if err != nil {
		if m == ModeGraph {
			return res, fmt.Errorf("%w: %v", ErrInvalidQuery, err)
		}
		return res, nil // an id BSKG cannot take (an alias) is answered by the DB alone
	}
	res.Warnings = addWarnings(res.Warnings, b.warnings...)
	if b.cause != "" {
		res.Gaps = []Gap{d.gap(b.cause)}
	}
	if m == ModeGraph && !b.found && b.cause != "" {
		if err := useDB(); err != nil {
			return res, err
		}
	}
	if !b.found {
		return res, nil
	}
	if m == ModeBoth && res.FieldFrom["detail"] == ModeDB {
		res.Data.Vuln, res.Data.Conflicts = mergeBoth(res.Data.Vuln, b.vuln, res.FieldFrom)
	}
	if m == ModeGraph || res.FieldFrom["detail"] == "" {
		res.Data.Vuln = b.vuln
		res.FieldFrom["detail"] = ModeGraph
	}
	res.Data.CWEs, res.Data.Exploits = b.d.CWEs, b.d.Exploits
	res.Data.Affected, res.Data.Related = b.d.Affected, b.d.Related
	res.FieldFrom["cwe"] = ModeGraph
	for name, l := range map[string][]Ref{"exploits": b.d.Exploits, "affected": b.d.Affected, "related": b.d.Related} {
		if l != nil {
			res.FieldFrom[name] = ModeGraph
		}
	}
	return res, nil
}
