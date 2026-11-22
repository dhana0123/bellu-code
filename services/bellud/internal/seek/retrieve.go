package seek

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Error categories a Source reports. They carry no URL, key or response body.
// Source implementations (bskg.Client) return these values.
var (
	ErrNotFound     = errors.New("bskg: not found")
	ErrUnconfigured = errors.New("bskg: not configured")
	ErrUnreachable  = errors.New("bskg: unreachable")
	ErrTimeout      = errors.New("bskg: timeout")
	ErrAuth         = errors.New("bskg: authentication failed")
)

const (
	maxDescription = 800
	// fetchShare is the part of TotalTimeout given to the scope and reference
	// fetches. The rest is kept for detail and name fetches, so a slow unit
	// cannot starve the finished ones of the time they need to be ranked.
	fetchShareNum, fetchShareDen = 3, 5
)

// Config holds the Retriever limits.
type Config struct {
	RequestTimeout time.Duration // per BSKG request, default 10s
	TotalTimeout   time.Duration // per Run, default 30s
	MinRelevance   float64       // candidates scoring below are dropped
	PerCWEFetch    int           // references fetched per scope CWE, default MaxScope
	MaxDetailFetch int           // CVE detail fetches per Run, default 120
	Concurrency    int           // parallel BSKG requests, default 8
}

// Retriever runs a validated Plan against a Source.
type Retriever struct {
	src Source
	cfg Config
	log *slog.Logger
}

// NewRetriever returns a Retriever. A nil src means BSKG is not configured and
// every non-empty plan yields cve_unavailable.
func NewRetriever(src Source, cfg Config, log *slog.Logger) *Retriever {
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.TotalTimeout <= 0 {
		cfg.TotalTimeout = 30 * time.Second
	}
	if cfg.PerCWEFetch <= 0 {
		cfg.PerCWEFetch = MaxScope
	}
	if cfg.MaxDetailFetch <= 0 {
		cfg.MaxDetailFetch = 120
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Retriever{src: src, cfg: cfg, log: log}
}

// work is the state of one accepted unit while a Run is in progress.
type work struct {
	unit     Unit
	status   string // "", ok, no_candidates, unknown_cwe, unavailable
	err      *ErrInfo
	name     string // name of the predicted CWE
	scope    Scope
	refs     []VulnRef // deduplicated within the unit, then across units
	detailEr *ErrInfo  // first failed detail fetch of one of its candidates
	cands    []Candidate
}

type detailResult struct {
	d   VulnDetail
	err error
}

// run holds the state shared by the goroutines of one Run.
type run struct {
	r      *Retriever
	cancel context.CancelFunc
	sem    chan struct{}
	auth   atomic.Bool
	calls  atomic.Int64
}

// Run validates plan and topK, fetches evidence and returns ranked candidates.
// Fetches run concurrently. Merging, dedupe, ranking, cutoff and allocation
// happen afterwards in Plan order, so the Result does not depend on timing.
func (r *Retriever) Run(ctx context.Context, plan Plan, topK int) Result {
	if issues := validate(plan, topK); len(issues) > 0 {
		return Result{Status: "invalid_plan", Issues: issues}
	}
	res := Result{Status: "ok", TopK: topK, Units: []UnitResult{}}
	if len(plan.Weaknesses) == 0 {
		return res
	}
	start := time.Now()
	works := make([]*work, len(plan.Weaknesses))
	for i, u := range plan.Weaknesses {
		works[i] = &work{unit: u}
	}
	if r.src == nil {
		for _, w := range works {
			w.status, w.err = "unavailable", errInfo(ErrUnconfigured)
		}
		return r.finish(res, works, start, nil)
	}

	total, cancelTotal := context.WithTimeout(ctx, r.cfg.TotalTimeout)
	defer cancelTotal()
	base, cancel := context.WithCancel(total)
	defer cancel()
	rn := &run{r: r, cancel: cancel, sem: make(chan struct{}, r.cfg.Concurrency)}

	// Phase 1: scope and references, one goroutine per unit.
	fetchCtx, cancelFetch := context.WithTimeout(base, r.cfg.TotalTimeout*fetchShareNum/fetchShareDen)
	var wg sync.WaitGroup
	for _, w := range works {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rn.fetchUnit(fetchCtx, w)
		}()
	}
	wg.Wait()
	cancelFetch()

	// Phase 2: dedupe in Plan order, then details for the best references.
	details := rn.fetchDetails(base, works)

	// Phase 3: rank, cut off and allocate in Plan order.
	rn.rankAndAllocate(works, details, topK)

	// Phase 4: CWE names for the allocated candidates only.
	names := map[string]string{}
	for _, w := range works {
		if w.name != "" {
			names[w.unit.CWEID] = w.name
		}
	}
	rn.fillNames(base, works, names)
	if rn.auth.Load() {
		for _, w := range works {
			w.status, w.err = "unavailable", errInfo(ErrAuth)
		}
	}
	return r.finish(res, works, start, rn)
}

// validate re-checks a typed Plan and topK. Callers that parsed the plan with
// ParsePlan pass this unchanged; it guards direct callers.
func validate(plan Plan, topK int) []Issue {
	var issues []Issue
	if topK < MinTopK || topK > MaxTopK {
		issues = append(issues, Issue{Path: "top_k", Reason: fmt.Sprintf("must be between %d and %d", MinTopK, MaxTopK)})
	}
	raw, err := plan.Marshal()
	if err != nil {
		return append(issues, Issue{Path: "plan", Reason: "cannot be encoded"})
	}
	_, rejected, planIssues := ParsePlan(raw)
	issues = append(issues, planIssues...)
	for _, d := range rejected {
		issues = append(issues, Issue{Path: fmt.Sprintf("weaknesses[%d].cwe_id", d.Index), Reason: d.Reason})
	}
	return issues
}

// call runs fn under the concurrency limit and the per-request timeout. A
// 401/403 cancels all work of the Run.
func (rn *run) call(ctx context.Context, fn func(context.Context) error) error {
	select {
	case rn.sem <- struct{}{}:
	case <-ctx.Done():
		return ctxErr(ctx)
	}
	defer func() { <-rn.sem }()
	rctx, cancel := context.WithTimeout(ctx, rn.r.cfg.RequestTimeout)
	defer cancel()
	rn.calls.Add(1)
	err := fn(rctx)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAuth) {
		rn.auth.Store(true)
		rn.cancel()
		return ErrAuth
	}
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	if errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(err, ErrUnconfigured) {
		return ErrUnconfigured
	}
	return ErrUnreachable
}

func ctxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrUnreachable
}

// errInfo maps a category error to a fixed ErrInfo.
func errInfo(err error) *ErrInfo {
	switch {
	case errors.Is(err, ErrUnconfigured):
		return &ErrInfo{Category: "unconfigured", Message: "CVE evidence source is not configured"}
	case errors.Is(err, ErrAuth):
		return &ErrInfo{Category: "authentication", Message: "CVE evidence source rejected the credentials"}
	case errors.Is(err, ErrTimeout):
		return &ErrInfo{Category: "timeout", Message: "CVE evidence source did not answer in time"}
	}
	return &ErrInfo{Category: "unreachable", Message: "CVE evidence source is unreachable"}
}

func (rn *run) fetchUnit(ctx context.Context, w *work) {
	src, cwe := rn.r.src, w.unit.CWEID
	var info WeaknessInfo
	err := rn.call(ctx, func(c context.Context) (e error) { info, e = src.Weakness(c, cwe); return })
	if errors.Is(err, ErrNotFound) {
		w.status = "unknown_cwe"
		return
	}
	if err != nil {
		w.status, w.err = "unavailable", errInfo(err)
		return
	}
	w.name = info.Name

	edges, err := rn.children(ctx, cwe, 1)
	if err != nil {
		w.status, w.err = "unavailable", errInfo(err)
		return
	}
	scope := BuildScope(cwe, edges, 1)
	refs, err := rn.refs(ctx, scope.CWEs)
	if err != nil {
		w.status, w.err = "unavailable", errInfo(err)
		return
	}
	if !anyRefs(refs) {
		// No direct CWE has a candidate: expand to grandchildren, once.
		edges, err = rn.children(ctx, cwe, 2)
		if err != nil {
			w.status, w.err = "unavailable", errInfo(err)
			return
		}
		scope = BuildScope(cwe, edges, 2)
		more := []string{}
		for _, id := range scope.CWEs {
			if _, done := refs[id]; !done {
				more = append(more, id)
			}
		}
		extra, err := rn.refs(ctx, more)
		if err != nil {
			w.status, w.err = "unavailable", errInfo(err)
			return
		}
		for id, rs := range extra {
			refs[id] = rs
		}
	}
	w.scope = scope

	// A CVE attached to several scope CWEs belongs to the lowest numeric one.
	ordered := append([]string(nil), scope.CWEs...)
	sort.Slice(ordered, func(i, j int) bool { return cweNumber(ordered[i]) < cweNumber(ordered[j]) })
	seen := map[string]bool{}
	for _, id := range ordered {
		for _, ref := range refs[id] {
			if !seen[ref.CVEID] {
				seen[ref.CVEID] = true
				ref.CWEID = id
				w.refs = append(w.refs, ref)
			}
		}
	}
}

func (rn *run) children(ctx context.Context, cwe string, depth int) ([]Edge, error) {
	var edges []Edge
	err := rn.call(ctx, func(c context.Context) (e error) { edges, e = rn.r.src.Children(c, cwe, depth); return })
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return edges, err
}

// refs fetches the references of each CWE concurrently. The returned error is
// the first one in CWE order, so it does not depend on scheduling.
func (rn *run) refs(ctx context.Context, cwes []string) (map[string][]VulnRef, error) {
	out := make([][]VulnRef, len(cwes))
	errs := make([]error, len(cwes))
	var wg sync.WaitGroup
	for i, id := range cwes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = rn.call(ctx, func(c context.Context) (e error) {
				out[i], e = rn.r.src.WeaknessVulns(c, id, rn.r.cfg.PerCWEFetch)
				return
			})
			if errors.Is(errs[i], ErrNotFound) {
				errs[i], out[i] = nil, nil
			}
		}()
	}
	wg.Wait()
	res := map[string][]VulnRef{}
	for i, id := range cwes {
		if errs[i] != nil {
			return nil, errs[i]
		}
		res[id] = out[i]
	}
	return res, nil
}

func anyRefs(m map[string][]VulnRef) bool {
	for _, rs := range m {
		if len(rs) > 0 {
			return true
		}
	}
	return false
}

// fetchDetails dedupes references across units (earliest unit wins), keeps the
// MaxDetailFetch best by CVSS then CVE id, and fetches their details.
func (rn *run) fetchDetails(ctx context.Context, works []*work) map[string]detailResult {
	owner := map[string]bool{}
	var all []VulnRef
	for _, w := range works {
		if w.status != "" {
			continue
		}
		kept := w.refs[:0:0]
		for _, ref := range w.refs {
			if !owner[ref.CVEID] {
				owner[ref.CVEID] = true
				kept = append(kept, ref)
				all = append(all, ref)
			}
		}
		w.refs = kept
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		switch {
		case a.CVSS != nil && b.CVSS == nil:
			return true
		case a.CVSS == nil && b.CVSS != nil:
			return false
		case a.CVSS != nil && *a.CVSS != *b.CVSS:
			return *a.CVSS > *b.CVSS
		}
		return a.CVEID < b.CVEID
	})
	if len(all) > rn.r.cfg.MaxDetailFetch {
		all = all[:rn.r.cfg.MaxDetailFetch]
	}
	results := make([]detailResult, len(all))
	var wg sync.WaitGroup
	for i, ref := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i].err = rn.call(ctx, func(c context.Context) (e error) {
				results[i].d, e = rn.r.src.Vulnerability(c, ref.CVEID)
				return
			})
		}()
	}
	wg.Wait()
	out := make(map[string]detailResult, len(all))
	for i, ref := range all {
		out[ref.CVEID] = results[i]
	}
	return out
}

func (rn *run) rankAndAllocate(works []*work, details map[string]detailResult, topK int) {
	min := rn.r.cfg.MinRelevance
	ranked := make([][]Candidate, len(works))
	have := make([]int, len(works))
	for i, w := range works {
		if w.status != "" {
			continue
		}
		var cs []Candidate
		for _, ref := range w.refs {
			dr, fetched := details[ref.CVEID]
			if !fetched {
				continue // beyond the detail cap
			}
			if dr.err != nil {
				if w.detailEr == nil {
					w.detailEr = errInfo(dr.err)
				}
				continue
			}
			cs = append(cs, candidate(w.unit, ref, dr.d))
		}
		ranked[i] = Cutoff(Rank(cs), min)
		have[i] = len(ranked[i])
	}
	slots := Allocate(topK, have)
	for i, w := range works {
		if w.status != "" {
			continue
		}
		w.refs = nil
		switch n := slots[i]; {
		case n > 0:
			w.status = "ok"
			ranked[i] = ranked[i][:n]
		case have[i] == 0 && w.detailEr != nil:
			w.status, w.err = "unavailable", w.detailEr
			ranked[i] = nil
		default:
			w.status = "no_candidates"
			ranked[i] = nil
		}
		w.cands = ranked[i]
	}
}

func candidate(u Unit, ref VulnRef, d VulnDetail) Candidate {
	c := Candidate{
		CVEID:       ref.CVEID,
		CWEID:       ref.CWEID,
		Score:       math.Round(Score(SignalsFor(u, d))*1e6) / 1e6,
		Description: truncateRunes(d.Description, maxDescription),
		KEV:         d.KEV,
		EPSS:        d.EPSS,
		CVSS:        d.CVSS,
	}
	if d.FixCommit != "" && d.Repository != "" {
		c.FixCommit, c.Repository = d.FixCommit, d.Repository
	}
	return c
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// fillNames sets CWEName on allocated candidates, one lookup per distinct CWE.
func (rn *run) fillNames(ctx context.Context, works []*work, names map[string]string) {
	var need []string
	seen := map[string]bool{}
	for _, w := range works {
		for _, c := range w.cands {
			if _, ok := names[c.CWEID]; !ok && !seen[c.CWEID] {
				seen[c.CWEID] = true
				need = append(need, c.CWEID)
			}
		}
	}
	sort.Strings(need)
	got := make([]string, len(need))
	var wg sync.WaitGroup
	for i, id := range need {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var info WeaknessInfo
			if rn.call(ctx, func(c context.Context) (e error) { info, e = rn.r.src.Weakness(c, id); return }) == nil {
				got[i] = info.Name
			}
		}()
	}
	wg.Wait()
	for i, id := range need {
		names[id] = got[i]
	}
	for _, w := range works {
		for i := range w.cands {
			w.cands[i].CWEName = names[w.cands[i].CWEID]
		}
	}
}

// finish builds the Result from the finished works and logs counts only.
func (r *Retriever) finish(res Result, works []*work, start time.Time, rn *run) Result {
	finished := 0
	var firstErr *ErrInfo
	counts := map[string]int{}
	for _, w := range works {
		counts[w.status]++
		u := UnitResult{CWEID: w.unit.CWEID, Status: w.status, Error: w.err, Candidates: w.cands}
		if w.status != "unavailable" && w.status != "unknown_cwe" {
			u.Scope, u.Expanded = w.scope.CWEs, w.scope.Expanded
		}
		res.Units = append(res.Units, u)
		if w.status == "unavailable" {
			if firstErr == nil {
				firstErr = w.err
			}
			continue
		}
		finished++
	}
	if finished == 0 {
		res.Status, res.Error = "cve_unavailable", firstErr
	}
	calls := int64(0)
	if rn != nil {
		calls = rn.calls.Load()
	}
	attrs := []any{
		"status", res.Status, "units", len(works), "requests", calls,
		"ok", counts["ok"], "no_candidates", counts["no_candidates"],
		"unknown_cwe", counts["unknown_cwe"], "unavailable", counts["unavailable"],
		"duration", time.Since(start),
	}
	if res.Error != nil {
		attrs = append(attrs, "category", res.Error.Category)
	}
	r.log.Info("seek retrieve finished", attrs...)
	return res
}
