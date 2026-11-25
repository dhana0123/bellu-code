package issues

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/posture"
)

// ---- Source over the graph facade and the findings store ----

// GraphSource is a Source that reads relations and attributes from the graph
// and member findings from the findings store. It is bound to one run: the
// Source interface has no context or error, so the first read error is kept
// and returned by Err.
type GraphSource struct {
	Ctx    context.Context
	Reader posture.GraphReader
	Store  *findings.Store

	mu  sync.Mutex
	err error
}

func (g *GraphSource) fail(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err == nil {
		g.err = err
	}
}

// Err returns the first read error of the run.
func (g *GraphSource) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// Relation implements Source.
func (g *GraphSource) Relation(from, relation, to string) (RelationInfo, bool) {
	cursor := ""
	for {
		pg, err := g.Reader.Neighbors(g.Ctx, facade.EntityID(from), facade.NeighborOpts{
			Direction: facade.DirOut, RelationType: relation, Depth: 1,
			Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor},
		})
		if err != nil {
			g.fail(err)
			return RelationInfo{}, false
		}
		for _, e := range pg.Items {
			if string(e.To) == to && e.Type == relation && !e.Derived {
				info := RelationInfo{Confidence: e.Confidence}
				if e.Evidence != "" {
					info.Evidence = []string{e.Evidence}
				}
				return info, true
			}
		}
		if pg.NextCursor == "" {
			return RelationInfo{}, false
		}
		cursor = pg.NextCursor
	}
}

// Attrs implements Source. Values are rendered with %v.
func (g *GraphSource) Attrs(entityID string) map[string]string {
	en, err := g.Reader.Entity(g.Ctx, facade.EntityID(entityID), nil)
	if err != nil {
		g.fail(err)
		return nil
	}
	out := make(map[string]string, len(en.Attributes))
	for k, v := range en.Attributes {
		out[k] = fmt.Sprint(v)
	}
	return out
}

// Findings implements Source: open and in-progress findings of the entities.
func (g *GraphSource) Findings(_ string, entityIDs []string) []findings.Finding {
	pg, err := g.Store.List(g.Ctx, findings.ListQuery{
		AssetIDs: entityIDs, Limit: 1000,
		Statuses: []findings.Status{findings.StatusOpen, findings.StatusInProgress},
	})
	if err != nil {
		g.fail(err)
		return nil
	}
	return pg.Items
}

// ---- Reevaluator ----

// RunStatus is the outcome of the last Reevaluate call.
type RunStatus struct {
	Failed   bool
	Err      string
	Attempts int
	At       time.Time
}

// Summary describes one successful run.
type Summary struct {
	Entities, Matches, Upserted, Resolved, Skipped int
}

// Reevaluator re-checks toxic combinations and keeps Issues in step (4.3, 4.4, 4.10).
type Reevaluator struct {
	Engine  *posture.Engine
	Reader  posture.GraphReader
	Store   *Store
	Finds   *findings.Store
	Packs   []posture.Pack // used to find toxic_combination rules and the kinds they apply to
	Include bool           // include inferred relations

	Timeout  time.Duration   // per attempt; default 60 s
	Retries  int             // retries after the first attempt; default 3
	Backoff  []time.Duration // wait before each retry; default 1 s, 5 s, 15 s
	Debounce time.Duration   // Watch delay; default 2 s

	mu   sync.Mutex
	last RunStatus
}

// Last returns the status of the last run.
func (r *Reevaluator) Last() RunStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

func (r *Reevaluator) toxic() (rules map[string]bool, kinds map[string]bool) {
	rules, kinds = map[string]bool{}, map[string]bool{}
	for _, p := range r.Packs {
		for _, ru := range p.Rules {
			if ru.Kind != posture.KindToxicCombination {
				continue
			}
			rules[p.ID+"/"+ru.ID] = true
			for _, k := range ru.AppliesTo {
				kinds[k] = true
			}
		}
	}
	return
}

// Reevaluate runs the toxic_combination rules over scope, upserts the Issues
// that match and resolves open Issues that no longer match. A failed or timed
// out attempt changes nothing; it is retried up to Retries times, after which
// the run is marked failed.
func (r *Reevaluator) Reevaluate(ctx context.Context, scope posture.Scope) (Summary, error) {
	retries, backoff := r.Retries, r.Backoff
	if retries == 0 {
		retries = 3
	}
	if backoff == nil {
		backoff = []time.Duration{time.Second, 5 * time.Second, 15 * time.Second}
	}
	var sum Summary
	var err error
	attempts := 0
	for {
		attempts++
		if sum, err = r.once(ctx, scope); err == nil || attempts > retries || ctx.Err() != nil {
			break
		}
		wait := backoff[min(attempts-1, len(backoff)-1)]
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	st := RunStatus{Attempts: attempts, At: time.Now().UTC()}
	if err != nil {
		st.Failed, st.Err = true, err.Error()
	}
	r.mu.Lock()
	r.last = st
	r.mu.Unlock()
	return sum, err
}

func (r *Reevaluator) once(parent context.Context, scope posture.Scope) (Summary, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	toxic, kinds := r.toxic()
	var sum Summary

	entities, err := r.entities(ctx, scope, kinds)
	if err != nil {
		return sum, err
	}
	sum.Entities = len(entities)
	evaluated := map[string]bool{}
	erroredRules := map[string]bool{}
	var matches []posture.Match
	for _, en := range entities {
		evaluated[string(en.ID)] = true
		ms, errs := r.Engine.EvalEntity(ctx, posture.Input{ID: string(en.ID), Type: en.Type, Label: en.Label, Attributes: en.Attributes})
		if ctx.Err() != nil {
			return sum, ctx.Err()
		}
		for _, e := range errs {
			erroredRules[e.PackID+"/"+e.RuleID] = true
		}
		for _, m := range ms {
			if toxic[m.PackID+"/"+m.RuleID] {
				matches = append(matches, m)
			}
		}
	}
	sum.Matches = len(matches)

	// Build every Issue before writing anything.
	src := &GraphSource{Ctx: ctx, Reader: r.Reader, Store: r.Finds}
	b := &Builder{Src: src, IncludeInferred: r.Include}
	built := map[string]Issue{}
	for _, m := range matches {
		is, err := b.FromMatch(m)
		if serr := src.Err(); serr != nil {
			return sum, serr
		}
		if err != nil {
			sum.Skipped++ // no evidence or no open member findings: no Issue
			continue
		}
		built[is.ID] = is
	}
	open, err := r.Store.List(ctx, Query{Statuses: []Status{StatusOpen}, Limit: 1000})
	if err != nil {
		return sum, err
	}
	var stale []string
	for _, is := range open {
		if _, ok := built[is.ID]; ok || !r.ruleKnown(toxic, is.RuleID) || r.ruleErrored(erroredRules, is.RuleID) {
			continue
		}
		for _, h := range is.Path {
			if evaluated[h.EntityID] {
				stale = append(stale, is.ID)
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return sum, err
	}

	// Apply.
	ids := make([]string, 0, len(built))
	for id := range built {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		prev, gerr := r.Store.Get(ctx, id)
		if err := r.Store.Upsert(ctx, built[id]); err != nil {
			return sum, err
		}
		if gerr == nil && prev.Status == StatusResolved { // the condition came back
			if err := r.Store.SetStatus(ctx, id, StatusOpen, "system"); err != nil {
				return sum, err
			}
		} else if gerr != nil && !errors.Is(gerr, ErrNotFound) {
			return sum, gerr
		}
		sum.Upserted++
	}
	for _, id := range stale {
		if err := r.Store.SetStatus(ctx, id, StatusResolved, "system"); err != nil {
			return sum, err
		}
		sum.Resolved++
	}
	return sum, nil
}

// ruleKnown reports whether an Issue's rule id belongs to a toxic rule of any pack.
func (r *Reevaluator) ruleKnown(toxic map[string]bool, ruleID string) bool {
	for k := range toxic {
		if len(k) > len(ruleID) && k[len(k)-len(ruleID)-1:] == "/"+ruleID {
			return true
		}
	}
	return false
}

func (r *Reevaluator) ruleErrored(errored map[string]bool, ruleID string) bool {
	for k := range errored {
		if len(k) > len(ruleID) && k[len(k)-len(ruleID)-1:] == "/"+ruleID {
			return true
		}
	}
	return false
}

// entities returns the entities to evaluate: all of the toxic rules' kinds for
// a full run, otherwise the changed entities and their one-hop neighbours.
func (r *Reevaluator) entities(ctx context.Context, scope posture.Scope, kinds map[string]bool) ([]facade.Entity, error) {
	byID := map[facade.EntityID]facade.Entity{}
	if scope.Full {
		for kind := range kinds {
			cursor := ""
			for {
				pg, err := r.Reader.Find(ctx, facade.FindQuery{Type: kind, Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor}})
				if err != nil {
					return nil, err
				}
				for _, en := range pg.Items {
					byID[en.ID] = en
				}
				if pg.NextCursor == "" {
					break
				}
				cursor = pg.NextCursor
			}
		}
	} else {
		ids := map[facade.EntityID]bool{}
		for _, id := range scope.Changed {
			ids[id] = true
			cursor := ""
			for {
				pg, err := r.Reader.Neighbors(ctx, id, facade.NeighborOpts{Direction: facade.DirBoth, Depth: 1,
					Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor}})
				if err != nil {
					return nil, err
				}
				for _, ed := range pg.Items {
					ids[ed.From], ids[ed.To] = true, true
				}
				if pg.NextCursor == "" {
					break
				}
				cursor = pg.NextCursor
			}
		}
		for id := range ids {
			en, err := r.Reader.Entity(ctx, id, nil)
			if err != nil { // removed or unknown entity
				continue
			}
			if kinds[en.Type] {
				byID[id] = en
			}
		}
	}
	out := make([]facade.Entity, 0, len(byID))
	for _, en := range byID {
		out = append(out, en)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Watch re-evaluates the Issues that contain a finding when it resolves. Changes
// are collected for Debounce and run as one Reevaluate. It returns when ctx ends
// or the findings store closes.
func (r *Reevaluator) Watch(ctx context.Context) {
	debounce := r.Debounce
	if debounce == 0 {
		debounce = 2 * time.Second
	}
	ch := r.Finds.Subscribe()
	pending := map[facade.EntityID]bool{}
	var timer <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case c, ok := <-ch:
			if !ok {
				return
			}
			if c.Status != findings.StatusResolved {
				continue
			}
			iss, err := r.Store.ByFinding(ctx, c.ID)
			if err != nil {
				continue
			}
			for _, is := range iss {
				for _, h := range is.Path {
					pending[facade.EntityID(h.EntityID)] = true
				}
			}
			if len(pending) > 0 && timer == nil {
				timer = time.After(debounce)
			}
		case <-timer:
			timer = nil
			changed := make([]facade.EntityID, 0, len(pending))
			for id := range pending {
				changed = append(changed, id)
			}
			slices.Sort(changed)
			clear(pending)
			_, _ = r.Reevaluate(ctx, posture.Scope{Changed: changed})
		}
	}
}
