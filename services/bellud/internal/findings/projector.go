package findings

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/codeschema"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// Projector timing (Requirement 3.16).
const (
	ProjectorCollector = "findings"
	ProjectDebounce    = time.Second
	ProjectMaxWait     = 60 * time.Second
	ProjectResync      = 60 * time.Second
)

// Projector writes open and in_progress findings onto the graph as `finding`
// nodes with one `affects` edge to the asset. Each projection is a full
// observation by collector "findings", so the engine retires findings that
// are no longer listed.
type Projector struct {
	store    *Store
	engine   graph.Engine
	log      *slog.Logger
	debounce time.Duration
	maxWait  time.Duration
	resync   time.Duration
}

// ProjectorOption configures NewProjector.
type ProjectorOption func(*Projector)

// WithProjectorTiming overrides debounce, hard bound and resync interval.
func WithProjectorTiming(debounce, maxWait, resync time.Duration) ProjectorOption {
	return func(p *Projector) { p.debounce, p.maxWait, p.resync = debounce, maxWait, resync }
}

// WithProjectorLogger sets the logger.
func WithProjectorLogger(l *slog.Logger) ProjectorOption { return func(p *Projector) { p.log = l } }

// NewProjector returns a Projector. Call Run to start it.
func NewProjector(s *Store, e graph.Engine, opts ...ProjectorOption) *Projector {
	p := &Projector{store: s, engine: e, log: slog.Default(),
		debounce: ProjectDebounce, maxWait: ProjectMaxWait, resync: ProjectResync}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Run projects once, then again after each burst of changes (debounced, and
// never later than maxWait after the first unprojected change) and on every
// resync tick, since Store.Subscribe drops changes for a slow consumer. It
// returns when ctx ends or the Store is closed.
func (p *Projector) Run(ctx context.Context) {
	changes := p.store.Subscribe()
	p.projectLogged(ctx)
	tick := time.NewTicker(p.resync)
	defer tick.Stop()
	var (
		quiet, bound *time.Timer
		quietC       <-chan time.Time
		boundC       <-chan time.Time
	)
	stop := func(t *time.Timer) {
		if t != nil {
			t.Stop()
		}
	}
	defer func() { stop(quiet); stop(bound) }()
	fire := func() {
		stop(quiet)
		stop(bound)
		quietC, boundC = nil, nil
		p.projectLogged(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-changes:
			if !ok {
				return
			}
			stop(quiet)
			quiet = time.NewTimer(p.debounce)
			quietC = quiet.C
			if boundC == nil {
				bound = time.NewTimer(p.maxWait)
				boundC = bound.C
			}
		case <-quietC:
			fire()
		case <-boundC:
			fire()
		case <-tick.C:
			fire()
		}
	}
}

func (p *Projector) projectLogged(ctx context.Context) {
	if err := p.Project(ctx); err != nil && ctx.Err() == nil {
		p.log.Warn("findings projection failed", "err", err)
	}
}

// Project applies one full observation of all open and in_progress findings.
// Findings whose asset is not live in the graph are left out, because the
// engine rejects a batch with a relation to a missing entity. If the liveness
// check fails for any reason other than not found, nothing is applied, so a
// transient error never retires nodes.
func (p *Projector) Project(ctx context.Context) error {
	b := batch.Batch{Collector: ProjectorCollector}
	live := map[string]bool{}
	cursor := ""
	for {
		page, err := p.store.List(ctx, ListQuery{Statuses: []Status{StatusOpen, StatusInProgress}, Limit: MaxBatch, Cursor: cursor})
		if err != nil {
			return err
		}
		for _, f := range page.Items {
			ok, seen := live[f.AssetID]
			if !seen {
				if _, err := p.engine.Query().Entity(ctx, graph.EntityID(f.AssetID), nil); err == nil {
					ok = true
				} else if !errors.Is(err, graph.ErrNotFound) {
					return err
				}
				live[f.AssetID] = ok
			}
			if !ok {
				continue
			}
			id, err := identity.Hash(codeschema.KindFinding, map[string]string{"id": f.ID})
			if err != nil {
				return err
			}
			title, err := redact.Text(f.Title)
			if err != nil {
				title = ""
			}
			attrs := map[string]any{
				"finding_type": string(f.Type),
				"severity":     string(f.Severity),
				"status":       string(f.Status),
				"category":     string(f.Category),
				"source":       f.Source,
			}
			if title != "" {
				attrs["title"] = title
			}
			b.Entities = append(b.Entities, batch.Entity{Type: codeschema.KindFinding, Identity: map[string]string{"id": f.ID}, Attributes: attrs})
			b.Relations = append(b.Relations, batch.Relation{Type: codeschema.RelAffects, From: string(id), To: f.AssetID})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	_, err := p.engine.Ingest().Apply(ctx, b)
	return err
}
