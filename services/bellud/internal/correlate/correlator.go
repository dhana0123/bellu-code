package correlate

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
)

const (
	// Interval is the period of the scheduled correlation run.
	Interval = 5 * time.Minute
	// Debounce is how long the Correlator waits after the last relevant change
	// before it triggers a run.
	Debounce = 2 * time.Second

	kindPackage  = "package"
	kindImage    = "image"
	pageSize     = 1000
	resubscribe  = 5 * time.Second
	collectLimit = collectors.ConnectorTimeout
)

// ErrNoCorpus is returned by Collect when the intel store has no active generation.
var ErrNoCorpus = errors.New("intel corpus not loaded")

// Corpus is the intel store as the Correlator uses it.
type Corpus interface {
	Lookup
	Meta() (store.Meta, error)
}

// Correlator is a collectors.Collector that matches package entities against
// the intel corpus and links identical entities across connections. The batch
// it returns is a full observation, so the Runner retires vulnerabilities and
// relations that no longer match.
type Correlator struct {
	eng    graph.Engine
	corpus Corpus

	wake chan struct{}

	runMu sync.Mutex // serializes triggered runs
	mu    sync.Mutex // guards cancel and done
	stop  context.CancelFunc
	done  chan struct{}
}

var (
	_ collectors.Collector = (*Correlator)(nil)
	_ collectors.Timeouter = (*Correlator)(nil)
)

// New returns a Correlator reading eng and corpus.
func New(eng graph.Engine, corpus Corpus) *Correlator {
	return &Correlator{eng: eng, corpus: corpus, wake: make(chan struct{}, 1)}
}

// Name implements collectors.Collector.
func (c *Correlator) Name() string { return CollectorName }

// Interval implements collectors.Collector.
func (c *Correlator) Interval() time.Duration { return Interval }

// Timeout implements collectors.Timeouter. A full scan can exceed the default.
func (c *Correlator) Timeout() time.Duration { return collectLimit }

// Wake requests a run after the debounce. It never blocks.
func (c *Correlator) Wake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Collect implements collectors.Collector.
func (c *Correlator) Collect(ctx context.Context) (graph.Batch, error) {
	meta, err := c.corpus.Meta()
	if err != nil {
		return graph.Batch{}, err
	}
	if !meta.Active() {
		return graph.Batch{}, ErrNoCorpus
	}

	pkgEnts, err := c.find(ctx, kindPackage)
	if err != nil {
		return graph.Batch{}, err
	}
	pkgs := make([]Pkg, 0, len(pkgEnts))
	keyed := make([]KeyedEntity, 0, len(pkgEnts))
	for _, e := range pkgEnts {
		pkgs = append(pkgs, Pkg{ID: string(e.ID), Connection: attr(e, "connection"), Scope: attr(e, "scope"), Purl: attr(e, "purl")})
		keyed = append(keyed, keyedOf(e))
	}
	for _, kind := range []string{kindRepo, kindResource, kindImage} {
		ents, err := c.find(ctx, kind)
		if err != nil {
			return graph.Batch{}, err
		}
		for _, e := range ents {
			keyed = append(keyed, keyedOf(e))
		}
	}

	out, err := Plan(pkgs, c.corpus)
	if err != nil {
		return graph.Batch{}, err
	}
	out.Relations = append(out.Relations, PlanSameAs(keyed)...)
	return out, nil
}

// find pages through every live entity of kind.
func (c *Correlator) find(ctx context.Context, kind string) ([]graph.Entity, error) {
	var all []graph.Entity
	cursor := ""
	for {
		pg, err := c.eng.Query().Find(ctx, graph.FindQuery{Type: kind, Paging: graph.Paging{PageSize: pageSize, Cursor: cursor}})
		if err != nil {
			return nil, err
		}
		all = append(all, pg.Items...)
		if !pg.Truncated || pg.NextCursor == "" {
			return all, nil
		}
		cursor = pg.NextCursor
	}
}

func keyedOf(e graph.Entity) KeyedEntity {
	return KeyedEntity{
		ID: string(e.ID), Kind: e.Type, Connection: attr(e, "connection"),
		Key: attr(e, canonical.AttrCanonicalKey), Name: attr(e, "name"),
	}
}

func attr(e graph.Entity, name string) string {
	s, _ := e.Attributes[name].(string)
	return s
}

// Start launches the trigger loop: relevant graph changes and Wake calls
// schedule a run through r after the debounce. Stop ends it.
func (c *Correlator) Start(ctx context.Context, r *collectors.Runner) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stop != nil {
		return
	}
	ctx, c.stop = context.WithCancel(ctx)
	c.done = make(chan struct{})
	go func() {
		defer close(c.done)
		c.loop(ctx, r)
	}()
}

// Stop ends the trigger loop and waits for it to return.
func (c *Correlator) Stop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	stop, done := c.stop, c.done
	c.mu.Unlock()
	if stop == nil {
		return
	}
	stop()
	<-done
}

func (c *Correlator) loop(ctx context.Context, r *collectors.Runner) {
	changes, closeSub := c.subscribe(ctx)
	defer func() { closeSub() }()

	var timer *time.Timer
	var fire <-chan time.Time
	arm := func() {
		if timer == nil {
			timer = time.NewTimer(Debounce)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(Debounce)
		}
		fire = timer.C
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
			arm()
		case ch, ok := <-changes:
			if !ok {
				// Subscription ended (overflow or engine error): run once to
				// catch up, then resubscribe after a pause.
				arm()
				closeSub()
				changes = nil
				time.AfterFunc(resubscribe, func() {
					select {
					case c.wake <- struct{}{}:
					default:
					}
				})
				continue
			}
			if relevant(ch.Change) {
				arm()
			}
		case <-fire:
			fire = nil
			if changes == nil {
				changes, closeSub = c.subscribe(ctx)
			}
			c.runMu.Lock()
			_ = r.RunOnce(ctx, c) // failures are recorded in collector_status
			c.runMu.Unlock()
		}
	}
}

// subscribe opens the change feed. When the engine has no feed it returns a
// nil channel, so the loop is driven by Wake alone.
func (c *Correlator) subscribe(ctx context.Context) (<-chan graph.SeqChange, func()) {
	x, ok := graph.ExtendedOf(c.eng)
	if !ok {
		return nil, func() {}
	}
	sub, err := x.Subscribe(ctx, graph.SubscribeOpts{Subject: graph.SubjectEntity})
	if err != nil {
		return nil, func() {}
	}
	return sub.C(), sub.Close
}

// relevant reports whether ch is an entity change of a kind the Correlator
// reads. Its own output (vulnerability entities) and the status entities of
// the Runner are not relevant.
func relevant(ch graph.Change) bool {
	if ch.Subject != graph.SubjectEntity {
		return false
	}
	switch kindOf(string(ch.Entity)) {
	case kindPackage, kindRepo, kindResource, kindImage:
		return true
	}
	return false
}

// kindOf returns the kind prefix of an Entity_ID "kind:<hex>".
func kindOf(id string) string {
	for i := 0; i < len(id); i++ {
		if id[i] == ':' {
			return id[:i]
		}
	}
	return ""
}
