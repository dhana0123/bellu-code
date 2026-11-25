// Package overview computes the nine Overview category cards: entity count,
// severity breakdown and top issues per category (Requirement 1).
package overview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/lens"
)

// CacheTTL is how long severity counts and top issues are reused.
const CacheTTL = 5 * time.Second

// SetupLink is the connector setup page named by every EmptyState.
const SetupLink = "/security/connectors"

// MaxTopIssues is the most issues shown per card.
const MaxTopIssues = 3

const (
	recountDelay   = 200 * time.Millisecond // debounce for graph change bursts
	resyncInterval = 5 * time.Second        // recount when the engine has no subscription
	slowResync     = 30 * time.Second       // safety net while subscribed
)

// ErrNotStarted is returned by Summaries before Start.
var ErrNotStarted = errors.New("overview: not started")

// Titles and Subtitles are the card texts (Requirement 1.2). The UI uses the
// i18n keys of the same names.
var (
	Titles = map[schema.OverviewCategory]string{
		schema.OvCloud: "Cloud infrastructure", schema.OvIdentity: "Identity", schema.OvVuln: "Vulnerabilities",
		schema.OvNetwork: "Network exposure", schema.OvSecrets: "Secrets", schema.OvData: "Data security",
		schema.OvCode: "Code and dependencies", schema.OvRuntime: "Runtime", schema.OvAI: "AI security",
	}
	Subtitles = map[schema.OverviewCategory]string{
		schema.OvCloud: "Resources and networks", schema.OvIdentity: "Users and permissions", schema.OvVuln: "CVEs and packages",
		schema.OvNetwork: "Connectivity and reachability", schema.OvSecrets: "Credentials and access",
		schema.OvData: "Databases and sensitive data", schema.OvCode: "Repositories and IaC",
		schema.OvRuntime: "Activity and threats", schema.OvAI: "Models and agents",
	}
)

// scannerFed lists the categories that scanners or the runtime sensor feed.
// The others are fed by connectors.
var scannerFed = map[schema.OverviewCategory]bool{
	schema.OvVuln: true, schema.OvSecrets: true, schema.OvData: true, schema.OvRuntime: true, schema.OvAI: true,
}

// Missing source types named by EmptyState.
const (
	SourceConnector = "connector"
	SourceScanner   = "scanner"
)

// EmptyState explains a card with zero entities (Requirement 1.4).
type EmptyState struct {
	MissingSource string // SourceConnector or SourceScanner
	SetupLink     string
}

// IssueBrief is one top issue of a card.
type IssueBrief struct {
	ID        string
	Title     string
	Severity  findings.Severity
	RiskScore float64
}

// CategorySummary is one Overview card.
type CategorySummary struct {
	Category    schema.OverviewCategory
	Title       string
	Subtitle    string
	EntityCount int
	Severity    map[findings.Severity]int // all five keys always present
	TopIssues   []IssueBrief              // 0..3 by risk score desc
	EmptyState  *EmptyState
	Extra       map[string]int // entity count per kind
}

// Summaries is the result of one call: nine cards in schema.OverviewOrder.
type Summaries struct {
	Revision   uint64
	Categories []CategorySummary
}

type counts struct {
	total  int
	byKind map[string]int
}

type snapshot struct {
	severity map[schema.OverviewCategory]map[findings.Severity]int
	issues   map[schema.OverviewCategory][]IssueBrief
	data     map[string]int // Data security counters
	at       time.Time
}

// Option configures New.
type Option func(*Service)

// WithClock sets the time source used for the cache.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// Service computes Summaries.
type Service struct {
	eng  facade.Engine
	reg  *schema.Registry
	fs   *findings.Store
	db   *sql.DB
	ws   string
	now  func() time.Time
	cats map[schema.OverviewCategory][]schema.KindDeclaration

	mu       sync.Mutex
	started  bool
	counts   map[schema.OverviewCategory]counts // categoryCounts
	snap     *snapshot
	revision uint64
	last     []CategorySummary // payload behind revision

	recount chan struct{}
}

// New returns a Service over the graph engine, registry, findings store and
// the workspace database (read only; the issue table is read directly until
// the issues package exists).
func New(eng facade.Engine, reg *schema.Registry, fs *findings.Store, db *sql.DB, workspaceID string, opts ...Option) *Service {
	s := &Service{eng: eng, reg: reg, fs: fs, db: db, ws: workspaceID, now: time.Now, recount: make(chan struct{}, 1),
		cats: map[schema.OverviewCategory][]schema.KindDeclaration{}}
	for _, o := range opts {
		o(s)
	}
	for _, k := range reg.Kinds() {
		// A kind can hold entities of several categories through type overrides.
		seen := map[schema.OverviewCategory]bool{k.Overview: true}
		for _, t := range k.Types {
			if t.Overview != "" {
				seen[t.Overview] = true
			}
		}
		for c := range seen {
			s.cats[c] = append(s.cats[c], k)
		}
	}
	return s
}

// Start rebuilds categoryCounts, then keeps it current until ctx ends. It
// recounts after graph changes (engine Subscribe) and resyncs periodically as
// a safety net. Without an engine subscription it recounts every 5 s.
func (s *Service) Start(ctx context.Context) error {
	if err := s.rebuild(ctx); err != nil {
		return err
	}
	go s.loop(ctx)
	return nil
}

func (s *Service) loop(ctx context.Context) {
	var graphC <-chan facade.SeqChange
	var sub facade.Subscription
	subscribe := func() {
		graphC, sub = nil, nil
		if x, ok := facade.ExtendedOf(s.eng); ok {
			if ss, err := x.Subscribe(ctx, facade.SubscribeOpts{Subject: facade.SubjectEntity}); err == nil {
				sub, graphC = ss, ss.C()
			}
		}
	}
	subscribe()
	defer func() {
		if sub != nil {
			sub.Close()
		}
	}()
	var findingsC <-chan findings.Change // nil blocks forever without a store
	if s.fs != nil {
		findingsC = s.fs.Subscribe()
	}
	tick := time.NewTicker(resyncInterval)
	defer tick.Stop()
	var debounce <-chan time.Time
	var lastFull = s.now()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-graphC:
			if !ok { // overflowed or ended: resubscribe and recount
				subscribe()
				debounce = time.After(0)
				continue
			}
			if debounce == nil {
				debounce = time.After(recountDelay)
			}
		case _, ok := <-findingsC:
			if !ok {
				findingsC = nil
			}
			// Severity counts follow the 5 s cache; the next refresh picks the change up.
		case <-s.recount:
			debounce = time.After(0)
		case <-tick.C:
			if graphC == nil || s.now().Sub(lastFull) >= slowResync {
				debounce = time.After(0)
			}
		case <-debounce:
			debounce = nil
			lastFull = s.now()
			_ = s.rebuild(ctx)
		}
	}
}

// rebuild pages every kind through the engine and replaces categoryCounts.
func (s *Service) rebuild(ctx context.Context) error {
	next := map[schema.OverviewCategory]counts{}
	done := map[string]bool{}
	for _, c := range schema.OverviewOrder {
		for _, k := range s.cats[c] {
			if done[k.Name] {
				continue
			}
			done[k.Name] = true
			q := facade.FindQuery{Type: k.Name}
			q.PageSize = facade.MaxPageSize
			for {
				pg, err := s.eng.Query().Find(ctx, q)
				if err != nil {
					return err
				}
				for i := range pg.Items {
					cat := lens.EntityCategory(s.reg, k, pg.Items[i].Attributes)
					n := next[cat]
					if n.byKind == nil {
						n.byKind = map[string]int{}
					}
					n.total++
					n.byKind[k.Name]++
					next[cat] = n
				}
				if !pg.Truncated || pg.NextCursor == "" {
					break
				}
				q.Cursor = pg.NextCursor
			}
		}
	}
	s.mu.Lock()
	s.counts, s.started = next, true
	s.mu.Unlock()
	return nil
}

// Summaries returns the nine cards in schema.OverviewOrder. Entity counts come
// from memory; severity counts and top issues are cached for CacheTTL.
func (s *Service) Summaries(ctx context.Context) (Summaries, error) {
	s.mu.Lock()
	started, snap := s.started, s.snap
	s.mu.Unlock()
	if !started {
		return Summaries{}, ErrNotStarted
	}
	if snap == nil || s.now().Sub(snap.at) >= CacheTTL {
		fresh, err := s.load(ctx)
		if err != nil {
			return Summaries{}, err
		}
		snap = fresh
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap = snap
	cards := make([]CategorySummary, 0, len(schema.OverviewOrder))
	for _, c := range schema.OverviewOrder {
		n := s.counts[c]
		sev := make(map[findings.Severity]int, len(findings.AllSeverities))
		for _, v := range findings.AllSeverities {
			sev[v] = snap.severity[c][v]
		}
		extra := make(map[string]int, len(n.byKind))
		for k, v := range n.byKind {
			extra[k] = v
		}
		if c == schema.OvData {
			for k, v := range snap.data {
				extra[k] = v
			}
		}
		top := append([]IssueBrief{}, snap.issues[c]...)
		card := CategorySummary{Category: c, Title: Titles[c], Subtitle: Subtitles[c], EntityCount: n.total,
			Severity: sev, TopIssues: top, Extra: extra}
		if n.total == 0 {
			card.EmptyState = &EmptyState{MissingSource: SourceConnector, SetupLink: SetupLink}
			if scannerFed[c] {
				card.EmptyState.MissingSource = SourceScanner
			}
		}
		cards = append(cards, card)
	}
	if s.last == nil || !reflect.DeepEqual(s.last, cards) {
		s.revision++
		s.last = cards
	}
	return Summaries{Revision: s.revision, Categories: cards}, nil
}

// load runs the indexed severity and top issue queries.
func (s *Service) load(ctx context.Context) (*snapshot, error) {
	var sev map[schema.OverviewCategory]map[findings.Severity]int
	if s.fs != nil {
		var err error
		if sev, err = s.fs.SeverityCounts(ctx); err != nil {
			return nil, err
		}
	}
	var issues map[schema.OverviewCategory][]IssueBrief
	if s.db != nil {
		var err error
		if issues, err = s.topIssues(ctx); err != nil {
			return nil, err
		}
	}
	var data map[string]int
	if s.db != nil {
		var err error
		if data, err = s.dataCounters(ctx); err != nil {
			return nil, err
		}
	}
	return &snapshot{severity: sev, issues: issues, data: data, at: s.now()}, nil
}

// Data security counter keys in the card's Extra.
const (
	ExtraDataStores    = "data_stores"       // classified data stores
	ExtraDataSensitive = "data_sensitive"    // stores with a class other than none
	ExtraDataExposed   = "data_exposed_open" // stores with an open data_exposure finding
)

// dataCounters counts classified stores, sensitive stores and stores with an
// open data_exposure finding.
func (s *Service) dataCounters(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	rows, err := s.db.QueryContext(ctx, `SELECT classes FROM data_classification WHERE workspace_id=?`, s.ws)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var classes []string
		_ = json.Unmarshal([]byte(raw), &classes)
		out[ExtraDataStores]++
		for _, c := range classes {
			if c != "none" {
				out[ExtraDataSensitive]++
				break
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var exposed int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT asset_id) FROM finding
		WHERE workspace_id=? AND rule_id='data_exposure' AND status IN ('open','in_progress')`, s.ws).Scan(&exposed)
	out[ExtraDataExposed] = exposed
	return out, err
}

// topIssues reads up to three open issues per category by risk score
// descending, then updated_at descending (issue_cat_idx).
func (s *Service) topIssues(ctx context.Context) (map[schema.OverviewCategory][]IssueBrief, error) {
	out := map[schema.OverviewCategory][]IssueBrief{}
	for _, c := range schema.OverviewOrder {
		rows, err := s.db.QueryContext(ctx,
			`SELECT id, title, severity, risk_score FROM issue
			 WHERE workspace_id=? AND category=? AND status='open'
			 ORDER BY risk_score DESC, updated_at DESC, id LIMIT ?`, s.ws, string(c), MaxTopIssues)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var b IssueBrief
			var sev string
			if err := rows.Scan(&b.ID, &b.Title, &sev, &b.RiskScore); err != nil {
				rows.Close()
				return nil, err
			}
			b.Severity = findings.Severity(sev)
			out[c] = append(out[c], b)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Refresh asks the background loop to recount now.
func (s *Service) Refresh() {
	select {
	case s.recount <- struct{}{}:
	default:
	}
}
