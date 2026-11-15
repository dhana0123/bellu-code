package lens

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/risk"
)

// ErrUnknownLens is returned for a lens id outside the catalog.
type ErrUnknownLens struct{ ID string }

func (e ErrUnknownLens) Error() string { return fmt.Sprintf("unknown lens %q", e.ID) }

// ErrInvalidParam is returned when a required parameter is missing or bad.
type ErrInvalidParam struct{ Field string }

func (e ErrInvalidParam) Error() string {
	return fmt.Sprintf("missing or invalid parameter %q", e.Field)
}

// Params are the request parameters of a slice.
type Params struct {
	Entity string
	Target string
	Depth  int
	// MaxNodes and MaxEdges bound the result; zero selects the HTTP defaults.
	MaxNodes int
	MaxEdges int
}

// Engine builds slices from a read-only Source.
type Engine struct {
	src Source
	now func() time.Time
}

// NewEngine returns an Engine over src.
func NewEngine(src Source) *Engine { return &Engine{src: src, now: time.Now} }

// Catalog lists the lens definitions.
func (e *Engine) Catalog() []Def { return Catalog() }

// Slice builds the slice of lens id. Unknown ids return ErrUnknownLens.
func (e *Engine) Slice(ctx context.Context, id string, p Params) (Slice, error) {
	def, ok := lookup(id)
	if !ok {
		return Slice{}, ErrUnknownLens{ID: id}
	}
	b := &builder{src: e.src, def: def, nodes: map[string]*facade.Entity{}, hops: map[string]int{}, edges: map[SliceEdge]struct{}{}}
	var err error
	switch def.Select {
	case SelectKinds:
		err = b.selectKinds(ctx)
	case SelectImpact:
		err = b.selectImpact(ctx, p)
	case SelectAttackPaths:
		err = b.selectAttackPaths(ctx, p)
	case SelectReachableVul:
		err = b.selectReachable(ctx)
	}
	if err != nil {
		return Slice{}, err
	}
	s := b.finish(ctx, e.now().UTC())
	maxN, maxE := p.MaxNodes, p.MaxEdges
	if maxN <= 0 {
		maxN = DefaultMaxNodes
	}
	if maxE <= 0 {
		maxE = DefaultMaxEdges
	}
	return Budget(s, maxN, maxE), nil
}

type builder struct {
	src       Source
	def       Def
	root      string
	nodes     map[string]*facade.Entity // nil value: kind known only, load lazily
	hops      map[string]int
	edges     map[SliceEdge]struct{}
	paths     []Path
	reachable map[string]bool
	truncated bool
}

func (b *builder) add(id string, hops int) {
	if _, ok := b.nodes[id]; !ok {
		b.nodes[id] = nil
	}
	if h, ok := b.hops[id]; !ok || hops < h {
		b.hops[id] = hops
	}
}

func (b *builder) addEdge(e facade.Edge) {
	b.edges[SliceEdge{From: string(e.From), To: string(e.To), Type: e.Type, Confidence: Confidence(e.Type)}] = struct{}{}
}

// findAll pages through Find up to collectCap entities.
func (b *builder) findAll(ctx context.Context, q facade.FindQuery, limit int) ([]facade.Entity, error) {
	q.PageSize = facade.MaxPageSize
	var out []facade.Entity
	for {
		pg, err := b.src.Find(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, en := range pg.Items {
			if len(out) >= limit {
				b.truncated = true
				return out, nil
			}
			out = append(out, en)
		}
		if !pg.Truncated || pg.NextCursor == "" {
			return out, nil
		}
		q.Cursor = pg.NextCursor
	}
}

func (b *builder) selectKinds(ctx context.Context) error {
	for _, kind := range b.def.Kinds {
		room := collectCap - len(b.nodes)
		if room <= 0 {
			b.truncated = true
			break
		}
		items, err := b.findAll(ctx, facade.FindQuery{Type: kind}, room)
		if err != nil {
			return err
		}
		for i := range items {
			en := items[i]
			b.nodes[string(en.ID)] = &en
			b.hops[string(en.ID)] = 0
		}
	}
	for id := range b.nodes {
		var cursor string
		for {
			pg, err := b.src.Neighbors(ctx, facade.EntityID(id), facade.NeighborOpts{
				Direction: facade.DirOut, Depth: 1, Paging: facade.Paging{PageSize: facade.MaxPageSize, Cursor: cursor},
			})
			if err != nil {
				return err
			}
			for _, e := range pg.Items {
				if _, ok := b.nodes[string(e.To)]; ok && !e.Derived {
					b.addEdge(e)
				}
			}
			if !pg.Truncated || pg.NextCursor == "" {
				break
			}
			cursor = pg.NextCursor
		}
	}
	return nil
}

func (b *builder) selectImpact(ctx context.Context, p Params) error {
	if strings.TrimSpace(p.Entity) == "" {
		return ErrInvalidParam{Field: "entity"}
	}
	depth := p.Depth
	if depth <= 0 {
		depth = DefaultDepth
	}
	if depth > MaxDepth {
		depth = MaxDepth
	}
	root, err := b.src.Resolve(ctx, p.Entity)
	if err != nil {
		return err
	}
	res, err := b.src.Impact(ctx, string(root), facade.ImpactOpts{Depth: depth})
	if err != nil {
		return err
	}
	b.root = string(root)
	b.add(b.root, 0)
	for _, it := range res.Items {
		b.add(string(it.ID), it.Hops)
		for _, e := range it.Via {
			b.add(string(e.From), b.hops[b.root]+1)
			b.add(string(e.To), b.hops[b.root]+1)
			b.addEdge(e)
		}
		if len(b.paths) < 200 {
			b.paths = append(b.paths, b.pathOf(b.root, it.Via))
		}
	}
	return nil
}

func (b *builder) selectAttackPaths(ctx context.Context, p Params) error {
	if strings.TrimSpace(p.Target) == "" {
		return ErrInvalidParam{Field: "target"}
	}
	target, err := b.src.Resolve(ctx, p.Target)
	if err != nil {
		return err
	}
	b.root = string(target)
	b.add(b.root, 0)
	exposed, err := b.exposed(ctx, MaxExposed)
	if err != nil {
		return err
	}
	for _, src := range exposed {
		if src.ID == target {
			continue
		}
		r, err := b.src.Path(ctx, string(src.ID), string(target), facade.PathOpts{MaxDepth: AttackMaxDepth})
		if err != nil {
			return err
		}
		if !r.Connected || len(r.Path) == 0 {
			continue
		}
		path := b.pathOf(string(src.ID), r.Path)
		for i, id := range path.Nodes {
			b.add(id, i)
		}
		for _, e := range r.Path {
			b.addEdge(e)
		}
		b.paths = append(b.paths, path)
	}
	return nil
}

func (b *builder) selectReachable(ctx context.Context) error {
	vulns, err := b.findAll(ctx, facade.FindQuery{Type: "vulnerability"}, collectCap)
	if err != nil {
		return err
	}
	exposed, err := b.exposed(ctx, collectCap)
	if err != nil {
		return err
	}
	exp := make(map[string]struct{}, len(exposed))
	for _, en := range exposed {
		exp[string(en.ID)] = struct{}{}
	}
	b.reachable = map[string]bool{}
	for i := range vulns {
		v := vulns[i]
		vid := string(v.ID)
		res, err := b.src.Impact(ctx, vid, facade.ImpactOpts{Depth: MaxDepth})
		if err != nil {
			return err
		}
		var hit *facade.Impacted
		for j := range res.Items {
			if _, ok := exp[string(res.Items[j].ID)]; ok {
				hit = &res.Items[j]
				break
			}
		}
		b.reachable[vid] = hit != nil
		if hit == nil {
			continue
		}
		b.nodes[vid] = &v
		b.hops[vid] = 0
		// Include the vulnerability's packages (hop 1) and the chain to the
		// exposed entity.
		for _, e := range hit.Via {
			b.add(string(e.From), 1)
			b.add(string(e.To), 1)
			b.addEdge(e)
		}
		b.add(string(hit.ID), hit.Hops)
		b.paths = append(b.paths, b.pathOf(vid, hit.Via))
	}
	return nil
}

func (b *builder) exposed(ctx context.Context, limit int) ([]facade.Entity, error) {
	items, err := b.findAll(ctx, facade.FindQuery{Attributes: map[string]string{"internet_exposed": "true"}}, limit)
	if err != nil {
		return nil, err
	}
	// Pagination truncation caused by the exposed cap is not a slice truncation.
	return items, nil
}

// pathOf walks edges from start and returns the node chain.
func (b *builder) pathOf(start string, edges []facade.Edge) Path {
	nodes := []string{start}
	cur := start
	conf := make([]string, 0, len(edges))
	for _, e := range edges {
		next := string(e.To)
		if next == cur {
			next = string(e.From)
		}
		nodes = append(nodes, next)
		conf = append(conf, Confidence(e.Type))
		cur = next
	}
	return Path{Nodes: nodes, Confidence: PathConfidence(conf)}
}

// finish loads missing entities, applies the allowlist, groups, scores risk,
// and prunes. Output order is deterministic.
func (b *builder) finish(ctx context.Context, now time.Time) Slice {
	ids := make([]string, 0, len(b.nodes))
	for id := range b.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	nodes := make([]Node, 0, len(ids))
	groupIdx := map[string]*Group{}
	var groupOrder []string
	for _, id := range ids {
		en := b.nodes[id]
		if en == nil {
			loaded, err := b.src.Entity(ctx, facade.EntityID(id))
			if err != nil {
				// A node that cannot be read (retired mid-read) is dropped;
				// Prune removes its edges.
				continue
			}
			en = &loaded
		}
		raw := stringAttrs(en.Attributes)
		n := Node{
			ID: id, Kind: en.Type, Label: en.Label, Hops: b.hops[id],
			Attrs: FilterAttrs(en.Type, raw),
		}
		if n.Label == "" {
			n.Label = raw["name"]
		}
		if n.Label == "" {
			n.Label = id
		}
		if gv := b.groupValue(raw); gv != "" {
			gid := b.def.Group + ":" + gv
			n.Group = &gid
			g, ok := groupIdx[gid]
			if !ok {
				g = &Group{ID: gid, Label: gv}
				groupIdx[gid] = g
				groupOrder = append(groupOrder, gid)
			}
			g.Members = append(g.Members, id)
		}
		if en.Type == "vulnerability" {
			n.Risk = b.riskOf(id, en.Attributes)
		}
		nodes = append(nodes, n)
	}
	edges := make([]SliceEdge, 0, len(b.edges))
	for e := range b.edges {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		a, c := edges[i], edges[j]
		if a.From != c.From {
			return a.From < c.From
		}
		if a.To != c.To {
			return a.To < c.To
		}
		return a.Type < c.Type
	})
	edges = Prune(nodes, edges)
	groups := make([]Group, 0, len(groupOrder))
	sort.Strings(groupOrder)
	for _, gid := range groupOrder {
		groups = append(groups, *groupIdx[gid])
	}
	return Slice{
		Lens: b.def.ID, GeneratedAt: now, Truncated: b.truncated,
		Counts: Counts{Nodes: len(nodes), Edges: len(edges)},
		Nodes:  nodes, Edges: edges, Groups: groups, Paths: b.keptPaths(nodes), Root: b.root,
	}
}

func (b *builder) keptPaths(nodes []Node) []Path {
	in := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		in[n.ID] = struct{}{}
	}
	var out []Path
	for _, p := range b.paths {
		ok := true
		for _, id := range p.Nodes {
			if _, has := in[id]; !has {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, p)
		}
	}
	return out
}

func (b *builder) groupValue(raw map[string]string) string {
	if b.def.Group == "" {
		return ""
	}
	return raw[b.def.Group]
}

func (b *builder) riskOf(id string, attrs map[string]any) *Risk {
	cvss := num(attrs["cvss"])
	epss := num(attrs["epss"])
	kev := fmt.Sprint(attrs["kev"]) == "true"
	var reach *bool
	if b.reachable != nil {
		r := b.reachable[id]
		reach = &r
	}
	score := risk.Compute(risk.Inputs{CVSS: cvss, EPSS: epss, KEV: kev, Reachable: reach != nil && *reach})
	return &Risk{
		Score: score, Severity: string(risk.Bucket(score, kev)),
		CVSS: cvss, EPSS: epss, KEV: kev, Reachable: reach,
	}
}

func stringAttrs(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case nil:
		case string:
			out[k] = t
		default:
			out[k] = fmt.Sprint(t)
		}
	}
	return out
}

func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	}
	return 0
}
