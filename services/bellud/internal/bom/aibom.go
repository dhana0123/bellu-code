package bom

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Property names written on AI-BOM and Cloud-BOM components.
const (
	PropProvider     = "bellu:provider"
	PropCategory     = "bellu:category"
	PropLicenseDeny  = "bellu:license_denied"
	PropResourceType = "bellu:resource_type"
	PropRegion       = "bellu:region"
	PropCount        = "bellu:count"
	PropDataFlow     = "bellu:data_flow"
	PropEndpoint     = "bellu:endpoint"
)

// ConnectorTimeout bounds one provider fetch (Requirement 6.11).
const ConnectorTimeout = 30 * time.Second

// UnknownVersion and UnknownLicense are recorded when a source gives none.
const (
	UnknownVersion = "unknown"
	UnknownLicense = "unknown"
)

// AICategory is the category of an AI-BOM component (Requirement 6.1).
type AICategory string

const (
	AIModel       AICategory = "model"
	AISDK         AICategory = "sdk"
	AIFramework   AICategory = "framework"
	AIMCPServer   AICategory = "mcp_server"
	AIVectorStore AICategory = "vector_store"
	AIService     AICategory = "ai_service"
)

// aiTypes maps a category to its CycloneDX component type (Requirement 6.4).
var aiTypes = map[AICategory]string{
	AIModel:       "machine-learning-model",
	AISDK:         "library",
	AIFramework:   "framework",
	AIMCPServer:   "service",
	AIVectorStore: "service",
	AIService:     "service",
}

// Source says where a component was found: kind is "code", "manifest",
// "config" or "cloud", and ref is a path or a cloud resource identifier.
type Source struct {
	Kind string
	Ref  string
}

// AIItem is one detected AI component, from a scan or a connector.
type AIItem struct {
	Name     string
	Category AICategory
	Version  string // empty means unknown
	License  string // empty means unknown
	Source   Source
}

// CloudItem is one collected cloud entity.
type CloudItem struct {
	Service      string // e.g. "rds", "eks", "lambda"
	ResourceType string
	Region       string
	Version      string // managed component version (engine, runtime); may be empty
	DataFlow     string // optional
	Endpoint     string // optional
}

// ProviderGap marks a provider section as incomplete.
type ProviderGap struct {
	Provider string
	Cause    string
}

// Kind names the kind of BOM a Document holds.
type Kind string

const (
	KindAI    Kind = "ai"
	KindCloud Kind = "cloud"
)

// Document is an AI-BOM or Cloud-BOM. SBOM can be passed to Write.
type Document struct {
	Kind       Kind
	SBOM       SBOM
	Incomplete []ProviderGap
	Findings   []Finding
}

// Finding is a misconfiguration produced by a CloudCheck. Rule and ID are
// stable for the same component and version so reruns do not duplicate.
type Finding struct {
	ID        string
	Rule      string
	Severity  string
	Component string
	Version   string
	Message   string
}

// CloudCheck inspects one Cloud-BOM component. Task 50.2 supplies the
// end-of-life check here.
type CloudCheck func(p Package, now time.Time) []Finding

// ProviderSource fetches the items of one provider. Fetch must honour ctx.
type ProviderSource[T any] struct {
	Provider string
	Fetch    func(ctx context.Context) ([]T, error)
}

// AIOptions configures BuildAI.
type AIOptions struct {
	// LicenseDenied reports whether a known license is on the deny list.
	// Task 50.2 supplies it from the bom.license_deny config. Nil denies nothing.
	LicenseDenied func(license string) bool
	// Prev is the previous document; its components for a failed provider are kept.
	Prev *Document
	// Timeout overrides ConnectorTimeout (tests).
	Timeout time.Duration
}

// CloudOptions configures BuildCloud.
type CloudOptions struct {
	Checks  []CloudCheck
	Now     func() time.Time
	Prev    *Document
	Timeout time.Duration
}

// BuildAI builds an AI-BOM. local holds items found by repository scans.
// A failing provider only marks its own section incomplete and keeps its
// previous components.
func BuildAI(ctx context.Context, local []AIItem, providers []ProviderSource[AIItem], opts AIOptions) Document {
	doc := Document{Kind: KindAI}
	type group struct {
		item     AIItem
		provider string
		sources  map[Source]bool
	}
	groups := map[string]*group{}
	add := func(provider string, it AIItem) {
		if it.Version == "" {
			it.Version = UnknownVersion
		}
		key := strings.Join([]string{provider, it.Name, string(it.Category), it.Version}, "\x00")
		g := groups[key]
		if g == nil {
			g = &group{item: it, provider: provider, sources: map[Source]bool{}}
			groups[key] = g
		}
		if g.item.License == "" {
			g.item.License = it.License
		}
		g.sources[it.Source] = true
	}
	for _, it := range local {
		add("", it)
	}
	for _, p := range providers {
		items, err := fetch(ctx, p, opts.Timeout)
		if err != nil {
			doc.Incomplete = append(doc.Incomplete, ProviderGap{Provider: p.Provider, Cause: err.Error()})
			continue
		}
		for _, it := range items {
			add(p.Provider, it)
		}
	}
	for _, g := range groups {
		typ, ok := aiTypes[g.item.Category]
		if !ok {
			continue
		}
		version := g.item.Version
		pkg := Package{
			Type: typ, Name: g.item.Name, Version: &version,
			Properties: map[string]string{PropCategory: string(g.item.Category)},
		}
		if g.provider != "" {
			pkg.Properties[PropProvider] = g.provider
		}
		for s := range g.sources {
			pkg.Locations = append(pkg.Locations, s.Kind+":"+s.Ref)
		}
		sort.Strings(pkg.Locations)
		if g.item.Category == AIModel {
			license := g.item.License
			if license == "" {
				license = UnknownLicense
			}
			pkg.Licenses = []string{license}
			if license != UnknownLicense && opts.LicenseDenied != nil && opts.LicenseDenied(license) {
				pkg.Properties[PropLicenseDeny] = "true"
			}
		}
		doc.SBOM.Packages = append(doc.SBOM.Packages, pkg)
	}
	doc.SBOM.Packages = append(doc.SBOM.Packages, retained(opts.Prev, doc.Incomplete)...)
	sortPackages(doc.SBOM.Packages)
	return doc
}

// BuildCloud builds a Cloud-BOM with one service component per
// (provider, service, resource type, region, version) and a resource count.
func BuildCloud(ctx context.Context, providers []ProviderSource[CloudItem], opts CloudOptions) Document {
	doc := Document{Kind: KindCloud}
	type group struct {
		item      CloudItem
		provider  string
		count     int
		flows     map[string]bool
		endpoints map[string]bool
	}
	groups := map[string]*group{}
	for _, p := range providers {
		items, err := fetch(ctx, p, opts.Timeout)
		if err != nil {
			doc.Incomplete = append(doc.Incomplete, ProviderGap{Provider: p.Provider, Cause: err.Error()})
			continue
		}
		for _, it := range items {
			key := strings.Join([]string{p.Provider, it.Service, it.ResourceType, it.Region, it.Version}, "\x00")
			g := groups[key]
			if g == nil {
				g = &group{item: it, provider: p.Provider, flows: map[string]bool{}, endpoints: map[string]bool{}}
				groups[key] = g
			}
			g.count++
			if it.DataFlow != "" {
				g.flows[it.DataFlow] = true
			}
			if it.Endpoint != "" {
				g.endpoints[it.Endpoint] = true
			}
		}
	}
	for _, g := range groups {
		pkg := Package{
			Type: "service", Name: g.item.Service,
			Properties: map[string]string{
				PropProvider:     g.provider,
				PropResourceType: g.item.ResourceType,
				PropRegion:       g.item.Region,
				PropCount:        strconv.Itoa(g.count),
			},
		}
		if g.item.Version != "" {
			v := g.item.Version
			pkg.Version = &v
		}
		// Data flow and endpoint are written only when an entity has them.
		if len(g.flows) > 0 {
			pkg.Properties[PropDataFlow] = joinSet(g.flows)
		}
		if len(g.endpoints) > 0 {
			pkg.Properties[PropEndpoint] = joinSet(g.endpoints)
		}
		doc.SBOM.Packages = append(doc.SBOM.Packages, pkg)
	}
	doc.SBOM.Packages = append(doc.SBOM.Packages, retained(opts.Prev, doc.Incomplete)...)
	sortPackages(doc.SBOM.Packages)
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	for _, p := range doc.SBOM.Packages {
		for _, c := range opts.Checks {
			doc.Findings = append(doc.Findings, c(p, now())...)
		}
	}
	return doc
}

// fetch runs one provider with a timeout. It returns on timeout even when
// Fetch ignores ctx.
func fetch[T any](ctx context.Context, p ProviderSource[T], timeout time.Duration) ([]T, error) {
	if timeout <= 0 {
		timeout = ConnectorTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		items []T
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		items, err := p.Fetch(ctx)
		ch <- result{items, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("%s: %w", p.Provider, r.err)
		}
		return r.items, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s: no response within %s", p.Provider, timeout)
		}
		return nil, fmt.Errorf("%s: %w", p.Provider, ctx.Err())
	}
}

// retained returns the previous components of every incomplete provider.
func retained(prev *Document, gaps []ProviderGap) []Package {
	if prev == nil || len(gaps) == 0 {
		return nil
	}
	failed := map[string]bool{}
	for _, g := range gaps {
		failed[g.Provider] = true
	}
	var out []Package
	for _, p := range prev.SBOM.Packages {
		if failed[p.Properties[PropProvider]] {
			out = append(out, p)
		}
	}
	return out
}

func sortPackages(ps []Package) {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if av, bv := deref(a.Version), deref(b.Version); av != bv {
			return av < bv
		}
		ak := a.Properties[PropProvider] + a.Properties[PropResourceType] + a.Properties[PropRegion]
		bk := b.Properties[PropProvider] + b.Properties[PropResourceType] + b.Properties[PropRegion]
		return ak < bk
	})
}

func joinSet(s map[string]bool) string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
