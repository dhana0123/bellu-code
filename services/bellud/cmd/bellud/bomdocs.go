package main

import (
	"context"
	"strings"
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

// aiFlag is the feature flag guarding the AI API and the AI-BOM routes.
const aiFlag = "security_ai"

// bomPageSize and bomMaxItems bound one graph read for a BOM.
const (
	bomPageSize = 500
	bomMaxItems = 50000
)

// bomDocs builds the AI-BOM and Cloud-BOM from graph entities. The previous
// document of each kind is kept so a failed provider retains its components.
type bomDocs struct {
	q         graph.Query
	deny      func(string) bool
	eol       bom.CloudCheck
	mu        sync.Mutex
	prevAI    *bom.Document
	prevCloud *bom.Document
}

// newBOMDocs returns nil without a graph query. licenseDeny is the
// bom.license_deny list (BELLUCODE_BOM_LICENSE_DENY, comma separated).
func newBOMDocs(q graph.Query, licenseDeny string) *bomDocs {
	if q == nil {
		return nil
	}
	var deny []string
	for _, s := range strings.Split(licenseDeny, ",") {
		if s = strings.TrimSpace(s); s != "" {
			deny = append(deny, s)
		}
	}
	d := &bomDocs{q: q, deny: bom.LicenseDenied(deny)}
	if c, err := bom.EOLCheck(); err == nil {
		d.eol = c
	}
	return d
}

func (d *bomDocs) list(ctx context.Context, typ string) ([]graph.Entity, error) {
	var out []graph.Entity
	cursor := ""
	for len(out) < bomMaxItems {
		pg, err := d.q.Find(ctx, graph.FindQuery{Type: typ, Paging: graph.Paging{PageSize: bomPageSize, Cursor: cursor}})
		if err != nil {
			return nil, err
		}
		out = append(out, pg.Items...)
		if pg.NextCursor == "" {
			break
		}
		cursor = pg.NextCursor
	}
	return out, nil
}

func str(e graph.Entity, keys ...string) string {
	for _, k := range keys {
		if v, _ := e.Attributes[k].(string); v != "" {
			return v
		}
	}
	return ""
}

var aiCategories = map[string]bom.AICategory{
	aischema.KindModel:       bom.AIModel,
	aischema.KindMCPServer:   bom.AIMCPServer,
	aischema.KindVectorStore: bom.AIVectorStore,
	aischema.KindService:     bom.AIService,
}

// AI builds the AI-BOM from the aischema entities of the graph.
func (d *bomDocs) AI(ctx context.Context) (bom.Document, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var providers []bom.ProviderSource[bom.AIItem]
	for kind, cat := range aiCategories {
		kind, cat := kind, cat
		providers = append(providers, bom.ProviderSource[bom.AIItem]{
			Provider: "graph:" + kind,
			Fetch: func(ctx context.Context) ([]bom.AIItem, error) {
				ents, err := d.list(ctx, kind)
				if err != nil {
					return nil, err
				}
				items := make([]bom.AIItem, 0, len(ents))
				for _, e := range ents {
					name := e.Label
					if name == "" {
						name = string(e.ID)
					}
					items = append(items, bom.AIItem{
						Name: name, Category: cat, Version: str(e, "version"), License: str(e, "license"),
						Source: bom.Source{Kind: "cloud", Ref: string(e.ID)},
					})
				}
				return items, nil
			},
		})
	}
	doc := bom.BuildAI(ctx, nil, providers, bom.AIOptions{LicenseDenied: d.deny, Prev: d.prevAI})
	d.prevAI = &doc
	return doc, nil
}

// Cloud builds the Cloud-BOM from the aws_resource entities of the graph.
func (d *bomDocs) Cloud(ctx context.Context) (bom.Document, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	src := bom.ProviderSource[bom.CloudItem]{
		Provider: "aws",
		Fetch: func(ctx context.Context) ([]bom.CloudItem, error) {
			ents, err := d.list(ctx, "aws_resource")
			if err != nil {
				return nil, err
			}
			items := make([]bom.CloudItem, 0, len(ents))
			for _, e := range ents {
				rt := str(e, "resource_type")
				svc, _, _ := strings.Cut(rt, ":")
				if svc == "" {
					continue
				}
				items = append(items, bom.CloudItem{
					Service: svc, ResourceType: rt, Region: str(e, "region"),
					Version:  str(e, "engine_version", "runtime", "version"),
					Endpoint: str(e, "endpoint"),
				})
			}
			return items, nil
		},
	}
	opts := bom.CloudOptions{Prev: d.prevCloud}
	if d.eol != nil {
		opts.Checks = []bom.CloudCheck{d.eol}
	}
	doc := bom.BuildCloud(ctx, []bom.ProviderSource[bom.CloudItem]{src}, opts)
	d.prevCloud = &doc
	return doc, nil
}
