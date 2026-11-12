// Package openapi builds the merged /openapi.json: the TS child's document plus
// the embedded Go contract operations, with Go-owned operations taken only
// from the embedded document.
package openapi

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

//go:embed gocontract.json
var goContract []byte

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// Merger fetches, merges and caches the document.
type Merger struct {
	Child    func() *tschild.Child // current child, nil when not ready
	Table    routes.RouteTable
	Client   *http.Client  // optional
	Attempt  time.Duration // per-attempt timeout, default 10s
	Retries  int           // retries after the first attempt, default 3
	Interval time.Duration // between attempts, default 1s

	mu     sync.Mutex
	cached []byte
	owner  *tschild.Child // child the cache was built from
}

// New returns a Merger with the spec defaults.
func New(child func() *tschild.Child, table routes.RouteTable) *Merger {
	return &Merger{Child: child, Table: table, Attempt: 10 * time.Second, Retries: 3, Interval: time.Second}
}

// Invalidate discards the cached document.
func (m *Merger) Invalidate() {
	m.mu.Lock()
	m.cached, m.owner = nil, nil
	m.mu.Unlock()
}

// Get returns the merged document. The cache is dropped when the child differs
// from the one it was built from (restart). When every fetch fails it returns
// the Go-only document, uncached, with a nil error.
func (m *Merger) Get(ctx context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	child := m.Child()
	if m.cached != nil && child == m.owner {
		return m.cached, nil
	}
	m.cached, m.owner = nil, nil
	if child != nil {
		if doc, ok := m.fetch(ctx, child); ok {
			out, err := Merge(doc, m.Table)
			if err == nil {
				m.cached, m.owner = out, child
				return out, nil
			}
		}
	}
	return Merge(nil, m.Table)
}

func (m *Merger) fetch(ctx context.Context, child *tschild.Child) (map[string]any, bool) {
	retries, interval := m.Retries, m.Interval
	for i := 0; i <= retries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, false
			case <-time.After(interval):
			}
		}
		if doc, err := m.fetchOnce(ctx, child); err == nil {
			return doc, true
		}
	}
	return nil, false
}

func (m *Merger) fetchOnce(ctx context.Context, child *tschild.Child) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, m.Attempt)
	defer cancel()
	target := child.URL.ResolveReference(&url.URL{Path: "/openapi.json"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(tschild.Username, child.Password)
	client := m.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("openapi fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if _, ok := doc["openapi"].(string); !ok {
		return nil, errors.New("openapi fetch: not an OpenAPI document")
	}
	if _, ok := doc["paths"].(map[string]any); !ok {
		return nil, errors.New("openapi fetch: missing paths")
	}
	return doc, nil
}

// Merge adds the embedded Go contract to child (nil means Go-only), removing
// child operations owned by Go so each method and path appears once.
func Merge(child map[string]any, table routes.RouteTable) ([]byte, error) {
	var contract map[string]any
	if err := json.Unmarshal(goContract, &contract); err != nil {
		return nil, err
	}
	doc := child
	if doc == nil {
		doc = map[string]any{"openapi": contract["openapi"], "info": contract["info"]}
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths == nil {
		paths = map[string]any{}
		doc["paths"] = paths
	}
	// Drop Go-owned operations still declared by the child.
	for p, v := range paths {
		item, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for _, method := range methods {
			if _, has := item[method]; !has {
				continue
			}
			if r, found := table.Lookup(strings.ToUpper(method), p); found && r.Owner == routes.OwnerGo {
				delete(item, method)
			}
		}
		if !hasOperation(item) {
			delete(paths, p)
		}
	}
	// Add the embedded Go operations (their definition wins).
	cpaths, _ := contract["paths"].(map[string]any)
	for p, v := range cpaths {
		item, _ := v.(map[string]any)
		dst, _ := paths[p].(map[string]any)
		if dst == nil {
			dst = map[string]any{}
			paths[p] = dst
		}
		for k, op := range item {
			dst[k] = op
		}
	}
	// Merge component schemas; the child's schema wins on name clashes.
	if cs := schemasOf(contract); len(cs) > 0 {
		comps, _ := doc["components"].(map[string]any)
		if comps == nil {
			comps = map[string]any{}
			doc["components"] = comps
		}
		dst, _ := comps["schemas"].(map[string]any)
		if dst == nil {
			dst = map[string]any{}
			comps["schemas"] = dst
		}
		for name, s := range cs {
			if _, exists := dst[name]; !exists {
				dst[name] = s
			}
		}
	}
	return json.Marshal(doc)
}

func schemasOf(doc map[string]any) map[string]any {
	c, _ := doc["components"].(map[string]any)
	s, _ := c["schemas"].(map[string]any)
	return s
}

func hasOperation(item map[string]any) bool {
	for _, m := range methods {
		if _, ok := item[m]; ok {
			return true
		}
	}
	return false
}
