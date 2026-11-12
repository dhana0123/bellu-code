// Package routes holds the route ownership table: loading, validation and
// most-specific-match lookup. Lookup results never depend on route order.
package routes

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

type Owner string

const (
	OwnerGo Owner = "go"
	OwnerTS Owner = "ts"
)

// Route is one entry of routes.yaml.
type Route struct {
	Method  string `yaml:"method"`  // "GET", "POST", ... or "*"
	Pattern string `yaml:"pattern"` // "{param}" segments, trailing "/*" for prefix
	Group   string `yaml:"group"`
	Owner   Owner  `yaml:"owner"`
	Public  bool   `yaml:"public"` // served before authentication
	Stream  bool   `yaml:"stream"` // SSE or WebSocket; never buffered
}

// Operation is one protocol operation (method and OpenAPI path).
type Operation struct {
	Method string
	Path   string
}

// RouteTable resolves routes. A false result means the default owner (ts).
type RouteTable interface {
	Lookup(method, path string) (Route, bool)
	Routes() []Route
}

// Table is the RouteTable implementation. Build it with NewTable or Load.
type Table struct {
	entries []entry
	routes  []Route
}

type entry struct {
	route Route
	segs  []segment
}

type kind int

// Higher kind is more specific.
const (
	kindPrefix kind = iota // trailing "*"
	kindParam
	kindExact
)

type segment struct {
	kind kind
	lit  string
}

// CleanPath collapses repeated slashes, resolves "." and ".." segments and
// removes a trailing slash other than the root.
func CleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// NewTable validates entries and overlaps, then builds a table.
func NewTable(routes []Route) (*Table, error) {
	t := &Table{routes: append([]Route(nil), routes...)}
	for i, r := range routes {
		segs, err := parsePattern(r.Pattern)
		if err == nil {
			err = checkEntry(r)
		}
		if err != nil {
			return nil, fmt.Errorf("route entry %d (%q): %w", i+1, r.Pattern, err)
		}
		t.entries = append(t.entries, entry{route: r, segs: segs})
	}
	for i := range t.entries {
		for j := i + 1; j < len(t.entries); j++ {
			if overlaps(t.entries[i], t.entries[j]) {
				return nil, fmt.Errorf("routes %q and %q overlap", t.entries[i].route.Pattern, t.entries[j].route.Pattern)
			}
		}
	}
	return t, nil
}

func (t *Table) Routes() []Route { return append([]Route(nil), t.routes...) }

// Lookup returns the most specific route for the method and path. The path is
// cleaned first. The result is independent of table order.
func (t *Table) Lookup(method, p string) (Route, bool) {
	reqSegs := splitPath(CleanPath(p))
	var best *entry
	for i := range t.entries {
		e := &t.entries[i]
		if e.route.Method != "*" && !strings.EqualFold(e.route.Method, method) {
			continue
		}
		if !matches(e.segs, reqSegs) {
			continue
		}
		if best == nil || moreSpecific(*e, *best) {
			best = e
		}
	}
	if best == nil {
		return Route{}, false
	}
	return best.route, true
}

// Validate checks entries, disjointness and totality against the protocol
// operations. Overlap errors name both patterns; totality errors name the
// operation method and path.
func Validate(routes []Route, ops []Operation) error {
	t, err := NewTable(routes)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if _, ok := t.Lookup(op.Method, examplePath(op.Path)); !ok {
			return fmt.Errorf("operation %s %s has no route", op.Method, op.Path)
		}
	}
	return nil
}

type file struct {
	Version int        `yaml:"version"`
	Routes  []rawRoute `yaml:"routes"`
}

type rawRoute struct {
	Method  *string `yaml:"method"`
	Pattern *string `yaml:"pattern"`
	Group   *string `yaml:"group"`
	Owner   *string `yaml:"owner"`
	Public  *bool   `yaml:"public"`
	Stream  *bool   `yaml:"stream"`
}

// Load parses routes.yaml content and returns a validated table.
func Load(r io.Reader) (*Table, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	routes, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return NewTable(routes)
}

// Parse decodes routes.yaml, requiring every field on every entry.
func Parse(data []byte) ([]Route, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse routes: %w", err)
	}
	out := make([]Route, 0, len(f.Routes))
	for i, raw := range f.Routes {
		missing := missingFields(raw)
		if len(missing) > 0 {
			return nil, fmt.Errorf("route entry %d%s: missing %s", i+1, describe(raw.Pattern), strings.Join(missing, ", "))
		}
		out = append(out, Route{
			Method: *raw.Method, Pattern: *raw.Pattern, Group: *raw.Group,
			Owner: Owner(*raw.Owner), Public: *raw.Public, Stream: *raw.Stream,
		})
	}
	return out, nil
}

func describe(p *string) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf(" (%q)", *p)
}

func missingFields(r rawRoute) []string {
	var m []string
	if r.Method == nil || *r.Method == "" {
		m = append(m, "method")
	}
	if r.Pattern == nil || *r.Pattern == "" {
		m = append(m, "pattern")
	}
	if r.Group == nil || *r.Group == "" {
		m = append(m, "group")
	}
	if r.Owner == nil || *r.Owner == "" {
		m = append(m, "owner")
	}
	if r.Public == nil {
		m = append(m, "public")
	}
	if r.Stream == nil {
		m = append(m, "stream")
	}
	return m
}

func checkEntry(r Route) error {
	if r.Owner != OwnerGo && r.Owner != OwnerTS {
		return fmt.Errorf("owner %q must be %q or %q", r.Owner, OwnerGo, OwnerTS)
	}
	if r.Group == "" {
		return fmt.Errorf("missing group")
	}
	switch r.Method {
	case "*", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return nil
	}
	return fmt.Errorf("invalid method %q", r.Method)
}

func parsePattern(p string) ([]segment, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("pattern must start with /")
	}
	if p == "/" {
		return nil, nil
	}
	parts := strings.Split(p[1:], "/")
	segs := make([]segment, 0, len(parts))
	for i, s := range parts {
		switch {
		case s == "":
			return nil, fmt.Errorf("empty segment")
		case s == "*":
			if i != len(parts)-1 {
				return nil, fmt.Errorf("%q is only allowed as the last segment", "*")
			}
			segs = append(segs, segment{kind: kindPrefix})
		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && len(s) > 2 && !strings.ContainsAny(s[1:len(s)-1], "{}*"):
			segs = append(segs, segment{kind: kindParam})
		case strings.ContainsAny(s, "{}*"):
			return nil, fmt.Errorf("malformed segment %q", s)
		default:
			segs = append(segs, segment{kind: kindExact, lit: s})
		}
	}
	return segs, nil
}

func splitPath(p string) []string {
	if p == "/" {
		return nil
	}
	return strings.Split(p[1:], "/")
}

// matches: a prefix segment consumes one or more remaining segments.
func matches(pat []segment, req []string) bool {
	for i, s := range pat {
		if s.kind == kindPrefix {
			return len(req) > i
		}
		if i >= len(req) {
			return false
		}
		if s.kind == kindExact && s.lit != req[i] {
			return false
		}
	}
	return len(pat) == len(req)
}

// moreSpecific compares path specificity segment by segment, then method.
// Ties fall back to pattern and method text so the result stays deterministic.
func moreSpecific(a, b entry) bool {
	for i := 0; i < len(a.segs) && i < len(b.segs); i++ {
		if a.segs[i].kind != b.segs[i].kind {
			return a.segs[i].kind > b.segs[i].kind
		}
	}
	if len(a.segs) != len(b.segs) {
		return len(a.segs) > len(b.segs)
	}
	if (a.route.Method == "*") != (b.route.Method == "*") {
		return b.route.Method == "*"
	}
	if a.route.Pattern != b.route.Pattern {
		return a.route.Pattern < b.route.Pattern
	}
	return a.route.Method < b.route.Method
}

// overlaps reports equal specificity (same method, same kind per segment) with
// at least one common path.
func overlaps(a, b entry) bool {
	if a.route.Method != b.route.Method || len(a.segs) != len(b.segs) {
		return false
	}
	for i := range a.segs {
		x, y := a.segs[i], b.segs[i]
		if x.kind != y.kind || (x.kind == kindExact && x.lit != y.lit) {
			return false
		}
	}
	return true
}

// examplePath turns an OpenAPI path into a concrete request path.
func examplePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "_param_"
		}
	}
	return strings.Join(segs, "/")
}
