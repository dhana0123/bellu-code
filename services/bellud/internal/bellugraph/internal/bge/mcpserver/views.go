package mcpserver

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/uri"
)

// Verbosity is the response detail tier of a read tool.
type Verbosity string

// Verbosity tiers.
const (
	Brief  Verbosity = "brief"
	Normal Verbosity = "normal"
	Full   Verbosity = "full"
)

// Normal-tier limits.
const (
	maxNormalAttrs = 32
	maxNormalValue = 256
)

// ParseVerbosity validates the optional verbosity argument; empty is Normal.
func ParseVerbosity(s string) (Verbosity, error) {
	switch Verbosity(s) {
	case "":
		return Normal, nil
	case Brief, Normal, Full:
		return Verbosity(s), nil
	}
	return "", fmt.Errorf("%w: verbosity %q must be brief, normal or full", errs.Validation, s)
}

// EntityOut is the projection of an entity. Fields beyond the brief tier are
// omitted at brief.
type EntityOut struct {
	ID                  string            `json:"id" jsonschema:"short local id (@xxxxxx), valid for about 15 minutes"`
	IdentityFingerprint string            `json:"identity_fingerprint" jsonschema:"stable entity id"`
	Kind                string            `json:"kind"`
	Label               string            `json:"label"`
	Attributes          map[string]any    `json:"attributes,omitempty"`
	TruncatedAttributes []string          `json:"truncated_attributes,omitempty" jsonschema:"attributes whose values were cut to 256 bytes"`
	OmittedAttributes   int               `json:"omitted_attributes,omitempty" jsonschema:"attributes not shown (normal shows at most 32)"`
	Annotations         map[string]string `json:"annotations,omitempty"`
	ObservedAt          string            `json:"observed_at,omitempty"`
	RecordedAt          string            `json:"recorded_at,omitempty"`
	URI                 string            `json:"uri,omitempty"`
}

// project is the one verbosity projection shared by every tool.
func (s *Server) project(e engine.EntityView, v Verbosity) EntityOut {
	out := EntityOut{
		ID:                  s.cfg.Core.LocalID(e.ID),
		IdentityFingerprint: e.ID,
		Kind:                e.Kind,
		Label:               e.Label,
	}
	if v == Brief {
		return out
	}
	if len(e.Annotations) > 0 {
		out.Annotations = e.Annotations
	}
	keys := make([]string, 0, len(e.Attributes))
	for k := range e.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if v == Normal {
		if len(keys) > maxNormalAttrs {
			out.OmittedAttributes = len(keys) - maxNormalAttrs
			keys = keys[:maxNormalAttrs]
		}
		out.Attributes = make(map[string]any, len(keys))
		for _, k := range keys {
			val, cut := cutValue(e.Attributes[k])
			out.Attributes[k] = val
			if cut {
				out.TruncatedAttributes = append(out.TruncatedAttributes, k)
			}
		}
		return out
	}
	out.Attributes = e.Attributes
	out.ObservedAt = e.ObservedAt.UTC().Format(time.RFC3339Nano)
	out.RecordedAt = e.RecordedAt.UTC().Format(time.RFC3339Nano)
	out.URI = entityURI(e.ID)
	return out
}

func entityURI(id string) string {
	kind, hex, ok := strings.Cut(id, ":")
	if !ok {
		return ""
	}
	u, err := uri.Format(uri.Entity{Kind: kind, Hex: hex})
	if err != nil {
		return ""
	}
	return u
}

// cutValue cuts a string (or list of strings) value to 256 bytes.
func cutValue(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		return cutString(x)
	case []string:
		out := make([]string, len(x))
		cut := false
		for i, e := range x {
			var c bool
			out[i], c = cutString(e)
			cut = cut || c
		}
		return out, cut
	}
	return v, false
}

func cutString(s string) (string, bool) {
	if len(s) <= maxNormalValue {
		return s, false
	}
	n := maxNormalValue
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

func (s *Server) projectAll(es []engine.EntityView, v Verbosity) []EntityOut {
	out := make([]EntityOut, len(es))
	for i, e := range es {
		out[i] = s.project(e, v)
	}
	return out
}

// EdgeOut is a relation. Derived edges (Endpoint_Resolution) are marked.
type EdgeOut struct {
	Type    string `json:"type"`
	From    string `json:"from" jsonschema:"identity_fingerprint of the source entity"`
	To      string `json:"to" jsonschema:"identity_fingerprint of the target entity"`
	Dir     string `json:"direction,omitempty"`
	Hops    int    `json:"hops,omitempty"`
	Derived bool   `json:"derived,omitempty" jsonschema:"true for relations computed at read time"`
}

func projectEdge(e engine.EdgeView, v Verbosity) EdgeOut {
	out := EdgeOut{Type: e.Type, From: e.From, To: e.To, Derived: e.Derived}
	if v != Brief {
		out.Dir, out.Hops = e.Direction, e.Hops
	}
	return out
}

func projectEdges(es []engine.EdgeView, v Verbosity) []EdgeOut {
	out := make([]EdgeOut, len(es))
	for i, e := range es {
		out[i] = projectEdge(e, v)
	}
	return out
}

// ChangeOut is one Change_Event.
type ChangeOut struct {
	Kind         string `json:"kind"`
	Subject      string `json:"subject"`
	Entity       string `json:"entity,omitempty"`
	EntityKind   string `json:"entity_kind,omitempty"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	RelationType string `json:"relation_type,omitempty"`
	ObservedAt   string `json:"observed_at"`
	RecordedAt   string `json:"recorded_at,omitempty"`
	Seq          uint64 `json:"seq,omitempty"`
}

func projectChange(c engine.ChangeView, v Verbosity) ChangeOut {
	out := ChangeOut{
		Kind: string(c.Kind), Subject: string(c.Subject), Entity: c.Entity,
		From: c.From, To: c.To, ObservedAt: c.ObservedAt.UTC().Format(time.RFC3339Nano),
	}
	if v == Brief {
		return out
	}
	out.EntityKind, out.RelationType, out.Seq = c.EntityKind, c.RelationType, c.Seq
	if v == Full {
		out.RecordedAt = c.RecordedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

// PageInfo carries the pagination fields of list results.
type PageInfo struct {
	Total      int    `json:"total" jsonschema:"size of the full matching set"`
	Truncated  bool   `json:"truncated" jsonschema:"true when more items follow"`
	NextCursor string `json:"next_cursor,omitempty" jsonschema:"pass as cursor to get the next page"`
}

func pageInfo[T any](p engine.Page[T]) PageInfo {
	return PageInfo{Total: p.Total, Truncated: p.Truncated, NextCursor: p.NextCursor}
}
