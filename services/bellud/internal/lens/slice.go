// Package lens builds Lens_Slices: bounded, deterministic views of the graph.
// This file holds the pure building blocks. They import no engine, service,
// or net/http.
package lens

import (
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

// Confidence values carried by edges and paths.
const (
	ConfExtracted = "extracted"
	ConfInferred  = "inferred"
)

// Slice is the Lens_Slice shared by the HTTP API and MCP.
type Slice struct {
	Lens        string    `json:"lens"`
	GeneratedAt time.Time `json:"generated_at"`
	Truncated   bool      `json:"truncated"`
	// Reason is time_limit or entity_limit on a truncated category slice.
	Reason string      `json:"reason,omitempty"`
	Counts Counts      `json:"counts"`
	Nodes  []Node      `json:"nodes"`
	Edges  []SliceEdge `json:"edges"`
	Groups []Group     `json:"groups"`
	Paths  []Path      `json:"paths,omitempty"`
	// MissingData lists the registered-only categories the answer depends on,
	// plus sentinel entries. Never nil.
	MissingData []string `json:"missing_data"`

	// Root is the lens root entity id. Budget keeps it first. Not serialized.
	Root string `json:"-"`
}

// Counts mirror the slice arrays.
type Counts struct {
	Nodes        int `json:"nodes"`
	Edges        int `json:"edges"`
	OmittedNodes int `json:"omitted_nodes"`
	// OmittedRules counts rule nodes that collapsed to nothing because their
	// peer was not in the slice.
	OmittedRules int `json:"omitted_rules"`
}

// Node is one entity in a slice.
type Node struct {
	ID    string            `json:"id"`
	Kind  string            `json:"kind"`
	Label string            `json:"label"`
	Group *string           `json:"group"`
	Hops  int               `json:"hops"`
	Attrs map[string]string `json:"attrs"`
	Risk  *Risk             `json:"risk"`
}

// Risk is present only on vulnerability nodes.
type Risk struct {
	Score     float64 `json:"score"`
	Severity  string  `json:"severity"`
	CVSS      float64 `json:"cvss"`
	EPSS      float64 `json:"epss"`
	KEV       bool    `json:"kev"`
	Reachable *bool   `json:"reachable"`
}

// SliceEdge is one relation between two nodes of the same slice.
type SliceEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
}

// MaxEvidence bounds SliceEdge.Evidence in bytes.
const MaxEvidence = 512

// Group collects node ids under one label.
type Group struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	Members []string `json:"members"`
}

// Path is a chain of node ids with its weakest-hop confidence.
type Path struct {
	Nodes      []string `json:"nodes"`
	Confidence string   `json:"confidence"`
}

// Confidence returns the registered default confidence of a relation type.
// An unregistered type, or a registry that failed to merge, is extracted.
func Confidence(relType string) string {
	r, err := schemaall.Default()
	if err != nil {
		return ConfExtracted
	}
	if d, ok := r.Relation(relType); ok && string(d.Confidence) == ConfInferred {
		return ConfInferred
	}
	return ConfExtracted
}

// EdgeConfidence returns the stored confidence of one relation when it is
// extracted or inferred, and the type default otherwise.
func EdgeConfidence(relType, attr string) string {
	if attr == ConfExtracted || attr == ConfInferred {
		return attr
	}
	return Confidence(relType)
}

// truncUTF8 cuts s to at most n bytes, backing up to a character boundary.
func truncUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// PathConfidence returns inferred when any hop is not extracted, else
// extracted. An empty path is extracted.
func PathConfidence(hops []string) string {
	for _, h := range hops {
		if h != ConfExtracted {
			return ConfInferred
		}
	}
	return ConfExtracted
}

// PathConfidenceOfEdges is PathConfidence over edges.
func PathConfidenceOfEdges(edges []SliceEdge) string {
	for _, e := range edges {
		if e.Confidence != ConfExtracted {
			return ConfInferred
		}
	}
	return ConfExtracted
}

// Prune keeps an edge only when both endpoints are in nodes. Order is kept.
func Prune(nodes []Node, edges []SliceEdge) []SliceEdge {
	in := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		in[n.ID] = struct{}{}
	}
	out := make([]SliceEdge, 0, len(edges))
	for _, e := range edges {
		_, a := in[e.From]
		_, b := in[e.To]
		if a && b {
			out = append(out, e)
		}
	}
	return out
}
