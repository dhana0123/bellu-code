// Package lens builds Lens_Slices: bounded, deterministic views of the graph.
// This file holds the pure building blocks. They import no engine, service,
// or net/http.
package lens

import "time"

// Confidence values carried by edges and paths.
const (
	ConfExtracted = "extracted"
	ConfInferred  = "inferred"
)

// Slice is the Lens_Slice shared by the HTTP API and MCP.
type Slice struct {
	Lens        string      `json:"lens"`
	GeneratedAt time.Time   `json:"generated_at"`
	Truncated   bool        `json:"truncated"`
	Counts      Counts      `json:"counts"`
	Nodes       []Node      `json:"nodes"`
	Edges       []SliceEdge `json:"edges"`
	Groups      []Group     `json:"groups"`
	Paths       []Path      `json:"paths,omitempty"`

	// Root is the lens root entity id. Budget keeps it first. Not serialized.
	Root string `json:"-"`
}

// Counts mirror the slice arrays.
type Counts struct {
	Nodes        int `json:"nodes"`
	Edges        int `json:"edges"`
	OmittedNodes int `json:"omitted_nodes"`
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
}

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

// Confidence returns the confidence of a relation type. The type is the only
// carrier: likely_same_as is inferred, every other type is extracted.
func Confidence(relType string) string {
	if relType == "likely_same_as" {
		return ConfInferred
	}
	return ConfExtracted
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
