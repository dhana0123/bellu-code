// Package bom serves the experimental BOM group under /api/experimental/bom.
// It serves the SBOM routes (Requirements 5.9, 20.1) and the AI-BOM and
// Cloud-BOM routes (Requirements 6.8, 6.9, 16.10). The SBOM routes share the handlers of
// internal/api/sbom.
package bom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/bom"

	"github.com/bellu/bellucode/services/bellud/internal/api/sbom"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/bom"

// Mount registers GET /bom/sbom (per-asset list) and
// GET /bom/sbom/{assetId}/export on mux. A disabled flag or missing store
// answers 404.
func Mount(mux *http.ServeMux, store *sbomstore.Store, enabled bool) {
	list, exp := "GET "+Prefix+"/sbom", "GET "+Prefix+"/sbom/{assetId}/export"
	if !enabled || store == nil {
		for _, p := range []string{list, exp} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { sbom.NotFound(w, "bom is not enabled") })
		}
		return
	}
	h := &sbom.Handler{Store: store}
	mux.HandleFunc(list, h.List)
	mux.HandleFunc(exp, h.Export)
}

// Docs builds the AI-BOM and Cloud-BOM on demand.
type Docs interface {
	AI(ctx context.Context) (bom.Document, error)
	Cloud(ctx context.Context) (bom.Document, error)
}

type wireComponent struct {
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Licenses   []string          `json:"licenses,omitempty"`
	Locations  []string          `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type wireGap struct {
	Provider string `json:"provider"`
	Cause    string `json:"cause"`
}

type wireDoc struct {
	Kind       string          `json:"kind"`
	Components []wireComponent `json:"components"`
	Incomplete []wireGap       `json:"incomplete"`
	Findings   []bom.Finding   `json:"findings"`
}

// MountDocs registers GET /bom/ai, /bom/cloud, /bom/ai/export and
// /bom/cloud/export. A disabled flag or missing source answers 404. The
// security_ai flag guards the AI routes and security_scanners the Cloud routes.
func MountDocs(mux *http.ServeMux, d Docs, aiEnabled, cloudEnabled bool) {
	for _, k := range []struct {
		name    string
		enabled bool
		build   func(context.Context) (bom.Document, error)
	}{
		{"ai", aiEnabled, func(c context.Context) (bom.Document, error) { return d.AI(c) }},
		{"cloud", cloudEnabled, func(c context.Context) (bom.Document, error) { return d.Cloud(c) }},
	} {
		list, exp := "GET "+Prefix+"/"+k.name, "GET "+Prefix+"/"+k.name+"/export"
		if !k.enabled || d == nil {
			for _, p := range []string{list, exp} {
				mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { sbom.NotFound(w, k.name+" bom is not enabled") })
			}
			continue
		}
		build, name := k.build, k.name
		mux.HandleFunc(list, func(w http.ResponseWriter, r *http.Request) {
			doc, err := build(r.Context())
			if err != nil {
				writeErr(w, err)
				return
			}
			out := wireDoc{Kind: string(doc.Kind), Components: []wireComponent{}, Incomplete: []wireGap{}, Findings: doc.Findings}
			if out.Findings == nil {
				out.Findings = []bom.Finding{}
			}
			for _, p := range doc.SBOM.Packages {
				c := wireComponent{Type: p.Type, Name: p.Name, Licenses: p.Licenses, Locations: p.Locations, Properties: p.Properties}
				if p.Version != nil {
					c.Version = *p.Version
				}
				out.Components = append(out.Components, c)
			}
			for _, g := range doc.Incomplete {
				out.Incomplete = append(out.Incomplete, wireGap{Provider: g.Provider, Cause: g.Cause})
			}
			writeJSON(w, http.StatusOK, out)
		})
		mux.HandleFunc(exp, func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			opts := bom.Options{Format: bom.Format(q.Get("format")), Version: q.Get("version")}
			switch strings.ToLower(string(opts.Format)) {
			case "cyclonedx":
				opts.Format = bom.FormatCycloneDXJSON
			case "spdx":
				opts.Format = bom.FormatSPDXJSON
			}
			if err := bom.Write(r.Context(), io.Discard, bom.SBOM{}, opts); err != nil {
				writeErr(w, err)
				return
			}
			doc, err := build(r.Context())
			if err != nil {
				writeErr(w, err)
				return
			}
			ext := ".cdx.json"
			if opts.Format == bom.FormatSPDXJSON {
				ext = ".spdx.json"
			}
			var buf strings.Builder
			if err := bom.Write(r.Context(), &buf, doc.SBOM, opts); err != nil {
				writeErr(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", `attachment; filename="`+name+"-bom"+ext+`"`)
			_, _ = io.WriteString(w, buf.String())
		})
	}
}

func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, bom.ErrUnsupportedFormat):
		writeJSON(w, http.StatusBadRequest, map[string]string{"_tag": "InvalidRequestError", "message": err.Error(), "kind": "validation", "code": "invalid_request", "field": "format"})
	case errors.Is(err, bom.ErrUnsupportedVersion):
		writeJSON(w, http.StatusBadRequest, map[string]string{"_tag": "InvalidRequestError", "message": err.Error(), "kind": "validation", "code": "invalid_request", "field": "version"})
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"_tag": "UnavailableError", "message": "request canceled"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "InternalError", "message": "internal error"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
