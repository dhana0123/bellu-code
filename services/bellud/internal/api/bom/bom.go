// Package bom serves the experimental BOM group under /api/experimental/bom.
// This task covers the SBOM part only (Requirements 5.9, 20.1); the AI-BOM and
// Cloud-BOM routes are added later. The SBOM routes share the handlers of
// internal/api/sbom.
package bom

import (
	"net/http"

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
