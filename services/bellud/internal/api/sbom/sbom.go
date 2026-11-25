// Package sbom serves the experimental SBOM API under /api/experimental/sbom:
// list, get and export (Requirements 5.9, 5.13, 20.1). Authentication is
// applied by the front door through the route table.
package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/sbom"

const (
	defaultLimit = 100
	maxLimit     = 1000
	maxIDLen     = 512
)

// Handler serves the SBOM routes from a store.
type Handler struct{ Store *sbomstore.Store }

// New returns a handler serving the three routes. See Mount.
func New(store *sbomstore.Store, enabled bool) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, store, enabled)
	return mux
}

// Mount registers the SBOM routes on mux. When the security_scanners flag is
// off (enabled false) or there is no store, the routes answer 404.
func Mount(mux *http.ServeMux, store *sbomstore.Store, enabled bool) {
	list, get, exp := "GET "+Prefix, "GET "+Prefix+"/{assetId}", "GET "+Prefix+"/{assetId}/export"
	if !enabled || store == nil {
		for _, p := range []string{list, get, exp} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { NotFound(w, "sbom is not enabled") })
		}
		return
	}
	h := &Handler{Store: store}
	mux.HandleFunc(list, h.List)
	mux.HandleFunc(get, h.Get)
	mux.HandleFunc(exp, h.Export)
}

type wireSummary struct {
	AssetID      string         `json:"assetId"`
	Digest       string         `json:"digest"`
	PackageCount int            `json:"packageCount"`
	CreatedAt    string         `json:"createdAt"`
	Ecosystems   map[string]int `json:"ecosystems"`
	Licenses     map[string]int `json:"licenses"`
}

type wirePackage struct {
	Type       string            `json:"type,omitempty"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Purl       string            `json:"purl,omitempty"`
	Ecosystem  string            `json:"ecosystem,omitempty"`
	Licenses   []string          `json:"licenses"`
	Supplier   string            `json:"supplier,omitempty"`
	Locations  []string          `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
}

type wireDetail struct {
	wireSummary
	Subject    string        `json:"subject,omitempty"`
	Items      []wirePackage `json:"items"`
	NextCursor string        `json:"nextCursor,omitempty"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// List answers GET /sbom with one summary per asset.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	sums, err := h.Store.List(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	items := make([]wireSummary, 0, len(sums))
	for _, s := range sums {
		items = append(items, toSummary(s.Meta, s.Ecosystems, s.Licenses))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func toSummary(m sbomstore.Meta, eco, lic map[string]int) wireSummary {
	return wireSummary{AssetID: m.AssetID, Digest: m.Digest, PackageCount: m.PackageCount,
		CreatedAt: m.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z07:00"), Ecosystems: eco, Licenses: lic}
}

// Get answers GET /sbom/{assetId}: the summary and one page of packages.
// limit (default 100, at most 1000) and cursor (an offset from nextCursor) page.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := assetID(w, r)
	if !ok {
		return
	}
	limit, offset, ok := paging(w, r.URL.Query())
	if !ok {
		return
	}
	d := wireDetail{wireSummary: wireSummary{AssetID: id, Ecosystems: map[string]int{}, Licenses: map[string]int{}}, Items: []wirePackage{}}
	n := 0
	m, found, err := h.Store.Each(r.Context(), id, func(s string) { d.Subject = s }, func(p bom.Package) error {
		d.Ecosystems[orUnknown(p.Ecosystem)]++
		if len(p.Licenses) == 0 {
			d.Licenses[sbomstore.UnknownLicense]++
		}
		for _, l := range p.Licenses {
			d.Licenses[orUnknown(l)]++
		}
		if n >= offset && n < offset+limit {
			d.Items = append(d.Items, wirePackage{Type: p.Type, Name: p.Name, Version: str(p.Version), Purl: str(p.Purl),
				Ecosystem: p.Ecosystem, Licenses: nz(p.Licenses), Supplier: str(p.Supplier), Locations: nz(p.Locations), Properties: p.Properties})
		}
		n++
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	if !found {
		NotFound(w, "no SBOM for asset "+id)
		return
	}
	d.wireSummary = toSummary(m, d.Ecosystems, d.Licenses)
	if offset+limit < n {
		d.NextCursor = strconv.Itoa(offset + limit)
	}
	writeJSON(w, http.StatusOK, d)
}

func orUnknown(s string) string {
	if s == "" {
		return sbomstore.UnknownLicense // "unknown" for both buckets
	}
	return s
}

func paging(w http.ResponseWriter, q url.Values) (limit, offset int, ok bool) {
	limit = defaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLimit {
			invalid(w, "limit", "limit must be an integer from 1 to "+strconv.Itoa(maxLimit))
			return 0, 0, false
		}
		limit = n
	}
	if v := q.Get("cursor"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			invalid(w, "cursor", "cursor is not valid")
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

func assetID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("assetId")
	if id == "" || len(id) > maxIDLen {
		NotFound(w, "unknown asset")
		return "", false
	}
	return id, true
}

// Export answers GET /sbom/{assetId}/export?format=&version=. Format is
// cyclonedx or spdx (or the full bom format name). Everything is validated
// before the first byte is written.
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	id, ok := assetID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	opts := bom.Options{Format: bom.Format(q.Get("format")), Version: q.Get("version")}
	switch strings.ToLower(string(opts.Format)) {
	case "cyclonedx":
		opts.Format = bom.FormatCycloneDXJSON
	case "spdx":
		opts.Format = bom.FormatSPDXJSON
	}
	// Validate format and version against an empty document; Write checks them first.
	if err := bom.Write(r.Context(), io.Discard, bom.SBOM{}, opts); err != nil {
		fail(w, err)
		return
	}
	sb, _, found, err := h.Store.Latest(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	if !found {
		NotFound(w, "no SBOM for asset "+id)
		return
	}
	ext := ".cdx.json"
	if opts.Format == bom.FormatSPDXJSON {
		ext = ".spdx.json"
	}
	lw := &lazyWriter{w: w, header: func(h http.Header) {
		h.Set("Content-Type", "application/json")
		h.Set("Content-Disposition", `attachment; filename="`+filename(id)+ext+`"`)
	}}
	if err := bom.Write(r.Context(), lw, sb, opts); err != nil && !lw.started {
		fail(w, err) // nothing written yet
	}
}

// lazyWriter sets headers on the first byte, so a failure before any output
// can still answer with a JSON error.
type lazyWriter struct {
	w       http.ResponseWriter
	header  func(http.Header)
	started bool
}

func (l *lazyWriter) Write(p []byte) (int, error) {
	if !l.started {
		l.started = true
		l.header(l.w.Header())
	}
	return l.w.Write(p)
}

func filename(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, id)
}

// ---- errors ----

// NotFound writes the 404 error body.
func NotFound(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": msg})
}

func invalid(w http.ResponseWriter, field, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"_tag": "InvalidRequestError", "message": msg,
		"kind": "validation", "code": "invalid_request", "field": field})
}

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, bom.ErrUnsupportedFormat):
		invalid(w, "format", err.Error())
	case errors.Is(err, bom.ErrUnsupportedVersion):
		invalid(w, "version", err.Error())
	case errors.Is(err, bom.ErrInvalidPackage):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"_tag": "InvalidRequestError", "message": err.Error(), "kind": "validation", "code": "invalid_package"})
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
