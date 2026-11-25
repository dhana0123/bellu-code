// Package data serves the experimental data store API under
// /api/experimental/data: GET /data/stores and GET /data/stores/{id}
// (Requirements 13.5, 20.1). Authentication is applied by the front door
// through the route table. Classifications are read through Reader, so this
// package does not touch the database.
package data

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/dataclass"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/data"

const maxIDLen = 256

// storeTypes are the aws_resource types that are data stores.
var storeTypes = []string{"s3:bucket", "rds:instance", "rds:cluster", "dynamodb:table"}

// Spec is the list query contract of GET /data/stores: paging only.
var Spec = listquery.Spec{}

// Reader reads stored classifications. *dataclass.Results implements it.
type Reader interface {
	Get(ctx context.Context, entityID string) (dataclass.Row, bool, error)
	List(ctx context.Context, entityIDs []string) (map[string]dataclass.Row, error)
}

// FindingLister lists findings. *findings.Store implements it.
type FindingLister interface {
	List(ctx context.Context, q findings.ListQuery) (findings.Page[findings.Finding], error)
}

// Deps are the handler dependencies. Findings may be nil; counts are then zero.
type Deps struct {
	Graph    graph.Query
	Classes  Reader
	Findings FindingLister
}

type handler struct{ d Deps }

// New returns a handler serving the two routes. See Mount.
func New(d Deps, enabled bool) http.Handler {
	mux := http.NewServeMux()
	Mount(mux, d, enabled)
	return mux
}

// Mount registers the data routes on mux. When the security_posture flag is
// off (enabled false) or there is no graph, the routes answer 404.
func Mount(mux *http.ServeMux, d Deps, enabled bool) {
	list, get := "GET "+Prefix+"/stores", "GET "+Prefix+"/stores/{id}"
	if !enabled || d.Graph == nil || d.Classes == nil {
		for _, p := range []string{list, get} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { notFound(w, "data stores are not enabled") })
		}
		return
	}
	h := &handler{d: d}
	mux.HandleFunc(list, h.list)
	mux.HandleFunc(get, h.get)
}

type wireStore struct {
	ID                  string         `json:"id"`
	Type                string         `json:"type"`
	Name                string         `json:"name"`
	Region              string         `json:"region,omitempty"`
	EncryptionAtRest    any            `json:"encryptionAtRest"`
	EncryptionInTransit any            `json:"encryptionInTransit"`
	PublicAccess        any            `json:"publicAccess"`
	Backup              any            `json:"backup"`
	Logging             any            `json:"logging"`
	Classes             []string       `json:"classes"`
	MatchCounts         map[string]int `json:"matchCounts"`
	OpenExposures       int            `json:"openExposureCount"`
}

func isStoreType(t string) bool {
	for _, s := range storeTypes {
		if s == t {
			return true
		}
	}
	return false
}

func (h *handler) toWire(ctx context.Context, e graph.Entity, rt string, row *dataclass.Row) (wireStore, error) {
	w := wireStore{ID: string(e.ID), Type: rt, Name: e.Label,
		EncryptionAtRest: e.Attributes["encryption_at_rest"], EncryptionInTransit: e.Attributes["encryption_in_transit"],
		PublicAccess: e.Attributes["public_access"], Backup: e.Attributes["backup"], Logging: e.Attributes["logging"],
		Classes: []string{}, MatchCounts: map[string]int{}}
	if n, _ := e.Attributes["name"].(string); n != "" {
		w.Name = n
	}
	w.Region, _ = e.Attributes["region"].(string)
	if row != nil {
		if row.Classes != nil {
			w.Classes = row.Classes
		}
		if row.MatchCounts != nil {
			w.MatchCounts = row.MatchCounts
		}
	}
	if h.d.Findings != nil {
		pg, err := h.d.Findings.List(ctx, findings.ListQuery{
			AssetIDs: []string{w.ID}, Types: []findings.Type{findings.TypeDataExposure},
			Statuses: []findings.Status{findings.StatusOpen}, Limit: 1000})
		if err != nil {
			return w, err
		}
		w.OpenExposures = len(pg.Items)
	}
	return w, nil
}

func resourceType(e graph.Entity) string {
	if e.Type != "aws_resource" {
		return ""
	}
	rt, _ := e.Attributes["resource_type"].(string)
	if !isStoreType(rt) {
		return ""
	}
	return rt
}

// position is "<type index>:<graph cursor>".
func parsePosition(p string) (int, string, bool) {
	if p == "" {
		return 0, "", true
	}
	idx, cur, ok := strings.Cut(p, ":")
	n, err := strconv.Atoi(idx)
	if !ok || err != nil || n < 0 || n >= len(storeTypes) {
		return 0, "", false
	}
	return n, cur, true
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	q, err := Spec.Parse(r.URL.Query())
	if listquery.WriteIfInvalid(w, err) {
		return
	}
	idx, cursor, ok := parsePosition(q.Position)
	if !ok {
		invalid(w, "cursor", "malformed cursor")
		return
	}
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	out := listquery.Page[wireStore]{Items: []wireStore{}}
	err = func() error {
		var ents []graph.Entity
		var types []string
		for idx < len(storeTypes) && len(ents) < q.Limit {
			pg, err := h.d.Graph.Find(ctx, graph.FindQuery{
				Type:       "aws_resource",
				Attributes: map[string]string{"resource_type": storeTypes[idx]},
				Paging:     graph.Paging{PageSize: q.Limit - len(ents), Cursor: cursor},
			})
			if err != nil {
				return err
			}
			for _, e := range pg.Items {
				ents = append(ents, e)
				types = append(types, storeTypes[idx])
			}
			if pg.NextCursor != "" {
				cursor = pg.NextCursor
			} else {
				idx, cursor = idx+1, ""
			}
		}
		ids := make([]string, len(ents))
		for i, e := range ents {
			ids[i] = string(e.ID)
		}
		rows, err := h.d.Classes.List(ctx, ids)
		if err != nil {
			return err
		}
		for i, e := range ents {
			var rp *dataclass.Row
			if row, ok := rows[ids[i]]; ok {
				rp = &row
			}
			ws, err := h.toWire(ctx, e, types[i], rp)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, ws)
		}
		if idx < len(storeTypes) {
			out.NextCursor = q.NextCursor(strconv.Itoa(idx) + ":" + cursor)
		}
		return nil
	}()
	switch {
	case err != nil && listquery.Truncated(ctx, err):
		out.Truncated = true
		out.NextCursor = ""
	case err != nil:
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > maxIDLen {
		invalid(w, "id", "must be 1 to 256 characters")
		return
	}
	e, err := h.d.Graph.Entity(r.Context(), graph.EntityID(id), nil)
	if err != nil {
		fail(w, err)
		return
	}
	rt := resourceType(e)
	if rt == "" {
		notFound(w, "data store not found")
		return
	}
	var rp *dataclass.Row
	if row, ok, err := h.d.Classes.Get(r.Context(), id); err != nil {
		fail(w, err)
		return
	} else if ok {
		rp = &row
	}
	ws, err := h.toWire(r.Context(), e, rt, rp)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func invalid(w http.ResponseWriter, field, msg string) {
	listquery.WriteError(w, &listquery.Error{Param: field, Msg: msg})
}

func notFound(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": msg})
}

func fail(w http.ResponseWriter, err error) {
	if errors.Is(err, graph.ErrNotFound) {
		notFound(w, "data store not found")
		return
	}
	if errors.Is(err, graph.ErrValidation) {
		invalid(w, "id", "invalid id")
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
}
