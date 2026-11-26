// Package ai serves the experimental AI API under /api/experimental/ai:
// GET /ai/entities and GET /ai/summary (Requirements 6.8, 20.1). The entities
// are the AI inventory kinds of the graph (aischema). Authentication is
// applied by the front door through the route table.
package ai

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bellu/bellucode/services/bellud/internal/api/listquery"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/ai"

// Kinds lists the AI entity kinds in a stable order.
var Kinds = []string{
	aischema.KindModel, aischema.KindAgent, aischema.KindTool,
	aischema.KindMCPServer, aischema.KindVectorStore, aischema.KindService,
}

// Spec is the list query contract of GET /ai/entities: paging and a kind filter.
var Spec = listquery.Spec{Filters: []string{"kind"}}

const countPage = 500

// Mount registers the AI routes on mux. When the security_ai flag is off
// (enabled false) or there is no graph, the routes answer 404.
func Mount(mux *http.ServeMux, q graph.Query, enabled bool) {
	list, sum := "GET "+Prefix+"/entities", "GET "+Prefix+"/summary"
	if !enabled || q == nil {
		for _, p := range []string{list, sum} {
			mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": "ai is not enabled"})
			})
		}
		return
	}
	h := &handler{q: q}
	mux.HandleFunc(list, h.entities)
	mux.HandleFunc(sum, h.summary)
}

type handler struct{ q graph.Query }

type wireEntity struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes"`
}

// Summary is the body of GET /ai/summary.
type Summary struct {
	Total  int            `json:"total"`
	Counts map[string]int `json:"counts"`
}

func kindIndex(k string) int {
	for i, s := range Kinds {
		if s == k {
			return i
		}
	}
	return -1
}

// position is "<kind index>:<graph cursor>".
func parsePosition(p string) (int, string, bool) {
	if p == "" {
		return 0, "", true
	}
	idx, cur, ok := cut(p)
	n, err := strconv.Atoi(idx)
	if !ok || err != nil || n < 0 || n >= len(Kinds) {
		return 0, "", false
	}
	return n, cur, true
}

func cut(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func (h *handler) entities(w http.ResponseWriter, r *http.Request) {
	q, err := Spec.Parse(r.URL.Query())
	if listquery.WriteIfInvalid(w, err) {
		return
	}
	kinds := Kinds
	only := -1
	if v := r.URL.Query().Get("kind"); v != "" {
		if only = kindIndex(v); only < 0 {
			listquery.WriteError(w, &listquery.Error{Param: "kind", Msg: "unknown AI kind"})
			return
		}
		kinds = Kinds[only : only+1]
	}
	idx, cursor, ok := parsePosition(q.Position)
	if !ok || (only >= 0 && idx > 0) {
		listquery.WriteError(w, &listquery.Error{Param: "cursor", Msg: "malformed cursor"})
		return
	}
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	out := listquery.Page[wireEntity]{Items: []wireEntity{}}
	err = func() error {
		for idx < len(kinds) && len(out.Items) < q.Limit {
			pg, err := h.q.Find(ctx, graph.FindQuery{
				Type:   kinds[idx],
				Paging: graph.Paging{PageSize: q.Limit - len(out.Items), Cursor: cursor},
			})
			if err != nil {
				return err
			}
			for _, e := range pg.Items {
				out.Items = append(out.Items, wireEntity{ID: string(e.ID), Kind: e.Type, Name: e.Label, Attributes: e.Attributes})
			}
			if pg.NextCursor != "" {
				cursor = pg.NextCursor
			} else {
				idx, cursor = idx+1, ""
			}
		}
		if idx < len(kinds) {
			out.NextCursor = q.NextCursor(strconv.Itoa(idx) + ":" + cursor)
		}
		return nil
	}()
	switch {
	case err != nil && listquery.Truncated(ctx, err):
		out.Truncated = true
		out.NextCursor = ""
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) summary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := listquery.Budget(r.Context())
	defer cancel()
	s := Summary{Counts: map[string]int{}}
	for _, k := range Kinds {
		n := 0
		cursor := ""
		for {
			pg, err := h.q.Find(ctx, graph.FindQuery{Type: k, Paging: graph.Paging{PageSize: countPage, Cursor: cursor}})
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
				return
			}
			n += len(pg.Items)
			if pg.NextCursor == "" {
				break
			}
			cursor = pg.NextCursor
		}
		s.Counts[k] = n
		s.Total += n
	}
	writeJSON(w, http.StatusOK, s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
