// Package identity serves GET /api/experimental/identity/paths: the shortest
// relation path between two identities or resources (Requirements 11.8, 11.9,
// 20.1). A search over the 5 second budget fails with no partial result.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/lens"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/identity"

const (
	// MaxDepth is the most relations a path may have (11.8).
	MaxDepth = 10
	// Budget bounds one query (11.8, 11.9).
	Budget = 5 * time.Second
	// MaxPage is the most paths one response carries (11.8).
	MaxPage = 500
	maxID   = 512
)

// Reacher answers a reachability query; lens.Reach over a lens.Source satisfies it.
type Reacher func(ctx context.Context, source, target string, opts lens.ReachOpts) (lens.ReachResult, error)

// FromSource adapts a lens.Source to a Reacher.
func FromSource(src lens.Source) Reacher {
	return func(ctx context.Context, from, to string, o lens.ReachOpts) (lens.ReachResult, error) {
		return lens.Reach(ctx, src, from, to, o)
	}
}

type response struct {
	From  string             `json:"from"`
	To    string             `json:"to"`
	Paths []lens.ReachResult `json:"paths"`
}

// Mount registers the route on mux. With no reacher or the flag off it answers 404.
func Mount(mux *http.ServeMux, reach Reacher, enabled bool) {
	route := "GET " + Prefix + "/paths"
	if !enabled || reach == nil {
		mux.HandleFunc(route, func(w http.ResponseWriter, _ *http.Request) {
			write(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": "identity paths are not enabled"})
		})
		return
	}
	mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) { paths(w, r, reach) })
}

func paths(w http.ResponseWriter, r *http.Request, reach Reacher) {
	q := r.URL.Query()
	from, to := q.Get("from"), q.Get("to")
	for name, v := range map[string]string{"from": from, "to": to} {
		if v == "" || len(v) > maxID {
			invalid(w, name, "must be 1 to 512 characters")
			return
		}
	}
	hops := MaxDepth
	if s := q.Get("max_hops"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxDepth {
			invalid(w, "max_hops", "must be an integer from 1 to 10")
			return
		}
		hops = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), Budget)
	defer cancel()
	res, err := reach(ctx, from, to, lens.ReachOpts{MaxHops: hops, IncludeInferred: true})
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (err == nil && ctx.Err() != nil):
		write(w, http.StatusGatewayTimeout, map[string]string{"_tag": "QueryBudgetExceeded", "message": "query budget exceeded"})
	case errors.Is(err, lens.ErrReachEntity):
		write(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": err.Error()})
	case err != nil:
		write(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
	default:
		out := response{From: from, To: to, Paths: []lens.ReachResult{}}
		if !res.Unreachable && len(res.Path) > 0 {
			out.Paths = append(out.Paths, res)
		}
		write(w, http.StatusOK, out)
	}
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func invalid(w http.ResponseWriter, field, msg string) {
	write(w, http.StatusBadRequest, map[string]string{"_tag": "InvalidRequest", "param": field, "message": msg})
}
