// Package debugui serves the read-only, server-rendered debug page. It uses
// no JavaScript and no external resources; every value goes through
// html/template.
package debugui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static/style.css
var styleCSS []byte

const (
	historyLimit = 100
	findLimit    = 100
	neighborMax  = 200
	csp          = "default-src 'none'; style-src 'self'"
)

var page = template.Must(template.ParseFS(tmplFS, "templates/*.html"))

// Handler is the debug UI http.Handler.
type Handler struct {
	core *engine.Core
	base string
}

// New returns a Handler. base is the mount prefix under which the routes
// live: the page is served at base+"/debug" and the stylesheet at
// base+"/debug/style.css" (e.g. base "/api/experimental/graph").
func New(core *engine.Core, base string) *Handler {
	return &Handler{core: core, base: strings.TrimRight(base, "/")}
}

type kv struct{ K, V string }

type findRow struct {
	ID, Kind, Label, Link string
}

type findView struct {
	Total int
	Rows  []findRow
}

type nbRow struct {
	Type, Dir, From, To, FromLink, ToLink string
	Evidence, Confidence, ObservedAt      string
	Hops                                  int
	Derived                               bool
}

type histRow struct {
	Seq                uint64
	Kind, Subject      string
	Detail             string
	Observed, Recorded string
}

type entityVM struct {
	ID, Kind, Label, Local string
	Observed, Recorded     string
	Attrs, Annots          []kv
	Neighbors              []nbRow
	NTotal                 int
	History                []histRow
	NextHistory            string
}

type pageVM struct {
	Base, Ref, AsOf, Kind, Q string
	Depth                    int
	Error                    string
	Found                    *findView
	Entity                   *entityVM
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", csp)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		hd.Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case h.base + "/debug":
		h.servePage(w, r)
	case h.base + "/debug/style.css":
		hd.Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(styleCSS)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) servePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	vm := pageVM{Base: h.base, Ref: q.Get("ref"), AsOf: q.Get("as_of"), Kind: q.Get("kind"), Q: q.Get("q"), Depth: 1}
	status := http.StatusOK
	fail := func(code int, err error) {
		status = code
		vm.Error = err.Error()
	}
	if d := q.Get("depth"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 3 {
			fail(http.StatusBadRequest, errors.New("depth must be 1 to 3"))
			n = 1
		}
		vm.Depth = n
	}
	var at *time.Time
	if vm.AsOf != "" && status == http.StatusOK {
		t, err := time.Parse(time.RFC3339Nano, vm.AsOf)
		if err != nil {
			fail(http.StatusBadRequest, errors.New("as_of must be an RFC 3339 instant"))
		} else {
			at = &t
		}
	}
	if status == http.StatusOK {
		switch {
		case vm.Ref != "":
			if err := h.entityPage(r.Context(), &vm, at, q.Get("hp")); err != nil {
				fail(statusFor(err), err)
			}
		case q.Has("kind") || q.Has("q"):
			if err := h.findPage(r.Context(), &vm, at); err != nil {
				fail(statusFor(err), err)
			}
		}
	}
	var buf bytes.Buffer
	if err := page.ExecuteTemplate(&buf, "page.html", vm); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, errs.NotFound):
		return http.StatusNotFound
	case errors.Is(err, errs.Validation):
		return http.StatusBadRequest
	case errors.Is(err, errs.Unavailable):
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

func (h *Handler) link(id string) string {
	return h.base + "/debug?ref=" + url.QueryEscape(id)
}

func (h *Handler) findPage(ctx context.Context, vm *pageVM, at *time.Time) error {
	fq := engine.FindQuery{Kind: vm.Kind, Paging: engine.Paging{PageSize: findLimit}}
	if vm.Q != "" {
		fq.Attributes = map[string]string{}
		for _, part := range strings.Fields(vm.Q) {
			k, v, ok := strings.Cut(part, "=")
			if !ok || k == "" {
				return fmt.Errorf("%w: q must be key=value pairs", errs.Validation)
			}
			fq.Attributes[k] = v
		}
	}
	p, err := h.core.Find(ctx, fq, at)
	if err != nil {
		return err
	}
	fv := &findView{Total: p.Total}
	for _, e := range p.Items {
		fv.Rows = append(fv.Rows, findRow{ID: e.ID, Kind: e.Kind, Label: e.Label, Link: h.link(h.core.LocalID(e.ID))})
	}
	vm.Found = fv
	return nil
}

func (h *Handler) entityPage(ctx context.Context, vm *pageVM, at *time.Time, hp string) error {
	id, err := h.core.Resolve(vm.Ref)
	if err != nil {
		return err
	}
	ev, err := h.core.Entity(ctx, id, at)
	if err != nil {
		return err
	}
	e := &entityVM{
		ID: ev.ID, Kind: ev.Kind, Label: ev.Label, Local: h.core.LocalID(ev.ID),
		Observed: fmtTime(ev.ObservedAt), Recorded: fmtTime(ev.RecordedAt),
		Attrs: sortedAttrs(ev.Attributes), Annots: sortedStrs(ev.Annotations),
	}
	np, err := h.core.Neighbors(ctx, id, engine.NeighborOpts{Depth: vm.Depth, Paging: engine.Paging{PageSize: neighborMax}}, at)
	if err != nil {
		return err
	}
	e.NTotal = np.Total
	for _, n := range np.Items {
		e.Neighbors = append(e.Neighbors, nbRow{
			Type: n.Type, Dir: n.Direction, Hops: n.Hops, Derived: n.Derived,
			Evidence: n.Evidence, Confidence: n.Confidence, ObservedAt: n.ObservedAt,
			From: n.From, To: n.To, FromLink: h.link(h.core.LocalID(n.From)), ToLink: h.link(h.core.LocalID(n.To)),
		})
	}
	items, next, err := h.history(ctx, id, hp)
	if err != nil {
		return err
	}
	for _, c := range items {
		var d string
		if c.Subject == engine.SubjectRelation {
			d = c.RelationType + " " + c.From + " -> " + c.To
		} else {
			d = c.EntityKind + " " + c.Entity
		}
		e.History = append(e.History, histRow{
			Seq: c.Seq, Kind: string(c.Kind), Subject: string(c.Subject), Detail: d,
			Observed: fmtTime(c.ObservedAt), Recorded: fmtTime(c.RecordedAt),
		})
	}
	if next != "" {
		e.NextHistory = h.link(vm.Ref) + "&hp=" + url.QueryEscape(next)
		if vm.AsOf != "" {
			e.NextHistory += "&as_of=" + url.QueryEscape(vm.AsOf)
		}
	}
	vm.Entity = e
	return nil
}

// history returns up to historyLimit changes. Without a cursor it returns the
// latest ones (the log is oldest first, so earlier pages are skipped); with a
// cursor it returns the page that follows it, plus the cursor for the next.
func (h *Handler) history(ctx context.Context, id engine.EntityID, hp string) ([]engine.ChangeView, string, error) {
	if hp != "" {
		p, err := h.core.History(ctx, id, engine.TimeRange{}, engine.Paging{PageSize: historyLimit, Cursor: hp})
		if err != nil {
			return nil, "", err
		}
		if !p.Truncated {
			return p.Items, "", nil
		}
		return p.Items, p.NextCursor, nil
	}
	var tail []engine.ChangeView
	cur := ""
	for {
		p, err := h.core.History(ctx, id, engine.TimeRange{}, engine.Paging{PageSize: engine.MaxPageSize, Cursor: cur})
		if err != nil {
			return nil, "", err
		}
		tail = append(tail, p.Items...)
		if len(tail) > historyLimit {
			tail = tail[len(tail)-historyLimit:]
		}
		if !p.Truncated || p.NextCursor == "" {
			return tail, "", nil
		}
		cur = p.NextCursor
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func sortedStrs(m map[string]string) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].K < out[j].K })
	return out
}

func sortedAttrs(m map[string]any) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		var s string
		switch x := v.(type) {
		case string:
			s = x
		default:
			if b, err := json.Marshal(x); err == nil {
				s = string(b)
			} else {
				s = fmt.Sprint(x)
			}
		}
		out = append(out, kv{k, s})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].K < out[j].K })
	return out
}
