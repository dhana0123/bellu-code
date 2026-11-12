package gql

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/mcpserver"
)

type eqEdge struct {
	Type, From, To, Dir string
	Hops                int
	Derived             bool
}

type eqChange struct {
	Seq                           uint64
	Kind, Subject, Entity         string
	From, To, RelationType, Kind2 string
}

type eqEnt struct{ ID, Kind, Label string }

func eqCallMCP(rt *rapid.T, cs *mcp.ClientSession, name string, args map[string]any, out any) {
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || res.IsError {
		rt.Fatalf("%s: %v %v", name, err, res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, out); err != nil {
		rt.Fatal(err)
	}
}

func eqCallGQL(rt *rapid.T, url, q string, vars map[string]any, out any) {
	body, _ := json.Marshal(map[string]any{"query": q, "variables": vars})
	res, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		rt.Fatal(err)
	}
	defer res.Body.Close()
	var r struct {
		Data   json.RawMessage `json:"data"`
		Errors []any           `json:"errors"`
	}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		rt.Fatal(err)
	}
	if len(r.Errors) > 0 {
		rt.Fatalf("graphql: %v", r.Errors)
	}
	if err := json.Unmarshal(r.Data, out); err != nil {
		rt.Fatal(err)
	}
}

// Feature: bellu-graph-native, Property 30: API equivalence
// **Validates: Requirements 7.3, 16.6**
func TestPropertyAPIEquivalence(t *testing.T) {
	ctx := context.Background()
	rapid.Check(t, func(rt *rapid.T) {
		dir, err := os.MkdirTemp("", "apieq")
		if err != nil {
			rt.Fatal(err)
		}
		defer os.RemoveAll(dir)
		now := gen.Epoch.Add(24 * time.Hour)
		core, err := engine.Open(dir, engine.Options{Clock: func() time.Time { return now }})
		if err != nil {
			rt.Fatal(err)
		}
		defer core.Close(ctx)

		allow := func(context.Context) string { return "read" }
		srv, err := mcpserver.New(mcpserver.Config{Core: core, CallerRole: allow,
			Annotate: func(context.Context, string, map[string]string, []string) error { return nil }})
		if err != nil {
			rt.Fatal(err)
		}
		ct, st := mcp.NewInMemoryTransports()
		if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
			rt.Fatal(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "eq"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			rt.Fatal(err)
		}
		defer cs.Close()
		hs := httptest.NewServer(New(Options{Core: core, CallerRole: allow}))
		defer hs.Close()

		for _, s := range (gen.Options{}).Schedule(1, 6).Draw(rt, "schedule") {
			now = s.Now
			// Rejected batches are fine; the graph is whatever got accepted.
			_, _ = core.Apply(ctx, s.Batch, engine.Mode(s.Mode))
		}

		kinds := append([]string{""}, gen.DefaultUniverse().Kinds...)
		kind := rapid.SampledFrom(kinds).Draw(rt, "kind")
		page := engine.MaxPageSize

		// find / find_entities
		want, err := core.Find(ctx, engine.FindQuery{Kind: kind, Paging: engine.Paging{PageSize: page}}, nil)
		if err != nil {
			rt.Fatal(err)
		}
		var wantEnts []eqEnt
		for _, e := range want.Items {
			wantEnts = append(wantEnts, eqEnt{e.ID, e.Kind, e.Label})
		}
		var mf struct {
			Items []struct {
				IdentityFingerprint string `json:"identity_fingerprint"`
				Kind, Label         string
			} `json:"items"`
			Total int `json:"total"`
		}
		args := map[string]any{"verbosity": "full", "page_size": page}
		if kind != "" {
			args["kind"] = kind
		}
		eqCallMCP(rt, cs, "find_entities", args, &mf)
		var gf struct {
			Find struct {
				Items []struct{ ID, Kind, Label string }
				Total int
			}
		}
		eqCallGQL(rt, hs.URL, `query($k: String, $n: Int){ find(kind: $k, first: $n){ total items{ id kind label } } }`,
			map[string]any{"k": nilIfEmpty(kind), "n": page}, &gf)
		var mcpEnts, gqlEnts []eqEnt
		for _, e := range mf.Items {
			mcpEnts = append(mcpEnts, eqEnt{e.IdentityFingerprint, e.Kind, e.Label})
		}
		for _, e := range gf.Find.Items {
			gqlEnts = append(gqlEnts, eqEnt{e.ID, e.Kind, e.Label})
		}
		if !reflect.DeepEqual(wantEnts, mcpEnts) || mf.Total != want.Total {
			rt.Fatalf("find_entities differs:\nwant %v (%d)\ngot  %v (%d)", wantEnts, want.Total, mcpEnts, mf.Total)
		}
		if !reflect.DeepEqual(wantEnts, gqlEnts) || gf.Find.Total != want.Total {
			rt.Fatalf("gql find differs:\nwant %v (%d)\ngot  %v (%d)", wantEnts, want.Total, gqlEnts, gf.Find.Total)
		}

		ids := gen.DefaultUniverse().IDs()
		id := rapid.SampledFrom(ids).Draw(rt, "id")
		dirs := []string{"out", "in", "both"}
		dir2 := rapid.SampledFrom(dirs).Draw(rt, "dir")
		depth := rapid.IntRange(1, 3).Draw(rt, "depth")
		resolve := rapid.Bool().Draw(rt, "resolve")

		// get_entity / entity
		ev, eerr := core.Entity(ctx, id, nil)
		var me struct {
			Entity struct {
				IdentityFingerprint string `json:"identity_fingerprint"`
				Kind, Label         string
			} `json:"entity"`
		}
		res, merr := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_entity", Arguments: map[string]any{"entity_id": id, "verbosity": "full"}})
		if merr != nil {
			rt.Fatal(merr)
		}
		var ge struct {
			Entity *struct{ ID, Kind, Label string }
		}
		body, _ := json.Marshal(map[string]any{"query": `query($id: ID!){ entity(id: $id){ id kind label } }`, "variables": map[string]any{"id": id}})
		hr, err := http.Post(hs.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			rt.Fatal(err)
		}
		var gr struct {
			Data struct {
				Entity *struct{ ID, Kind, Label string }
			}
			Errors []any
		}
		_ = json.NewDecoder(hr.Body).Decode(&gr)
		hr.Body.Close()
		ge.Entity = gr.Data.Entity
		if eerr != nil {
			if !res.IsError || ge.Entity != nil {
				rt.Fatalf("entity %s: engine error %v but mcp isError=%v gql=%v", id, eerr, res.IsError, ge.Entity)
			}
		} else {
			if res.IsError || ge.Entity == nil || len(gr.Errors) > 0 {
				rt.Fatalf("entity %s: engine ok but mcp isError=%v gql=%v %v", id, res.IsError, ge.Entity, gr.Errors)
			}
			b, _ := json.Marshal(res.StructuredContent)
			_ = json.Unmarshal(b, &me)
			w := eqEnt{ev.ID, ev.Kind, ev.Label}
			if g := (eqEnt{me.Entity.IdentityFingerprint, me.Entity.Kind, me.Entity.Label}); g != w {
				rt.Fatalf("get_entity %v != %v", g, w)
			}
			if g := (eqEnt{ge.Entity.ID, ge.Entity.Kind, ge.Entity.Label}); g != w {
				rt.Fatalf("gql entity %v != %v", g, w)
			}
		}
		if eerr != nil {
			return // neighbors/history of an unknown entity are not compared
		}

		// neighbors / get_neighbors
		nb, err := core.Neighbors(ctx, id, engine.NeighborOpts{Direction: dir2, Depth: depth, Resolve: resolve,
			Paging: engine.Paging{PageSize: page}}, nil)
		if err != nil {
			rt.Fatal(err)
		}
		var wantEdges []eqEdge
		for _, e := range nb.Items {
			wantEdges = append(wantEdges, eqEdge{e.Type, e.From, e.To, e.Direction, e.Hops, e.Derived})
		}
		var mn struct {
			Items []struct {
				Type, From, To string
				Direction      string `json:"direction"`
				Hops           int
				Derived        bool
			} `json:"items"`
			Total int `json:"total"`
		}
		eqCallMCP(rt, cs, "get_neighbors", map[string]any{"entity_id": id, "direction": dir2, "depth": depth,
			"resolve": resolve, "verbosity": "full", "page_size": page}, &mn)
		var mcpEdges []eqEdge
		for _, e := range mn.Items {
			mcpEdges = append(mcpEdges, eqEdge{e.Type, e.From, e.To, e.Direction, e.Hops, e.Derived})
		}
		if !reflect.DeepEqual(wantEdges, mcpEdges) || mn.Total != nb.Total {
			rt.Fatalf("get_neighbors differs:\nwant %v (%d)\ngot  %v (%d)", wantEdges, nb.Total, mcpEdges, mn.Total)
		}
		var gn struct {
			Neighbors struct {
				Total int
				Items []struct {
					Type, Direction string
					Hops            int
					Derived         bool
					From, To        struct{ ID string }
				}
			}
		}
		eqCallGQL(rt, hs.URL, `query($id: ID!, $d: Direction, $n: Int, $r: Boolean, $f: Int){ neighbors(id: $id, direction: $d, depth: $n, resolve: $r, first: $f){
			total items{ type direction hops derived from{ id } to{ id } } } }`,
			map[string]any{"id": id, "d": gqlDir(dir2), "n": depth, "r": resolve, "f": page}, &gn)
		var gqlEdges []eqEdge
		for _, e := range gn.Neighbors.Items {
			gqlEdges = append(gqlEdges, eqEdge{e.Type, e.From.ID, e.To.ID, string(dirToEngine(e.Direction)), e.Hops, e.Derived})
		}
		if !reflect.DeepEqual(wantEdges, gqlEdges) || gn.Neighbors.Total != nb.Total {
			rt.Fatalf("gql neighbors differs:\nwant %v (%d)\ngot  %v (%d)", wantEdges, nb.Total, gqlEdges, gn.Neighbors.Total)
		}

		// history / entity_history
		h, err := core.History(ctx, id, engine.TimeRange{}, engine.Paging{PageSize: page})
		if err != nil {
			rt.Fatal(err)
		}
		var wantCh []eqChange
		for _, c := range h.Items {
			wantCh = append(wantCh, eqChange{c.Seq, string(c.Kind), string(c.Subject), c.Entity, c.From, c.To, c.RelationType, ""})
		}
		var mh struct {
			Items []struct {
				Kind, Subject, Entity, From, To string
				RelationType                    string `json:"relation_type"`
				Seq                             uint64
			} `json:"items"`
			Total int `json:"total"`
		}
		eqCallMCP(rt, cs, "entity_history", map[string]any{"entity_id": id, "verbosity": "full", "page_size": page}, &mh)
		var mcpCh []eqChange
		for _, c := range mh.Items {
			mcpCh = append(mcpCh, eqChange{c.Seq, c.Kind, c.Subject, c.Entity, c.From, c.To, c.RelationType, ""})
		}
		if !reflect.DeepEqual(wantCh, mcpCh) || mh.Total != h.Total {
			rt.Fatalf("entity_history differs:\nwant %v (%d)\ngot  %v (%d)", wantCh, h.Total, mcpCh, mh.Total)
		}
		var gh struct {
			History struct {
				Total int
				Items []struct {
					Seq, Kind, Subject, RelationType string
					Entity, From, To                 *string
				}
			}
		}
		eqCallGQL(rt, hs.URL, `query($id: ID!, $f: Int){ history(id: $id, first: $f){ total items{ seq kind subject entity from to relationType } } }`,
			map[string]any{"id": id, "f": page}, &gh)
		var gqlCh []eqChange
		for _, c := range gh.History.Items {
			seq, err := strconv.ParseUint(c.Seq, 10, 64)
			if err != nil {
				rt.Fatal(err)
			}
			gqlCh = append(gqlCh, eqChange{seq, lower(c.Kind), lower(c.Subject), deref(c.Entity), deref(c.From), deref(c.To), c.RelationType, ""})
		}
		if !reflect.DeepEqual(wantCh, gqlCh) || gh.History.Total != h.Total {
			rt.Fatalf("gql history differs:\nwant %v (%d)\ngot  %v (%d)", wantCh, h.Total, gqlCh, gh.History.Total)
		}
	})
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func lower(s string) string { return strings.ToLower(s) }

func gqlDir(d string) string {
	switch d {
	case "out":
		return "OUT"
	case "in":
		return "IN"
	}
	return "BOTH"
}

func dirToEngine(g string) string {
	switch g {
	case "OUT":
		return "out"
	case "IN":
		return "in"
	}
	return "both"
}
