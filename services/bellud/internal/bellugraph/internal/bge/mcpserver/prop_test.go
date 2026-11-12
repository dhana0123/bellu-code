package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

var propT0 = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// propEnv is a fresh engine plus an in-memory MCP client for one rapid iteration.
type propEnv struct {
	core *engine.Core
	cs   *mcp.ClientSession
	done func()
}

func newPropEnv(rt *rapid.T) *propEnv {
	dir, err := os.MkdirTemp("", "mcpprop")
	if err != nil {
		rt.Fatal(err)
	}
	core, err := engine.Open(dir, engine.Options{Clock: func() time.Time { return propT0.Add(24 * time.Hour) }})
	if err != nil {
		os.RemoveAll(dir)
		rt.Fatal(err)
	}
	srv, err := New(Config{
		Core:       core,
		CallerRole: func(context.Context) string { return RoleRead },
		Annotate:   func(context.Context, string, map[string]string, []string) error { return nil },
	})
	if err != nil {
		rt.Fatal(err)
	}
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		rt.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "prop"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		rt.Fatal(err)
	}
	return &propEnv{core: core, cs: cs, done: func() {
		_ = cs.Close()
		_ = core.Close(ctx)
		os.RemoveAll(dir)
	}}
}

// call runs a tool and decodes its structured result into out; it returns
// the raw text of the whole result for leak scans.
func (e *propEnv) call(rt *rapid.T, name string, args map[string]any, out any) string {
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		rt.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		rt.Fatalf("%s: error result %v", name, res.Content)
	}
	b, _ := json.Marshal(res)
	if out != nil {
		sb, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(sb, out); err != nil {
			rt.Fatal(err)
		}
	}
	return string(b)
}

func mustHash(rt *rapid.T, kind string, id map[string]string) string {
	h, err := ident.Hash(kind, id)
	if err != nil {
		rt.Fatal(err)
	}
	return h
}

// Feature: bellu-graph-native, Property 19: recent_changes budget and digest
// **Validates: Requirements 8.1, 8.2**
func TestPropertyRecentChangesBudgetAndDigest(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		e := newPropEnv(rt)
		defer e.done()
		ctx := context.Background()
		nBatches := rapid.IntRange(1, 6).Draw(rt, "batches")
		for i := 0; i < nBatches; i++ {
			var ents []batch.Entity
			for _, n := range rapid.SliceOfNDistinct(rapid.IntRange(0, 4), 1, 4, func(i int) int { return i }).Draw(rt, "hosts") {
				ents = append(ents, batch.Entity{Type: "host", Identity: map[string]string{"hostname": fmt.Sprintf("h%d", n)},
					Attributes: map[string]any{"os": rapid.SampledFrom([]string{"linux", "bsd", "win"}).Draw(rt, "os")}})
			}
			for _, n := range rapid.SliceOfNDistinct(rapid.IntRange(0, 3), 0, 3, func(i int) int { return i }).Draw(rt, "conts") {
				ents = append(ents, batch.Entity{Type: "container", Identity: map[string]string{"id": fmt.Sprintf("c%d", n)},
					Attributes: map[string]any{"state": rapid.SampledFrom([]string{"up", "down"}).Draw(rt, "state")}})
			}
			at := propT0.Add(time.Duration(i+1) * time.Minute)
			if _, err := e.core.Apply(ctx, batch.Batch{Collector: "t", ObservedAt: at, Entities: ents}, engine.ModeFull); err != nil {
				rt.Fatal(err)
			}
		}
		base := map[string]any{"since": "2000-01-01T00:00:00Z", "verbosity": "normal"}

		// The full matching set, newest first, at the maximum budget.
		var all []ChangeOut
		var first recentOut
		args := map[string]any{"max_bytes": MaxBudget}
		for k, v := range base {
			args[k] = v
		}
		for page := 0; ; page++ {
			var r recentOut
			e.call(rt, "recent_changes", args, &r)
			if page == 0 {
				first = r
			}
			all = append(all, r.Items...)
			if !r.Truncated {
				break
			}
			args["cursor"] = r.NextCursor
		}
		size := func(c ChangeOut) int { b, _ := json.Marshal(c); return len(b) }

		// Digest equals the model over the full set.
		if first.Digest == nil || first.Digest.Total != len(all) {
			rt.Fatalf("digest = %+v, want total %d", first.Digest, len(all))
		}
		byKind, bySubject, byEK, perEntity := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
		for _, c := range all {
			byKind[c.Kind]++
			bySubject[c.Subject]++
			if c.EntityKind != "" {
				byEK[c.EntityKind]++
			}
			if c.Entity != "" {
				perEntity[c.Entity]++
			}
		}
		eqMap := func(name string, got, want map[string]int) {
			if len(got) != len(want) {
				rt.Fatalf("%s = %v, want %v", name, got, want)
			}
			for k, v := range want {
				if got[k] != v {
					rt.Fatalf("%s = %v, want %v", name, got, want)
				}
			}
		}
		eqMap("by_kind", first.Digest.ByKind, byKind)
		eqMap("by_subject", first.Digest.BySubject, bySubject)
		eqMap("by_entity_kind", first.Digest.ByEntityKind, byEK)
		counts := make([]int, 0, len(perEntity))
		for _, n := range perEntity {
			counts = append(counts, n)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(counts)))
		if len(counts) > 10 {
			counts = counts[:10]
		}
		if len(first.Digest.Top) != len(counts) {
			rt.Fatalf("top = %v, want counts %v", first.Digest.Top, counts)
		}
		for i, f := range first.Digest.Top {
			if f.Changes != counts[i] || perEntity[f.Entity] != f.Changes {
				rt.Fatalf("top[%d] = %+v, model counts %v", i, f, counts)
			}
		}

		// Budget: longest newest-first prefix within B, or the first item alone.
		budget := rapid.OneOf(rapid.IntRange(1, 600), rapid.IntRange(1, 262144)).Draw(rt, "budget")
		want, used := 0, 0
		for _, c := range all {
			if want > 0 && used+size(c) > budget {
				break
			}
			used += size(c)
			want++
		}
		var got recentOut
		args = map[string]any{"max_bytes": budget}
		for k, v := range base {
			args[k] = v
		}
		e.call(rt, "recent_changes", args, &got)
		if len(got.Items) != want {
			rt.Fatalf("budget %d: %d items, want %d of %d", budget, len(got.Items), want, len(all))
		}
		for i, c := range got.Items {
			if c != all[i] {
				rt.Fatalf("item %d = %+v, want %+v", i, c, all[i])
			}
		}
		if got.Truncated != (want < len(all)) || got.Truncated != (got.NextCursor != "") {
			rt.Fatalf("truncated=%v cursor=%q, items %d of %d", got.Truncated, got.NextCursor, want, len(all))
		}
	})
}

func drawText(rt *rapid.T, label string, maxRunes int) string {
	return rapid.StringOfN(rapid.RuneFrom([]rune("abcxyz09 é世🙂")), 0, maxRunes, -1).Draw(rt, label)
}

// Feature: bellu-graph-native, Property 20: Verbosity shapes
// **Validates: Requirements 10.2, 10.3, 10.4**
func TestPropertyVerbosityShapes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		e := newPropEnv(rt)
		defer e.done()
		ctx := context.Background()
		names := rapid.SliceOfNDistinct(rapid.StringMatching(`[a-z]{1,6}`), 0, 45, func(s string) string { return s }).Draw(rt, "names")
		attrs := map[string]any{}
		for _, n := range names {
			k := "a_" + n
			switch rapid.IntRange(0, 2).Draw(rt, "type") {
			case 0:
				attrs[k] = drawText(rt, "val", 400)
			case 1:
				attrs[k] = []string{drawText(rt, "e1", 300), drawText(rt, "e2", 100)}
			default:
				attrs[k] = rapid.IntRange(0, 1000).Draw(rt, "num")
			}
		}
		_, err := e.core.Apply(ctx, batch.Batch{Collector: "t", ObservedAt: propT0, Entities: []batch.Entity{
			{Type: "host", Identity: map[string]string{"hostname": "h"}, Attributes: attrs}}}, engine.ModeFull)
		if err != nil {
			rt.Fatal(err)
		}
		id := mustHash(rt, "host", map[string]string{"hostname": "h"})
		ann := map[string]string{}
		for _, k := range rapid.SliceOfNDistinct(rapid.StringMatching(`[a-z]{1,6}`), 0, 3, func(s string) string { return s }).Draw(rt, "annkeys") {
			ann[k] = drawText(rt, "annval", 20)
		}
		if len(ann) > 0 {
			if _, err := e.core.Annotate(ctx, id, ann, nil, "test"); err != nil {
				rt.Fatal(err)
			}
		}
		truth, err := e.core.Entity(ctx, id, nil)
		if err != nil {
			rt.Fatal(err)
		}
		get := func(v string) (EntityOut, map[string]any) {
			var raw struct {
				Entity json.RawMessage `json:"entity"`
			}
			e.call(rt, "get_entity", map[string]any{"entity_id": id, "verbosity": v}, &raw)
			var out EntityOut
			var m map[string]any
			if err := json.Unmarshal(raw.Entity, &out); err != nil {
				rt.Fatal(err)
			}
			_ = json.Unmarshal(raw.Entity, &m)
			return out, m
		}
		jsonEq := func(a, b any) bool {
			x, _ := json.Marshal(a)
			y, _ := json.Marshal(b)
			return string(x) == string(y)
		}

		_, bm := get("brief")
		keys := make([]string, 0, 4)
		for k := range bm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "id,identity_fingerprint,kind,label" {
			rt.Fatalf("brief keys = %v", keys)
		}

		n, _ := get("normal")
		if len(n.Attributes) > 32 || len(n.Attributes)+n.OmittedAttributes != len(truth.Attributes) {
			rt.Fatalf("normal: %d shown, %d omitted, %d total", len(n.Attributes), n.OmittedAttributes, len(truth.Attributes))
		}
		cut := map[string]bool{}
		for _, k := range n.TruncatedAttributes {
			cut[k] = true
		}
		for k, v := range n.Attributes {
			orig := truth.Attributes[k]
			over := false
			var check func(s string, o string)
			check = func(s, o string) {
				if len(s) > 256 || !utf8.ValidString(s) || !strings.HasPrefix(o, s) {
					rt.Fatalf("normal %s: bad cut value len %d", k, len(s))
				}
				if len(o) > 256 {
					over = true
				}
			}
			switch x := v.(type) {
			case string:
				check(x, orig.(string))
			case []any:
				for i, el := range x {
					check(el.(string), orig.([]string)[i])
				}
			default:
				if !jsonEq(v, orig) {
					rt.Fatalf("normal %s = %v, want %v", k, v, orig)
				}
			}
			if over != cut[k] {
				rt.Fatalf("normal %s: oversize=%v listed=%v", k, over, cut[k])
			}
		}
		for k := range cut {
			if _, ok := n.Attributes[k]; !ok {
				rt.Fatalf("truncated list names absent attribute %s", k)
			}
		}
		if !jsonEq(n.Annotations, truth.Annotations) && !(len(n.Annotations) == 0 && len(truth.Annotations) == 0) {
			rt.Fatalf("normal annotations = %v, want %v", n.Annotations, truth.Annotations)
		}

		f, _ := get("full")
		if !jsonEq(f.Attributes, truth.Attributes) {
			rt.Fatalf("full attributes differ:\n%v\n%v", f.Attributes, truth.Attributes)
		}
		if f.ObservedAt == "" || f.RecordedAt == "" || f.URI == "" {
			rt.Fatalf("full lacks timestamps/uri: %+v", f)
		}
	})
}

// Feature: bellu-graph-native, Property 21: Secret-named values are never emitted
// **Validates: Requirements 7.9, 8.5, 9.5**
func TestPropertySecretValuesNeverEmitted(t *testing.T) {
	frags := []string{"secret", "token", "password", "passwd", "credential", "private", "apikey", "api_key", "hash"}
	rapid.Check(t, func(rt *rapid.T) {
		e := newPropEnv(rt)
		defer e.done()
		ctx := context.Background()
		var sentinels []string
		mk := func(label string) (map[string]any, map[string]string) {
			attrs := map[string]any{"os": "linux"}
			ann := map[string]string{}
			nameGen := rapid.Custom(func(rt *rapid.T) string {
				f := rapid.SampledFrom(frags).Draw(rt, "frag")
				if rapid.Bool().Draw(rt, "upper") {
					f = strings.ToUpper(f)
				}
				return rapid.StringMatching(`[a-z]{0,4}`).Draw(rt, "pre") + f + rapid.StringMatching(`[a-z]{0,4}`).Draw(rt, "suf")
			})
			for i, n := range rapid.SliceOfNDistinct(nameGen, 1, 4, func(s string) string { return strings.ToLower(s) }).Draw(rt, label) {
				s := fmt.Sprintf("SENTINEL-%s-%d-%s", label, i, rapid.StringMatching(`[0-9a-f]{12}`).Draw(rt, "hex"))
				sentinels = append(sentinels, s)
				attrs[n] = s
			}
			a := fmt.Sprintf("SENTINEL-ann-%s-%s", label, rapid.StringMatching(`[0-9a-f]{12}`).Draw(rt, "annhex"))
			sentinels = append(sentinels, a)
			ann["secret_note"] = a
			return attrs, ann
		}
		a1, n1 := mk("a")
		a2, _ := mk("b")
		// Identical secret names with the same value on both ends, so the
		// shared-attribute computation would see them.
		for k, v := range a1 {
			if ident.IsSecretName(k) {
				a2[k] = v
			}
		}
		_, err := e.core.Apply(ctx, batch.Batch{Collector: "t", ObservedAt: propT0, Entities: []batch.Entity{
			{Type: "host", Identity: map[string]string{"hostname": "one"}, Attributes: a1},
			{Type: "host", Identity: map[string]string{"hostname": "two"}, Attributes: a2},
		}}, engine.ModeFull)
		if err != nil {
			rt.Fatal(err)
		}
		one := mustHash(rt, "host", map[string]string{"hostname": "one"})
		two := mustHash(rt, "host", map[string]string{"hostname": "two"})
		if _, err := e.core.Annotate(ctx, one, n1, nil, "test"); err != nil {
			rt.Fatal(err)
		}
		scan := func(where, text string) {
			for _, s := range sentinels {
				if strings.Contains(text, s) {
					rt.Fatalf("%s leaks %s", where, s)
				}
			}
		}
		for _, v := range []string{"brief", "normal", "full"} {
			scan("telemetry_keys/"+v, e.call(rt, "telemetry_keys", map[string]any{"entity_id": one, "verbosity": v}, nil))
		}
		var fp findPathOut
		scan("find_path", e.call(rt, "find_path", map[string]any{"from": one, "to": two}, &fp))
		if fp.Connected || fp.SharedAttributes["os"] != "linux" {
			rt.Fatalf("find_path = %+v, want unconnected with shared os", fp)
		}
		for name, args := range map[string]map[string]string{
			"investigate_incident": {"entity_id": one, "since": "1h"},
			"blast_radius":         {"entity_id": one},
			"explain_entity":       {"entity_id": one},
		} {
			r, err := e.cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: name, Arguments: args})
			if err != nil {
				rt.Fatal(err)
			}
			b, _ := json.Marshal(r)
			scan("prompt "+name, string(b))
		}
		res, err := e.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: entityURI(one)})
		if err != nil {
			rt.Fatal(err)
		}
		b, _ := json.Marshal(res)
		scan("entity resource", string(b))
	})
}
