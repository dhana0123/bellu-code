package otlp

import (
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/internal/gen"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// encodeBatch writes b as one ResourceLogs per the design's attribute mapping.
func encodeBatch(b batch.Batch, collector string, full bool) plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr(AttrCollector, collector)
	if full {
		rl.Resource().Attributes().PutBool(AttrFullObservation, true)
	}
	recs := rl.ScopeLogs().AppendEmpty().LogRecords()
	for _, e := range b.Entities {
		r := recs.AppendEmpty()
		r.SetTimestamp(pcommon.NewTimestampFromTime(b.ObservedAt))
		a := r.Attributes()
		a.PutStr(AttrRecord, "entity")
		a.PutStr(AttrKind, e.Type)
		for k, v := range e.Identity {
			a.PutStr(PrefixIdentity+k, v)
		}
		for k, v := range e.Attributes {
			switch x := v.(type) {
			case string:
				a.PutStr(PrefixAttr+k, x)
			case bool:
				a.PutBool(PrefixAttr+k, x)
			case int:
				a.PutInt(PrefixAttr+k, int64(x))
			case int64:
				a.PutInt(PrefixAttr+k, x)
			case float64:
				a.PutDouble(PrefixAttr+k, x)
			case []string:
				sl := a.PutEmptySlice(PrefixAttr + k)
				for _, s := range x {
					sl.AppendEmpty().SetStr(s)
				}
			default:
				panic("unexpected generated value")
			}
		}
	}
	for _, rel := range b.Relations {
		r := recs.AppendEmpty()
		r.SetTimestamp(pcommon.NewTimestampFromTime(b.ObservedAt))
		a := r.Attributes()
		a.PutStr(AttrRecord, "relation")
		a.PutStr(AttrRelationType, rel.Type)
		a.PutStr(AttrRelationFrom, rel.From)
		a.PutStr(AttrRelationTo, rel.To)
	}
	return logs
}

// normAttr widens int to int64, the type OTLP carries.
func normAttr(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if i, ok := v.(int); ok {
			v = int64(i)
		}
		out[k] = v
	}
	return out
}

// Feature: bellu-graph-native, Property 28: OTLP conversion round trip
// **Validates: Requirements 19.2**
func TestPropertyOTLPConversionRoundTrip(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[a-z][a-z0-9_-]{0,11}`).Draw(t, "collector")
		observed := gen.ValidTime().Draw(t, "observed")
		full := rapid.Bool().Draw(t, "full")
		viaJSON := rapid.Bool().Draw(t, "json")
		want := gen.Options{}.Batch(name, observed).Draw(t, "batch")

		req := plogotlp.NewExportRequestFromLogs(encodeBatch(want, name, full))
		var back plogotlp.ExportRequest
		if viaJSON {
			b, err := req.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			back = plogotlp.NewExportRequest()
			if err := back.UnmarshalJSON(b); err != nil {
				t.Fatal(err)
			}
		} else {
			b, err := req.MarshalProto()
			if err != nil {
				t.Fatal(err)
			}
			back = plogotlp.NewExportRequest()
			if err := back.UnmarshalProto(b); err != nil {
				t.Fatal(err)
			}
		}

		items, rejs := Convert(back.Logs(), now)
		if len(rejs) != 0 {
			t.Fatalf("rejections: %+v", rejs)
		}
		if len(want.Entities)+len(want.Relations) == 0 {
			if len(items) != 0 {
				t.Fatalf("empty batch produced %d items", len(items))
			}
			return
		}
		if len(items) != 1 {
			t.Fatalf("items=%d", len(items))
		}
		got := items[0]
		wantMode := engine.ModePartial
		if full {
			wantMode = engine.ModeFull
		}
		if got.Mode != wantMode {
			t.Fatalf("mode %v want %v", got.Mode, wantMode)
		}
		if got.Batch.Collector != CollectorPrefix+name {
			t.Fatalf("collector %q", got.Batch.Collector)
		}
		if !got.Batch.ObservedAt.Equal(observed) {
			t.Fatalf("valid time %v want %v", got.Batch.ObservedAt, observed)
		}
		if got.Records != len(want.Entities)+len(want.Relations) {
			t.Fatalf("records %d", got.Records)
		}
		if len(got.Batch.Entities) != len(want.Entities) || len(got.Batch.Relations) != len(want.Relations) {
			t.Fatalf("shape %+v vs %+v", got.Batch, want)
		}
		for i, e := range want.Entities {
			g := got.Batch.Entities[i]
			if g.Type != e.Type || !mapsEqual(g.Identity, e.Identity) || !attrsEqual(g.Attributes, normAttr(e.Attributes)) {
				t.Fatalf("entity %d: got %+v want %+v", i, g, e)
			}
		}
		for i, r := range want.Relations {
			g := got.Batch.Relations[i]
			if g.Type != r.Type || g.From != r.From || g.To != r.To || len(g.Attributes) != 0 {
				t.Fatalf("relation %d: got %+v want %+v", i, g, r)
			}
		}
	})
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func attrsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok {
			return false
		}
		if vs, ok := v.([]string); ok {
			ws, ok := w.([]string)
			if !ok || len(vs) != len(ws) {
				return false
			}
			for i := range vs {
				if vs[i] != ws[i] {
					return false
				}
			}
			continue
		}
		if v != w {
			return false
		}
	}
	return true
}
