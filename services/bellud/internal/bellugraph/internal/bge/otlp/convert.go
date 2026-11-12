// Package otlp is the OTLP/HTTP logs receiver of the Bellu Graph Engine. It
// decodes log exports, maps each resource to one Batch and applies it.
package otlp

import (
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/engine"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// Attribute names understood by the receiver.
const (
	AttrCollector       = "bellugraph.collector"
	AttrFullObservation = "bellugraph.full_observation"
	AttrRecord          = "bellugraph.record"
	AttrKind            = "bellugraph.kind"
	AttrRelationType    = "bellugraph.relation.type"
	AttrRelationFrom    = "bellugraph.relation.from"
	AttrRelationTo      = "bellugraph.relation.to"
	PrefixIdentity      = "bellugraph.id."
	PrefixAttr          = "bellugraph.attr."

	// CollectorPrefix is prepended to the producer's collector name.
	CollectorPrefix = "otlp/"
)

// Item is one converted resource.
type Item struct {
	Batch   batch.Batch
	Mode    engine.Mode
	Records int // number of log records the resource carried
}

// Rejection describes one resource that could not be converted.
type Rejection struct {
	Records int
	Reason  string
}

// Convert maps every ResourceLogs of logs to an Item, or to a Rejection when
// any of its records is invalid. Resources without records are skipped. now is
// the Valid_Time of resources whose records carry no timestamp.
func Convert(logs plog.Logs, now time.Time) ([]Item, []Rejection) {
	var items []Item
	var rejs []Rejection
	rls := logs.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		n := 0
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			n += rl.ScopeLogs().At(j).LogRecords().Len()
		}
		if n == 0 {
			continue
		}
		it, err := convertResource(rl, n, now)
		if err != nil {
			rejs = append(rejs, Rejection{Records: n, Reason: err.Error()})
			continue
		}
		items = append(items, it)
	}
	return items, rejs
}

func convertResource(rl plog.ResourceLogs, n int, now time.Time) (Item, error) {
	res := rl.Resource().Attributes()
	cv, ok := res.Get(AttrCollector)
	if !ok || cv.Type() != pcommon.ValueTypeStr || cv.Str() == "" {
		return Item{}, fmt.Errorf("resource attribute %s is required and must be a non-empty string", AttrCollector)
	}
	mode := engine.ModePartial
	if fv, ok := res.Get(AttrFullObservation); ok {
		if fv.Type() != pcommon.ValueTypeBool {
			return Item{}, fmt.Errorf("resource attribute %s must be a bool", AttrFullObservation)
		}
		if fv.Bool() {
			mode = engine.ModeFull
		}
	}
	b := batch.Batch{Collector: CollectorPrefix + cv.Str()}
	var latest time.Time
	for j := 0; j < rl.ScopeLogs().Len(); j++ {
		recs := rl.ScopeLogs().At(j).LogRecords()
		for k := 0; k < recs.Len(); k++ {
			rec := recs.At(k)
			ts := rec.Timestamp()
			if ts == 0 {
				ts = rec.ObservedTimestamp()
			}
			if t := ts.AsTime(); ts != 0 && t.After(latest) {
				latest = t
			}
			if err := convertRecord(rec.Attributes(), &b); err != nil {
				return Item{}, fmt.Errorf("record %d: %w", k, err)
			}
		}
	}
	if latest.IsZero() {
		latest = now
	}
	b.ObservedAt = latest.UTC()
	return Item{Batch: b, Mode: mode, Records: n}, nil
}

func convertRecord(attrs pcommon.Map, b *batch.Batch) error {
	rv, ok := attrs.Get(AttrRecord)
	if !ok || rv.Type() != pcommon.ValueTypeStr {
		return fmt.Errorf("attribute %s is required", AttrRecord)
	}
	switch rv.Str() {
	case "entity":
		e, err := convertEntity(attrs)
		if err != nil {
			return err
		}
		b.Entities = append(b.Entities, e)
	case "relation":
		r, err := convertRelation(attrs)
		if err != nil {
			return err
		}
		b.Relations = append(b.Relations, r)
	default:
		return fmt.Errorf("attribute %s must be \"entity\" or \"relation\", got %q", AttrRecord, rv.Str())
	}
	return nil
}

func convertEntity(attrs pcommon.Map) (batch.Entity, error) {
	kind, err := requireStr(attrs, AttrKind)
	if err != nil {
		return batch.Entity{}, err
	}
	e := batch.Entity{Type: kind, Identity: map[string]string{}, Attributes: map[string]any{}}
	var rerr error
	attrs.Range(func(k string, v pcommon.Value) bool {
		switch {
		case strings.HasPrefix(k, PrefixIdentity):
			name := strings.TrimPrefix(k, PrefixIdentity)
			if name == "" || v.Type() != pcommon.ValueTypeStr {
				rerr = fmt.Errorf("identity attribute %q must be a string with a name", k)
				return false
			}
			e.Identity[name] = v.Str()
		case strings.HasPrefix(k, PrefixAttr):
			name := strings.TrimPrefix(k, PrefixAttr)
			x, err := scalar(v)
			if name == "" || err != nil {
				rerr = fmt.Errorf("attribute %q is not a supported value", k)
				return false
			}
			e.Attributes[name] = x
		}
		return true
	})
	if rerr != nil {
		return batch.Entity{}, rerr
	}
	return e, nil
}

func convertRelation(attrs pcommon.Map) (batch.Relation, error) {
	var r batch.Relation
	var err error
	if r.Type, err = requireStr(attrs, AttrRelationType); err != nil {
		return r, err
	}
	if r.From, err = requireStr(attrs, AttrRelationFrom); err != nil {
		return r, err
	}
	if r.To, err = requireStr(attrs, AttrRelationTo); err != nil {
		return r, err
	}
	return r, nil
}

func requireStr(attrs pcommon.Map, key string) (string, error) {
	v, ok := attrs.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeStr || v.Str() == "" {
		return "", fmt.Errorf("attribute %s is required and must be a non-empty string", key)
	}
	return v.Str(), nil
}

func scalar(v pcommon.Value) (any, error) {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return v.Str(), nil
	case pcommon.ValueTypeBool:
		return v.Bool(), nil
	case pcommon.ValueTypeInt:
		return v.Int(), nil
	case pcommon.ValueTypeDouble:
		return v.Double(), nil
	case pcommon.ValueTypeSlice:
		s := v.Slice()
		out := make([]string, s.Len())
		for i := range out {
			if s.At(i).Type() != pcommon.ValueTypeStr {
				return nil, fmt.Errorf("array element %d is not a string", i)
			}
			out[i] = s.At(i).Str()
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported type %s", v.Type())
}
