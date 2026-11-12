package facade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"pgregory.net/rapid"
)

// aoObs is one full observation: host name -> "os" attribute.
type aoObs struct {
	at    time.Time
	hosts map[string]string
}

// aoResult is the comparable outcome of Query.Entity: found flag + attributes.
type aoResult struct {
	Found bool
	Attrs map[string]any
}

func aoQuery(ctx context.Context, e Engine, id EntityID, at time.Time) (aoResult, error) {
	got, err := e.Query().Entity(ctx, id, &at)
	if errors.Is(err, ErrNotFound) {
		return aoResult{}, nil
	}
	if err != nil {
		return aoResult{}, err
	}
	return aoResult{Found: true, Attrs: got.Attributes}, nil
}

// aoModel folds observations in log order: the latest one with at <= T wins.
func aoModel(log []aoObs, host string, at time.Time) aoResult {
	var last *aoObs
	for i := range log {
		if !log[i].at.After(at) {
			last = &log[i]
		}
	}
	if last == nil {
		return aoResult{}
	}
	os, ok := last.hosts[host]
	if !ok {
		return aoResult{}
	}
	return aoResult{Found: true, Attrs: map[string]any{"hostname": host, "os": os}}
}

// Feature: go-server-bellu-graph, Property 10: As-of equals replay
// **Validates: Requirements 13.6, 13.7, 13.8, 13.9**
func TestAsOfEqualsReplayProperty(t *testing.T) {
	ctx := context.Background()
	names := []string{"h0", "h1", "h2", "h3"}
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 6).Draw(rt, "events")
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		var log []aoObs
		cur := base
		for i := 0; i < n; i++ {
			if i > 0 {
				cur = cur.Add(time.Duration(rapid.IntRange(0, 3).Draw(rt, "gap")) * time.Minute)
			}
			hosts := map[string]string{}
			for _, h := range names {
				if rapid.Bool().Draw(rt, "present") {
					hosts[h] = rapid.SampledFrom([]string{"linux", "darwin", "bsd"}).Draw(rt, "os")
				}
			}
			log = append(log, aoObs{at: cur, hosts: hosts})
		}
		dir := filepath.Join(t.TempDir(), "g")
		e, err := Open(ctx, testCfg(dir, &bytes.Buffer{}))
		if err != nil {
			rt.Fatal(err)
		}
		closed := false
		defer func() {
			if !closed {
				e.Close(ctx)
			}
		}()
		for _, o := range log {
			b := batch.Batch{Collector: "host", ObservedAt: o.at}
			for _, h := range names {
				if os, ok := o.hosts[h]; ok {
					b.Entities = append(b.Entities, hostEnt(h, map[string]any{"os": os}))
				}
			}
			if _, err := e.Ingest().Apply(ctx, b); err != nil {
				rt.Fatalf("apply: %v", err)
			}
		}
		// Query times: before first, each event time, between, after last.
		times := []time.Time{base.Add(-time.Second), cur.Add(time.Hour)}
		for _, o := range log {
			times = append(times, o.at, o.at.Add(30*time.Second))
		}
		times = append(times, base.Add(time.Duration(rapid.IntRange(-2, 20).Draw(rt, "rand"))*time.Minute))
		var live []aoResult
		for _, h := range names {
			id := EntityID(aoHostID(h))
			for _, at := range times {
				got, err := aoQuery(ctx, e, id, at)
				if err != nil {
					rt.Fatalf("query: %v", err)
				}
				if want := aoModel(log, h, at); !reflect.DeepEqual(got, want) {
					rt.Fatalf("host %s at %v: got %+v want %+v (log %v)", h, at, got, want, aoDescribe(log))
				}
				live = append(live, got)
			}
		}
		if err := e.Close(ctx); err != nil {
			rt.Fatalf("close: %v", err)
		}
		closed = true
		e2, err := Open(ctx, testCfg(dir, &bytes.Buffer{}))
		if err != nil {
			rt.Fatal(err)
		}
		defer e2.Close(ctx)
		i := 0
		for _, h := range names {
			id := EntityID(aoHostID(h))
			for _, at := range times {
				got, err := aoQuery(ctx, e2, id, at)
				if err != nil {
					rt.Fatalf("reopened query: %v", err)
				}
				if !reflect.DeepEqual(got, live[i]) {
					rt.Fatalf("reopened differs host %s at %v: %+v vs %+v", h, at, got, live[i])
				}
				i++
			}
		}
	})
}

func aoHostID(h string) string {
	id, err := Hash("host", map[string]string{"hostname": h})
	if err != nil {
		panic(err)
	}
	return string(id)
}

func aoDescribe(log []aoObs) string {
	s := ""
	for _, o := range log {
		s += fmt.Sprintf("[%s %v] ", o.at.Format("15:04"), o.hosts)
	}
	return s
}
