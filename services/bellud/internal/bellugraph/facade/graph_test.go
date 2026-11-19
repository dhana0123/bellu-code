package facade

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

func openTemp(t *testing.T) Engine {
	t.Helper()
	e, err := Open(context.Background(), testCfg(filepath.Join(t.TempDir(), "g"), &bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	return e
}

func hostEnt(name string, attrs map[string]any) batch.Entity {
	return batch.Entity{Type: "host", Identity: map[string]string{"hostname": name}, Attributes: attrs}
}

func procEnt(host, pid string, attrs map[string]any) batch.Entity {
	return batch.Entity{Type: "process", Identity: map[string]string{"host": host, "pid": pid, "start_time": "1"}, Attributes: attrs}
}

func mustID(t *testing.T, kind string, attrs map[string]string) string {
	t.Helper()
	id, err := Hash(kind, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return string(id)
}

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestHashDeterministicAndScoped(t *testing.T) {
	a := mustID(t, "host", map[string]string{"hostname": "a", "os": "linux"})
	if a != mustID(t, "host", map[string]string{"os": "darwin", "hostname": "a"}) {
		t.Fatal("non-identity attributes changed the ID")
	}
	if a == mustID(t, "host", map[string]string{"hostname": "b"}) {
		t.Fatal("different identity values must differ")
	}
	if mustID(t, "image", map[string]string{"id": "x"}) == mustID(t, "container", map[string]string{"id": "x"}) {
		t.Fatal("different kinds must differ")
	}
	if _, err := Hash("nope", nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := Hash("process", map[string]string{"host": "h", "pid": "1"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("missing identity attribute: %v", err)
	}
}

func TestApplyThenQuery(t *testing.T) {
	ctx := context.Background()
	e := openTemp(t)
	hid := mustID(t, "host", map[string]string{"hostname": "h1"})
	pid := mustID(t, "process", map[string]string{"host": "h1", "pid": "7", "start_time": "1"})
	r, err := e.Ingest().Apply(ctx, batch.Batch{
		Collector: "host", ObservedAt: t0,
		Entities:  []batch.Entity{hostEnt("h1", map[string]any{"os": "linux"}), procEnt("h1", "7", map[string]any{"cmd": "sh", "n": 3})},
		Relations: []batch.Relation{{Type: "runs_on", From: pid, To: hid}},
	})
	if err != nil || r.ID == "" || r.Entities != 2 || r.Relations != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if !r.ObservedAt.Equal(t0) || r.RecordedAt.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("times %v %v", r.ObservedAt, r.RecordedAt)
	}
	got, err := e.Query().Entity(ctx, EntityID(hid), nil)
	if err != nil || got.Type != "host" || got.Attributes["os"] != "linux" || got.Attributes["hostname"] != "h1" {
		t.Fatalf("%+v %v", got, err)
	}
	// observed_at preserved exactly; recorded_at assigned at append.
	if !got.ObservedAt.Equal(t0) || !got.RecordedAt.After(t0) {
		t.Fatalf("observed %v recorded %v", got.ObservedAt, got.RecordedAt)
	}
	if _, err := e.Query().Entity(ctx, "host:00", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	pg, err := e.Query().Find(ctx, FindQuery{Type: "process", Attributes: map[string]string{"cmd": "sh"}})
	if err != nil || pg.Total != 1 || pg.Limit != DefaultPageSize || pg.Truncated || pg.Items[0].ID != EntityID(pid) {
		t.Fatalf("%+v %v", pg, err)
	}
	nb, err := e.Query().Neighbors(ctx, EntityID(hid), NeighborOpts{})
	if err != nil || len(nb.Items) != 1 || nb.Items[0].Type != "runs_on" || nb.Items[0].Direction != DirIn ||
		nb.Items[0].From != EntityID(pid) || nb.Items[0].To != EntityID(hid) || nb.Items[0].Hops != 1 {
		t.Fatalf("%+v %v", nb, err)
	}
	if out, _ := e.Query().Neighbors(ctx, EntityID(hid), NeighborOpts{Direction: DirOut}); len(out.Items) != 0 {
		t.Fatalf("out edges of host: %+v", out)
	}
}

func TestAsOfHistoryChangesDiffAndRemoval(t *testing.T) {
	ctx := context.Background()
	e := openTemp(t)
	hid := mustID(t, "host", map[string]string{"hostname": "h1"})
	p1 := mustID(t, "process", map[string]string{"host": "h1", "pid": "1", "start_time": "1"})
	p2 := mustID(t, "process", map[string]string{"host": "h1", "pid": "2", "start_time": "1"})
	apply := func(at time.Time, ents ...batch.Entity) {
		t.Helper()
		if _, err := e.Ingest().Apply(ctx, batch.Batch{Collector: "host", ObservedAt: at, Entities: ents}); err != nil {
			t.Fatal(err)
		}
	}
	apply(t0, hostEnt("h1", map[string]any{"os": "linux"}), procEnt("h1", "1", nil))
	apply(t0.Add(10*time.Minute), hostEnt("h1", map[string]any{"os": "linux", "kernel": "6"}), procEnt("h1", "2", nil)) // p1 gone, p2 added

	// as-of: inclusive at T, before first event is not found, after last is current.
	at := func(d time.Duration) (Entity, error) { x := t0.Add(d); return e.Query().Entity(ctx, EntityID(hid), &x) }
	if v, err := at(0); err != nil || v.Attributes["kernel"] != nil {
		t.Fatalf("at t0: %+v %v", v, err)
	}
	if _, err := at(-time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before first: %v", err)
	}
	if v, err := at(time.Hour); err != nil || v.Attributes["kernel"] != "6" {
		t.Fatalf("after last: %+v %v", v, err)
	}
	if v, err := at(10 * time.Minute); err != nil || v.Attributes["kernel"] != "6" {
		t.Fatalf("at second event time: %+v %v", v, err)
	}
	x := t0.Add(time.Hour)
	if _, err := e.Query().Entity(ctx, EntityID(p1), &x); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed entity as-of: %v", err)
	}
	if _, err := e.Query().Entity(ctx, EntityID(p1), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed entity now: %v", err)
	}
	x = t0
	if v, err := e.Query().Entity(ctx, EntityID(p1), &x); err != nil || v.ID != EntityID(p1) {
		t.Fatalf("removed entity before removal: %+v %v", v, err)
	}

	// history of the host: created then attribute change; heartbeats excluded.
	h, err := e.Query().History(ctx, EntityID(hid), TimeRange{}, Paging{})
	if err != nil || len(h.Items) != 2 || h.Items[0].Kind != ChangeAdded || h.Items[1].Kind != ChangeChanged ||
		h.Items[0].Subject != SubjectEntity || !h.Items[0].ObservedAt.Equal(t0) {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := e.Query().History(ctx, "host:00", TimeRange{}, Paging{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("history of unknown: %v", err)
	}
	// history survives deletion.
	if h, err := e.Query().History(ctx, EntityID(p1), TimeRange{}, Paging{}); err != nil || len(h.Items) != 2 || h.Items[1].Kind != ChangeRemoved {
		t.Fatalf("deleted history: %+v %v", h, err)
	}

	// changes: filter by kind and range.
	all, err := e.Query().Changes(ctx, TimeRange{}, ChangeFilter{})
	if err != nil || all.Total != 5 { // host+p1 added; host changed; p2 added; p1 removed
		t.Fatalf("%d %+v %v", all.Total, all, err)
	}
	rm, _ := e.Query().Changes(ctx, TimeRange{}, ChangeFilter{Kind: ChangeRemoved})
	if len(rm.Items) != 1 || rm.Items[0].Entity != EntityID(p1) {
		t.Fatalf("%+v", rm)
	}
	late, _ := e.Query().Changes(ctx, TimeRange{From: t0.Add(time.Minute)}, ChangeFilter{})
	if late.Total != 3 {
		t.Fatalf("late %d", late.Total)
	}

	// diff derived from full states.
	d, err := e.Query().Diff(ctx, t0, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || d.Added[0].ID != EntityID(p2) || len(d.Changed) != 1 || d.Changed[0].ID != EntityID(hid) ||
		len(d.Removed) != 1 || d.Removed[0] != EntityID(p1) || d.Truncated {
		t.Fatalf("%+v", d)
	}
	if d.Added[0].ObservedAt.IsZero() || d.Added[0].RecordedAt.IsZero() {
		t.Fatalf("diff entity times: %+v", d.Added[0])
	}
	if _, err := e.Query().Diff(ctx, t0.Add(time.Hour), t0); !errors.Is(err, ErrValidation) {
		t.Fatalf("reversed diff: %v", err)
	}
}

func TestRemovalIsScopedToCollector(t *testing.T) {
	ctx := context.Background()
	e := openTemp(t)
	if _, err := e.Ingest().Apply(ctx, batch.Batch{Collector: "host", ObservedAt: t0, Entities: []batch.Entity{hostEnt("h1", nil)}}); err != nil {
		t.Fatal(err)
	}
	// A different collector's empty observation must not retire host's entities.
	if _, err := e.Ingest().Apply(ctx, batch.Batch{Collector: "docker", ObservedAt: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Query().Entity(ctx, EntityID(mustID(t, "host", map[string]string{"hostname": "h1"})), nil); err != nil {
		t.Fatalf("entity of another scope was removed: %v", err)
	}
}

func TestUnknownRelationAttributeRejectedAppendsNothing(t *testing.T) {
	ctx := context.Background()
	e := openTemp(t)
	hid := mustID(t, "host", map[string]string{"hostname": "h1"})
	pid := mustID(t, "process", map[string]string{"host": "h1", "pid": "7", "start_time": "1"})
	_, err := e.Ingest().Apply(ctx, batch.Batch{
		Collector: "host", ObservedAt: t0,
		Entities:  []batch.Entity{hostEnt("h1", nil), procEnt("h1", "7", nil)},
		Relations: []batch.Relation{{Type: "runs_on", From: pid, To: hid, Attributes: map[string]any{"w": 1}}},
	})
	if !errors.Is(err, ErrValidation) || !contains(err.Error(), "runs_on") || !contains(err.Error(), hid) {
		t.Fatalf("want validation error naming the relation, got %v", err)
	}
	if pg, _ := e.Query().Find(ctx, FindQuery{}); pg.Total != 0 {
		t.Fatalf("entities leaked: %+v", pg)
	}
	if ch, _ := e.Query().Changes(ctx, TimeRange{}, ChangeFilter{}); ch.Total != 0 {
		t.Fatalf("events leaked: %+v", ch)
	}
	// the engine keeps accepting batches, including relations with fixed attribute names.
	if _, err := e.Ingest().Apply(ctx, batch.Batch{Collector: "host", ObservedAt: t0,
		Entities:  []batch.Entity{hostEnt("h1", nil), procEnt("h1", "7", nil)},
		Relations: []batch.Relation{{Type: "runs_on", From: pid, To: hid, Attributes: map[string]any{"evidence": "e", "confidence": "extracted", "observed_at": "2024-01-02T03:04:05Z"}}},
	}); err != nil {
		t.Fatalf("fixed attribute names rejected: %v", err)
	}
}

func TestInvalidBatchesAppendNothing(t *testing.T) {
	ctx := context.Background()
	e := openTemp(t)
	good := hostEnt("h1", nil)
	cases := map[string]batch.Batch{
		"unknown kind":     {Collector: "c", Entities: []batch.Entity{good, {Type: "nope", Identity: map[string]string{"a": "b"}}}},
		"missing identity": {Collector: "c", Entities: []batch.Entity{good, {Type: "process", Identity: map[string]string{"host": "h1"}}}},
		"no collector":     {Entities: []batch.Entity{good}},
		"dangling relation": {Collector: "c", Entities: []batch.Entity{good},
			Relations: []batch.Relation{{Type: "runs_on", From: "process:abc", To: "host:def"}}},
	}
	for name, b := range cases {
		if _, err := e.Ingest().Apply(ctx, b); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if pg, _ := e.Query().Find(ctx, FindQuery{}); pg.Total != 0 {
		t.Fatalf("leaked: %+v", pg)
	}
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
	e := openTemp(t)
	var ents []batch.Entity
	for i := range 5 {
		ents = append(ents, batch.Entity{Type: "volume", Identity: map[string]string{"name": string(rune('a' + i))}})
	}
	if _, err := e.Ingest().Apply(ctx, batch.Batch{Collector: "docker", ObservedAt: t0, Entities: ents}); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{-1, 1001} {
		if _, err := e.Query().Find(ctx, FindQuery{Paging: Paging{PageSize: size}}); !errors.Is(err, ErrValidation) || !contains(err.Error(), "1 to 1000") {
			t.Errorf("size %d: %v", size, err)
		}
		if _, err := e.Query().Changes(ctx, TimeRange{}, ChangeFilter{Paging: Paging{PageSize: size}}); !errors.Is(err, ErrValidation) {
			t.Errorf("changes size %d: %v", size, err)
		}
	}
	if pg, err := e.Query().Find(ctx, FindQuery{Paging: Paging{PageSize: 1000}}); err != nil || pg.Limit != 1000 || len(pg.Items) != 5 {
		t.Fatalf("%+v %v", pg, err)
	}
	seen := map[EntityID]bool{}
	cur := ""
	for pages := 0; ; pages++ {
		pg, err := e.Query().Find(ctx, FindQuery{Paging: Paging{PageSize: 2, Cursor: cur}})
		if err != nil || pg.Total != 5 || len(pg.Items) > 2 {
			t.Fatalf("%+v %v", pg, err)
		}
		for _, it := range pg.Items {
			seen[it.ID] = true
		}
		if !pg.Truncated {
			if pages != 2 {
				t.Fatalf("pages %d", pages)
			}
			break
		}
		cur = pg.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("saw %d distinct", len(seen))
	}
	ch, _ := e.Query().Changes(ctx, TimeRange{}, ChangeFilter{Paging: Paging{PageSize: 2}})
	if ch.Total != 5 || len(ch.Items) != 2 || !ch.Truncated || ch.NextCursor == "" {
		t.Fatalf("%+v", ch)
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
