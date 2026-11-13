package collectors

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

type timedFake struct {
	fake
	d time.Duration
}

func (t timedFake) Timeout() time.Duration { return t.d }

func TestCollectorTimeoutOverridesRunnerTimeout(t *testing.T) {
	e := openEngine(t)
	c := timedFake{fake{"conn", func(ctx context.Context) (graph.Batch, error) {
		select {
		case <-time.After(150 * time.Millisecond):
			return hostBatch("slowok"), nil
		case <-ctx.Done():
			return graph.Batch{}, ctx.Err()
		}
	}}, 2 * time.Second}
	r := New(e, []Collector{c}, WithTickTimeout(30*time.Millisecond))
	if err := r.RunOnce(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if a := status(t, e, "conn"); a["status"] != StatusOK {
		t.Fatalf("%v", a)
	}
	if ConnectorTimeout != 120*time.Second {
		t.Fatal("connector timeout")
	}
}

func TestPartialErrorAppliesBatchAndRecordsOK(t *testing.T) {
	e := openEngine(t)
	c := fake{"part", func(context.Context) (graph.Batch, error) {
		return hostBatch("partial-host"), fmt.Errorf("wrap: %w", PartialError{Types: []string{"ec2", "rds"}})
	}}
	r := New(e, []Collector{c})
	if err := r.RunOnce(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !hostFound(e, "partial-host") {
		t.Fatal("partial batch must be applied")
	}
	a := status(t, e, "part")
	if a["status"] != StatusOK || a["last_error"] != "partial: ec2,rds" {
		t.Fatalf("%v", a)
	}
}

func TestForgetRemovesStatusEntity(t *testing.T) {
	e := openEngine(t)
	ok := func(context.Context) (graph.Batch, error) { return hostBatch("h"), nil }
	a, b := fake{"a", ok}, fake{"b", ok}
	r := New(e, []Collector{a, b})
	ctx := context.Background()
	r.RunOnce(ctx, a)
	r.RunOnce(ctx, b)
	r.Forget("a")
	r.Forget("missing")
	r.RunOnce(ctx, b)
	id, _ := identity.Hash("collector_status", map[string]string{"collector": "a"})
	if _, err := e.Query().Entity(ctx, graph.EntityID(id), nil); err == nil {
		t.Fatal("a's status should be gone")
	}
	if status(t, e, "b")["status"] != StatusOK {
		t.Fatal("b must remain")
	}
	// A solitary collector forgotten still publishes an empty status batch.
	r.Forget("b")
	r.RunOnce(ctx, fake{"c", func(context.Context) (graph.Batch, error) { return graph.Batch{}, errors.New("x") }})
}
