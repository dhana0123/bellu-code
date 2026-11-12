package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/uri"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

func mustID(t *testing.T, kind string, id map[string]string) string {
	t.Helper()
	h, err := ident.Hash(kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// traverseFixture: container c1 depends_on endpoint tcp/10.0.0.5:80, served by
// a wildcard listening port on host web-1 owned_by a process.
func traverseFixture(t *testing.T) (*Core, map[string]string) {
	t.Helper()
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := openTest(t, t.TempDir(), &fakeClock{t: t0.Add(time.Hour)})
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	ids := map[string]string{
		"host": mustID(t, "host", map[string]string{"hostname": "web-1"}),
		"cont": mustID(t, "container", map[string]string{"id": "c1"}),
		"ep":   mustID(t, "endpoint", map[string]string{"protocol": "tcp", "address": "10.0.0.5", "port": "80"}),
		"lp":   mustID(t, "listening_port", map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "80"}),
		"proc": mustID(t, "process", map[string]string{"host": "web-1", "pid": "7", "start_time": "1"}),
		"lone": mustID(t, "host", map[string]string{"hostname": "lone"}),
	}
	apply(t, c, batch.Batch{Collector: "t", ObservedAt: t0, Entities: []batch.Entity{
		{Type: "host", Identity: map[string]string{"hostname": "web-1"}, Attributes: map[string]any{"addresses": []string{"10.0.0.5"}, "os": "linux"}},
		{Type: "host", Identity: map[string]string{"hostname": "lone"}, Attributes: map[string]any{"os": "linux", "api_token": "s3cret"}},
		{Type: "container", Identity: map[string]string{"id": "c1"}},
		{Type: "endpoint", Identity: map[string]string{"protocol": "tcp", "address": "10.0.0.5", "port": "80"}},
		{Type: "listening_port", Identity: map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "80"}},
		{Type: "process", Identity: map[string]string{"host": "web-1", "pid": "7", "start_time": "1"}},
	}, Relations: []batch.Relation{
		{Type: "depends_on", From: ids["cont"], To: ids["ep"]},
		{Type: "owned_by", From: ids["lp"], To: ids["proc"]},
		{Type: "on", From: ids["lp"], To: ids["host"]},
	}}, ModeFull)
	return c, ids
}

func TestPathAndImpact(t *testing.T) {
	c, id := traverseFixture(t)
	ctx := context.Background()

	r, err := c.Path(ctx, id["cont"], id["proc"], PathOpts{})
	if err != nil || !r.Connected || len(r.Path) != 2 || r.Path[0].Derived || !r.Path[1].Derived {
		t.Fatalf("path = %+v, %v", r, err)
	}
	// Without resolution the container is not connected to the process.
	r, err = c.Path(ctx, id["cont"], id["proc"], PathOpts{StoredOnly: true})
	if err != nil || r.Connected || !r.Exhausted || r.DepthSearched == 0 {
		t.Fatalf("stored-only = %+v, %v", r, err)
	}
	r, _ = c.Path(ctx, id["host"], id["lone"], PathOpts{})
	if r.Connected || !r.Exhausted || r.SharedAttributes["os"] != "linux" {
		t.Fatalf("not connected = %+v", r)
	}
	if _, bad := r.SharedAttributes["api_token"]; bad {
		t.Fatal("secret attribute leaked")
	}
	if _, err := c.Path(ctx, id["cont"], "host:nope", PathOpts{}); !errors.Is(err, errs.NotFound) {
		t.Fatalf("unknown err = %v", err)
	}
	if _, err := c.Path(ctx, id["cont"], id["proc"], PathOpts{MaxDepth: 11}); !errors.Is(err, errs.Validation) {
		t.Fatalf("depth err = %v", err)
	}

	// Failure of the process impacts its port (owned_by reverse), then the
	// endpoint resolving to it, then the container depending on the endpoint.
	imp, err := c.Impact(ctx, id["proc"], ImpactOpts{Depth: 5})
	if err != nil {
		t.Fatal(err)
	}
	hops := map[string]int{}
	for _, it := range imp.Items {
		hops[it.ID] = it.Hops
	}
	if hops[id["lp"]] != 1 || hops[id["ep"]] != 1 || hops[id["cont"]] != 2 || hops[id["host"]] != 0 {
		t.Fatalf("impact hops = %v", hops)
	}
	imp, _ = c.Impact(ctx, id["proc"], ImpactOpts{Depth: 5, StoredOnly: true})
	if len(imp.Items) != 1 || imp.Items[0].ID != id["lp"] {
		t.Fatalf("stored-only impact = %+v", imp)
	}
}

func TestResolveRefsAndLocalID(t *testing.T) {
	c, id := traverseFixture(t)
	host := id["host"]
	alias := c.LocalID(host)
	if alias[0] != '@' || c.LocalID(host) != alias {
		t.Fatalf("alias = %q", alias)
	}
	u, err := uri.Format(uri.Entity{Kind: "host", Hex: host[len("host:"):]})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{host, alias, u} {
		if got, err := c.Resolve(ref); err != nil || got != host {
			t.Fatalf("Resolve(%q) = %q, %v", ref, got, err)
		}
	}
	if _, err := c.Resolve("@zzzzzz"); !errors.Is(err, errs.NotFound) {
		t.Fatalf("unknown alias err = %v", err)
	}
	if _, err := c.Resolve("bellugraph://event/01ARZ3NDEKTSV4RRFFQ69G5FAV"); !errors.Is(err, errs.Validation) {
		t.Fatalf("event uri err = %v", err)
	}
	if _, err := c.Resolve("bellugraph://host/xyz"); !errors.Is(err, errs.Validation) {
		t.Fatalf("bad uri err = %v", err)
	}
}
