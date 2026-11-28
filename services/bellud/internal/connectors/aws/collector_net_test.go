package aws

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

func openEngine(t *testing.T) graph.Engine {
	t.Helper()
	e, err := graph.Open(context.Background(), graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	return e
}

func netCollector(c Client) *collector {
	return NewCollector(c, store.Connection{ID: "c1"}, store.Selection{Regions: []string{"eu-west-1"}}).(*collector)
}

func resID(arn string) graph.EntityID {
	id, _ := identity.Hash(kindResource, map[string]string{"connection": "c1", "arn": arn})
	return graph.EntityID(id)
}

func collectApply(t *testing.T, e graph.Engine, c *collector) graph.Batch {
	t.Helper()
	b, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if err != nil && !errors.As(err, &pe) {
		t.Fatal(err)
	}
	if _, err := e.Ingest().Apply(context.Background(), b); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return b
}

func live(t *testing.T, e graph.Engine, id graph.EntityID) bool {
	t.Helper()
	_, err := e.Query().Entity(context.Background(), id, nil)
	if err != nil && !errors.Is(err, graph.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func relTypes(b graph.Batch) map[string]int {
	out := map[string]int{}
	for _, r := range b.Relations {
		out[r.Type]++
	}
	return out
}

func TestCollectorNetworkBatchApplies(t *testing.T) {
	e := openEngine(t)
	b := collectApply(t, e, netCollector(newNetClient()))
	rel := relTypes(b)
	for _, want := range []string{
		"aws_in_vpc", "aws_in_subnet", "aws_member_of_sg", "aws_has_eni", "aws_routes_to", "aws_route_of",
		"aws_associated_subnet", "aws_attached_igw", "aws_assigned_to", "aws_rule_of", "aws_rule_peer",
		"aws_lb_listener_of", "aws_lb_forwards_to", "aws_targets", "aws_exposed_via", "runs_on", "owned_by",
	} {
		if rel[want] == 0 {
			t.Errorf("no %s relation; got %v", want, rel)
		}
	}
	if rel["attached_to"] != 0 {
		t.Errorf("attached_to emitted %d times", rel["attached_to"])
	}
	inst := arnOf("instance/i-1")
	for _, en := range b.Entities {
		if en.Identity["arn"] == inst && en.Attributes["internet_exposed"] != "true" {
			t.Errorf("instance internet_exposed = %v, want true", en.Attributes["internet_exposed"])
		}
	}
	for _, r := range b.Relations {
		if r.Type == "aws_exposed_via" && (r.Attributes["confidence"] != "extracted" || r.Attributes["evidence"] == "") {
			t.Errorf("aws_exposed_via attributes %v", r.Attributes)
		}
	}
	if !live(t, e, resID(inst)) {
		t.Fatal("instance not ingested")
	}
}

func TestCollectorRetiresAbsentAndRetainsFailed(t *testing.T) {
	e := openEngine(t)
	nc := newNetClient()
	collectApply(t, e, netCollector(nc))
	inst, subnet := resID(arnOf("instance/i-1")), resID(arnOf("subnet/subnet-1"))

	// Subnets fail: the subnet and its relations stay.
	nc.fail["subnet"] = ErrAccessDenied
	c := netCollector(nc)
	collectApply(t, e, c)
	if !live(t, e, subnet) {
		t.Fatal("subnet of a failed listing was retired")
	}
	page, err := e.Query().Neighbors(context.Background(), subnet, graph.NeighborOpts{Direction: graph.DirIn, RelationType: "aws_in_subnet", Depth: 1})
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("aws_in_subnet of a failed listing was removed: %v %v", page.Items, err)
	}
	if !slices.Contains(c.RunStatus().DeniedScopes, "subnet@eu-west-1") {
		t.Fatalf("denied scopes %v", c.RunStatus().DeniedScopes)
	}

	// The instance disappears from a successful listing: it is retired.
	delete(nc.fail, "subnet")
	nc.instances = nil
	collectApply(t, e, netCollector(nc))
	if live(t, e, inst) {
		t.Fatal("instance absent from a successful listing was not retired")
	}
}

func TestCollectorRejectedCredentialsEndRun(t *testing.T) {
	nc := newNetClient()
	nc.fail["eni"] = ErrExpired
	b, err := netCollector(nc).Collect(context.Background())
	var pe collectors.PartialError
	if err == nil || errors.As(err, &pe) || len(b.Entities) != 0 {
		t.Fatalf("err=%v entities=%d", err, len(b.Entities))
	}
	for _, call := range nc.calls {
		if call == "ec2:eu-west-1" {
			t.Fatal("steps after a credential rejection still ran")
		}
	}
}

func TestCollectorCapsSetTruncation(t *testing.T) {
	account := func(b graph.Batch) map[string]any {
		for _, en := range b.Entities {
			if en.Type == kindAccount {
				return en.Attributes
			}
		}
		return nil
	}
	group := func(b graph.Batch) map[string]any {
		for _, en := range b.Entities {
			if en.Identity["arn"] == arnOf("security-group/sg-1") {
				return en.Attributes
			}
		}
		return nil
	}
	// At the caps nothing is flagged.
	c := netCollector(newNetClient())
	c.maxRulesPerSG, c.maxRuleNodesPerConn = 3, 3
	b, _ := c.Collect(context.Background())
	if account(b)["rules_truncated"] != nil || group(b)["rules_truncated"] != nil || account(b)["truncated"] != nil {
		t.Fatalf("flags set at the cap: %v %v", account(b), group(b))
	}
	// One below the per-group cap.
	c = netCollector(newNetClient())
	c.maxRulesPerSG = 2
	b, _ = c.Collect(context.Background())
	if group(b)["rules_truncated"] != "true" || group(b)["rules_omitted"] != 1 {
		t.Fatalf("group attrs %v", group(b))
	}
	if len(c.RunStatus().Truncations) != 1 || c.RunStatus().Truncations[0].Omitted != 1 {
		t.Fatalf("truncations %v", c.RunStatus().Truncations)
	}
	// One below the per-connection cap.
	c = netCollector(newNetClient())
	c.maxRuleNodesPerConn = 2
	b, _ = c.Collect(context.Background())
	if account(b)["rules_truncated"] != "true" {
		t.Fatalf("account attrs %v", account(b))
	}
	// A truncated listing.
	nc := newNetClient()
	nc.truncate["eni"] = true
	c = netCollector(nc)
	b, _ = c.Collect(context.Background())
	if account(b)["truncated"] != "true" {
		t.Fatalf("account attrs %v", account(b))
	}
	retained := false
	for _, r := range b.Retain {
		retained = retained || r.Attrs["resource_type"] == "ec2:eni"
	}
	if !retained {
		t.Fatalf("a truncated listing adds no retain rule: %v", b.Retain)
	}
}
