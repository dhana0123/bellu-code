package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
)

var (
	cidrPool = []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "10.0.0.0/8", "FE80::/10", "fe80::/10", "192.168.0.0/16"}
	protoGen = rapid.SampledFrom([]string{"tcp", "udp", "-1"})
)

// genRules draws security groups sg-0.. and rules among them. Peer groups
// may name a group that was not collected (sg-gone).
func genRules(t *rapid.T, nc *netClient) {
	ng := rapid.IntRange(1, 4).Draw(t, "groups")
	nc.groups = nil
	for i := range ng {
		nc.groups = append(nc.groups, SecurityGroup{ID: fmt.Sprintf("sg-%d", i), Region: "eu-west-1", VPCID: "vpc-1"})
	}
	nc.sgRules = nil
	for range rapid.IntRange(0, 12).Draw(t, "rules") {
		x := SGRule{
			GroupID:   fmt.Sprintf("sg-%d", rapid.IntRange(0, ng-1).Draw(t, "group")),
			Direction: rapid.SampledFrom([]string{"ingress", "egress"}).Draw(t, "dir"),
			Protocol:  protoGen.Draw(t, "proto"),
		}
		if x.Protocol != "-1" {
			x.HasPorts, x.From = true, rapid.IntRange(0, 3).Draw(t, "from")
			x.To = x.From + rapid.IntRange(0, 2).Draw(t, "span")
		}
		switch rapid.IntRange(0, 2).Draw(t, "peer") {
		case 0:
			x.CIDR = rapid.SampledFrom(cidrPool).Draw(t, "cidr")
		case 1:
			x.PeerGroupID = rapid.SampledFrom([]string{"sg-0", "sg-1", "sg-gone"}).Draw(t, "peerSG")
		default:
			x.PrefixListID = "pl-1"
		}
		if rapid.Bool().Draw(t, "providerID") {
			x.ID = fmt.Sprintf("sgr-%d", rapid.IntRange(0, 20).Draw(t, "sgr"))
		}
		nc.sgRules = append(nc.sgRules, x)
	}
}

func entitiesOf(b graph.Batch, kind string) []map[string]any {
	var out []map[string]any
	for _, e := range b.Entities {
		if e.Type == kind {
			out = append(out, e.Attributes)
		}
	}
	return out
}

// distinctRules returns the distinct rule ids per group ARN.
func distinctRules(nc *netClient) (map[string][]string, map[string]SGRule) {
	per, byKey := map[string][]string{}, map[string]SGRule{}
	for _, x := range nc.sgRules {
		g := arnOf("security-group/" + x.GroupID)
		id := RuleID(x)
		if _, ok := byKey[g+"|"+id]; ok {
			continue
		}
		byKey[g+"|"+id] = x
		per[g] = append(per[g], id)
	}
	for g := range per {
		sort.Strings(per[g])
	}
	return per, byKey
}

// Feature: aws-relationship-registry, Property 13: Rule node emission invariants
//
// **Validates: Requirements 8.1, 8.3, 8.5, 8.7**
func TestPropertyRuleNodeEmission(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nc := newNetClient()
		genRules(t, nc)
		b, err := netCollector(nc).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		per, byKey := distinctRules(nc)
		nodes := entitiesOf(b, kindSGRule)
		if len(nodes) != len(byKey) {
			t.Fatalf("%d rule nodes, %d distinct rules", len(nodes), len(byKey))
		}
		collected := map[string]bool{}
		for _, g := range nc.groups {
			collected[g.ID] = true
		}
		wantPeers, cidrs := 0, map[string]bool{}
		for _, x := range byKey {
			switch {
			case x.CIDR != "":
				wantPeers++
				cidrs[strings.ToLower(x.CIDR)] = true
			case collected[x.PeerGroupID]:
				wantPeers++
			}
		}
		for _, n := range nodes {
			cidr, _ := n["cidr"].(string)
			if (n["internet_open"] == "true") != (cidr == "0.0.0.0/0" || cidr == "::/0") {
				t.Fatalf("internet_open %v for cidr %q", n["internet_open"], cidr)
			}
			if !slices.Contains(per[n["sg"].(string)], n["rule_id"].(string)) {
				t.Fatalf("unexpected rule node %v", n)
			}
		}
		rel := relTypes(b)
		if rel["aws_rule_of"] != len(byKey) || rel["aws_rule_peer"] != wantPeers {
			t.Fatalf("rule_of=%d (want %d) rule_peer=%d (want %d)", rel["aws_rule_of"], len(byKey), rel["aws_rule_peer"], wantPeers)
		}
		if got := len(entitiesOf(b, kindCIDR)); got != len(cidrs) {
			t.Fatalf("%d cidr nodes, want %d", got, len(cidrs))
		}
	})
}

// Feature: aws-relationship-registry, Property 14: Caps set truncation flags exactly when exceeded
//
// **Validates: Requirements 8.6, 11.7**
func TestPropertyRuleCaps(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nc := newNetClient()
		genRules(t, nc)
		c := netCollector(nc)
		c.maxRulesPerSG = rapid.IntRange(0, 5).Draw(t, "perSG")
		c.maxRuleNodesPerConn = rapid.IntRange(0, 12).Draw(t, "perConn")
		b, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		per, _ := distinctRules(nc)
		groups := map[string]map[string]any{}
		var acct map[string]any
		for _, e := range b.Entities {
			if e.Type == kindAccount {
				acct = e.Attributes
			}
			if e.Attributes["resource_type"] == "ec2:security-group" {
				groups[e.Identity["arn"]] = e.Attributes
			}
		}
		emitted := map[string][]string{}
		for _, n := range entitiesOf(b, kindSGRule) {
			emitted[n["sg"].(string)] = append(emitted[n["sg"].(string)], n["rule_id"].(string))
		}
		// Groups are emitted in ARN order, so the connection cap cuts the tail.
		gs := make([]string, 0, len(per))
		for g := range per {
			gs = append(gs, g)
		}
		sort.Strings(gs)
		budget, connCut := c.maxRuleNodesPerConn, false
		for _, g := range gs {
			kept := min(len(per[g]), c.maxRulesPerSG)
			over := len(per[g]) > c.maxRulesPerSG
			if (groups[g]["rules_truncated"] == "true") != over {
				t.Fatalf("%s: %d rules, cap %d, rules_truncated=%v", g, len(per[g]), c.maxRulesPerSG, groups[g]["rules_truncated"])
			}
			if over && groups[g]["rules_omitted"] != len(per[g])-c.maxRulesPerSG {
				t.Fatalf("%s: rules_omitted=%v", g, groups[g]["rules_omitted"])
			}
			n := min(kept, max(budget, 0))
			if kept > budget {
				connCut = true
			}
			budget -= kept
			got := emitted[g]
			sort.Strings(got)
			if !slices.Equal(got, per[g][:n]) {
				t.Fatalf("%s: emitted %v, want lowest %v", g, got, per[g][:n])
			}
		}
		if (acct["rules_truncated"] == "true") != connCut {
			t.Fatalf("account rules_truncated=%v, want %v", acct["rules_truncated"], connCut)
		}
	})
}

// Feature: aws-relationship-registry, Property 18: Emitted network relations are well formed
//
// **Validates: Requirements 9.7, 9.8, 9.9, 9.10, 9.11, 9.14, 11.14, 11.15**
func TestPropertyNetworkRelationsWellFormed(t *testing.T) {
	reg, err := schemaall.Default()
	if err != nil {
		t.Fatal(err)
	}
	e := openEngine(t)
	rapid.Check(t, func(t *rapid.T) {
		nc := newNetClient()
		genRules(t, nc)
		active := 0
		for i := range rapid.IntRange(0, 3).Draw(t, "peerings") {
			st := rapid.SampledFrom([]string{"active", "pending-acceptance", "deleted"}).Draw(t, "status")
			if st == "active" {
				active++
			}
			nc.peerings = append(nc.peerings, PeeringConnection{ID: fmt.Sprintf("pcx-%d", i), Region: "eu-west-1",
				Status: st, RequesterVPC: "vpc-1", AccepterVPC: "vpc-2"})
		}
		// Drop a step so some relations lose an endpoint.
		if s := rapid.SampledFrom([]string{"", "subnet", "igw", "security-groups", "eni"}).Draw(t, "fail"); s != "" {
			nc.fail[s] = ErrAccessDenied
		}
		b, err := netCollector(nc).Collect(context.Background())
		var pe collectors.PartialError
		if err != nil && !errors.As(err, &pe) {
			t.Fatal(err)
		}
		typeOf := map[string]string{}
		for _, en := range b.Entities {
			id := entityID(t, en.Type, en.Identity)
			typeOf[id] = en.Type
			if rt, ok := en.Attributes["resource_type"].(string); ok {
				typeOf[id] = rt
				if _, ok := canonical.Key(canonical.KindARN, en.Identity["arn"]); ok && en.Attributes[canonical.AttrCanonicalKey] == nil {
					t.Fatalf("%s has no canonical_key", en.Identity["arn"])
				}
			}
		}
		peers := 0
		for _, r := range b.Relations {
			ft, ok1 := typeOf[r.From]
			tt, ok2 := typeOf[r.To]
			if !ok1 || !ok2 {
				t.Fatalf("%s has an endpoint outside the batch", r.Type)
			}
			d, ok := reg.Relation(r.Type)
			if !ok {
				t.Fatalf("relation %s is not declared", r.Type)
			}
			if !allowed(d.From, ft, typeOf[r.From]) || !allowed(d.To, tt, typeOf[r.To]) {
				t.Fatalf("%s from %s to %s is not allowed by %v -> %v", r.Type, ft, tt, d.From, d.To)
			}
			if r.Type == "aws_peers_with" {
				peers++
			}
		}
		if peers != 2*active {
			t.Fatalf("%d peering relations for %d active peerings", peers, active)
		}
		if _, err := e.Ingest().Apply(context.Background(), b); err != nil {
			t.Fatalf("apply: %v", err)
		}
	})
}

func allowed(decl []string, typ, _ string) bool {
	return len(decl) == 0 || slices.Contains(decl, typ) || (strings.Contains(typ, ":") && slices.Contains(decl, kindResource))
}

// Feature: aws-relationship-registry, Property 19: A failed type keeps its entities and a succeeded type retires
//
// Collector half.
//
// **Validates: Requirements 11.8, 11.9, 11.11, 11.12, 11.13**
func TestPropertyCollectorRetention(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := openEngineR(t)
		nc := newNetClient()
		first, err := netCollector(nc).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Ingest().Apply(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		steps := make([]string, 0, len(collectSteps))
		for _, s := range collectSteps {
			steps = append(steps, s.name)
		}
		failing := rapid.SliceOfNDistinct(rapid.SampledFrom(steps), 0, len(steps), func(s string) string { return s }).Draw(t, "failing")
		for _, s := range failing {
			nc.fail[s] = ErrAccessDenied
		}
		dropInstance := rapid.Bool().Draw(t, "dropInstance")
		if dropInstance {
			nc.instances = nil
		}
		second, err := netCollector(nc).Collect(context.Background())
		var pe collectors.PartialError
		if err != nil && !errors.As(err, &pe) {
			if len(second.Entities) != 0 {
				t.Fatal("a hard error returned a batch")
			}
			return // every step failed
		}
		if _, err := e.Ingest().Apply(context.Background(), second); err != nil {
			t.Fatal(err)
		}
		failed := map[string]bool{}
		for _, s := range pe.Types {
			failed[s] = true
		}
		stepOf := map[string]string{}
		for _, s := range collectSteps {
			for _, typ := range s.types {
				if _, ok := stepOf[typ]; !ok {
					stepOf[typ] = s.name
				}
			}
		}
		for _, en := range first.Entities {
			rt, _ := en.Attributes["resource_type"].(string)
			if rt == "" {
				continue
			}
			id := graph.EntityID(entityID(t, en.Type, en.Identity))
			isLive := liveR(t, e, id)
			gone := dropInstance && rt == "ec2:instance"
			switch {
			case failed[stepOf[rt]] && !isLive:
				t.Fatalf("%s of failed step %s was retired", en.Identity["arn"], stepOf[rt])
			case !failed[stepOf[rt]] && gone && isLive:
				t.Fatalf("%s absent from a successful listing is live", en.Identity["arn"])
			case !failed[stepOf[rt]] && !gone && !isLive:
				t.Fatalf("%s observed again was retired", en.Identity["arn"])
			}
		}
	})
}

func entityID(t interface{ Fatal(...any) }, kind string, idn map[string]string) string {
	id, err := identity.Hash(kind, idn)
	if err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// openEngineR opens a fresh engine for one rapid case and closes it with the
// case.
func openEngineR(t *rapid.T) graph.Engine {
	dir, err := os.MkdirTemp("", "aws-retain-")
	if err != nil {
		t.Fatal(err)
	}
	e, err := graph.Open(context.Background(), graph.Config{
		Enabled: true, Dir: filepath.Join(dir, "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.Close(context.Background())
		os.RemoveAll(dir)
	})
	return e
}

func liveR(t *rapid.T, e graph.Engine, id graph.EntityID) bool {
	_, err := e.Query().Entity(context.Background(), id, nil)
	if err != nil && !errors.Is(err, graph.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}
