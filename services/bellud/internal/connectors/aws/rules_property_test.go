package aws

import (
	"testing"

	"pgregory.net/rapid"
)

func genSGRule() *rapid.Generator[SGRule] {
	return rapid.Custom(func(t *rapid.T) SGRule {
		r := SGRule{
			Direction: rapid.SampledFrom([]string{"ingress", "egress"}).Draw(t, "dir"),
			Protocol:  rapid.SampledFrom([]string{"tcp", "udp", "icmp", "-1"}).Draw(t, "proto"),
			From:      rapid.IntRange(0, 100).Draw(t, "from"),
			To:        rapid.IntRange(100, 200).Draw(t, "to"),
		}
		switch rapid.IntRange(0, 2).Draw(t, "peer") {
		case 0:
			r.CIDR = rapid.SampledFrom([]string{"0.0.0.0/0", "10.0.0.0/8", "::/0", "FE80::/10"}).Draw(t, "cidr")
		case 1:
			r.PeerGroupID = rapid.SampledFrom([]string{"sg-a", "sg-b"}).Draw(t, "sg")
		default:
			r.PrefixListID = rapid.SampledFrom([]string{"pl-a", "pl-b"}).Draw(t, "pl")
		}
		return r
	})
}

// Feature: aws-relationship-registry, Property 12: Rule identity is deterministic and distinguishing
//
// **Validates: Requirements 8.2, 8.4, 16.7**
func TestPropertyRuleIdentity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSGRule().Draw(t, "a"), genSGRule().Draw(t, "b")
		if RuleID(a) != RuleID(a) {
			t.Fatal("RuleID is not deterministic")
		}
		// The group and description are not part of the identity.
		c := a
		c.GroupID, c.Description = "sg-other", "text"
		if RuleID(a) != RuleID(c) {
			t.Fatal("RuleID depends on group or description")
		}
		if RuleID(a) == RuleID(b) && !sameIdentity(a, b) {
			t.Fatalf("different rules share an id: %+v %+v", a, b)
		}
		if sameIdentity(a, b) && RuleID(a) != RuleID(b) {
			t.Fatalf("equal rules have different ids: %+v %+v", a, b)
		}
		a.ID = "sgr-123"
		if RuleID(a) != "sgr-123" {
			t.Fatal("provider id must win")
		}
	})
}

func sameIdentity(a, b SGRule) bool {
	lower := func(s string) string { return RuleID(SGRule{CIDR: s}) }
	return a.Direction == b.Direction && a.Protocol == b.Protocol && a.From == b.From && a.To == b.To &&
		a.PeerGroupID == b.PeerGroupID && a.PrefixListID == b.PrefixListID && lower(a.CIDR) == lower(b.CIDR)
}
