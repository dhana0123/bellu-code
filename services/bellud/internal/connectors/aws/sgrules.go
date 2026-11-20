package aws

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// This file collects security group rules as Rule_Nodes (aws_sg_rule), each
// linked to its group and to its peer: a shared aws_cidr node or the peer
// security group when it was collected.

const maxRuleDescription = 1024

func (r *run) sgRulesStep(ctx context.Context, rg string) error {
	l, err := r.c.client.SGRules(ctx, rg)
	r.truncate("sg-rules", rg, l.Truncated)
	byGroup := map[string][]SGRule{}
	for _, x := range l.Items {
		byGroup[x.GroupID] = append(byGroup[x.GroupID], x)
	}
	r.sgRules[rg] = byGroup
	groups := make([]string, 0, len(byGroup))
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		r.emitGroupRules(rg, g, byGroup[g])
	}
	return err
}

// emitGroupRules emits the distinct rules of one group, sorted by rule_id and
// cut at the per-group and per-connection caps.
func (r *run) emitGroupRules(rg, groupID string, rules []SGRule) {
	sgARN := r.sgARN(rg, groupID)
	byID := map[string]SGRule{}
	ids := make([]string, 0, len(rules))
	for _, x := range rules {
		id := RuleID(x)
		if _, dup := byID[id]; !dup {
			byID[id] = x
			ids = append(ids, id)
		}
	}
	kept, omitted := capRules(ids, r.c.maxRulesPerSG)
	if omitted > 0 {
		if a := r.b.attrs[sgARN]; a != nil {
			a["rules_truncated"] = "true"
			a["rules_omitted"] = omitted
		}
		r.truncatedGroups[sgARN] = true
		r.c.status.Truncate("rules@"+sgARN, omitted)
	}
	for i, id := range kept {
		if r.ruleNodes >= r.c.maxRuleNodesPerConn {
			r.b.attrs[r.accountKey()]["rules_truncated"] = "true"
			r.truncatedGroups[sgARN] = true
			r.c.status.Truncate("rules@connection", len(kept)-i)
			return
		}
		r.ruleNodes++
		r.emitRule(rg, sgARN, id, byID[id])
	}
}

func (r *run) emitRule(rg, sgARN, id string, x SGRule) {
	attrs := map[string]any{
		"connection": r.c.connID, "sg": sgARN, "rule_id": id, "source": r.b.source, "region": rg,
		"direction": x.Direction, "protocol": x.Protocol, "internet_open": strconv.FormatBool(internetOpen(x.CIDR)),
		"name": ruleLabel(x),
	}
	if x.HasPorts {
		attrs["from_port"], attrs["to_port"] = x.From, x.To
	}
	switch {
	case x.CIDR != "":
		attrs["cidr"] = strings.ToLower(x.CIDR)
	case x.PeerGroupID != "":
		attrs["peer_sg"] = x.PeerGroupID
	case x.PrefixListID != "":
		attrs["prefix_list"] = x.PrefixListID
	}
	if x.Description != "" {
		attrs["description"] = cutRunes(x.Description, maxRuleDescription)
	}
	key := "rule|" + sgARN + "|" + id
	if !r.b.node(kindSGRule, key, map[string]string{"connection": r.c.connID, "sg": sgARN, "rule_id": id}, attrs) {
		return
	}
	r.b.rel("aws_rule_of", key, sgARN, nil)
	switch {
	case x.CIDR != "":
		c := strings.ToLower(x.CIDR)
		ck := "cidr|" + c
		r.b.node(kindCIDR, ck, map[string]string{"connection": r.c.connID, "cidr": c}, map[string]any{
			"connection": r.c.connID, "cidr": c, "source": r.b.source, "internet_open": strconv.FormatBool(internetOpen(c)),
		})
		r.b.rel("aws_rule_peer", key, ck, nil)
	case x.PeerGroupID != "":
		// Resolved only when the peer group was collected (Req 9.14).
		r.b.rel("aws_rule_peer", key, r.sgARN(rg, x.PeerGroupID), nil)
	}
}

// ruleLabel is the display name, for example "ingress tcp 443-443 0.0.0.0/0".
func ruleLabel(x SGRule) string {
	parts := []string{x.Direction, x.Protocol}
	if x.HasPorts {
		parts = append(parts, strconv.Itoa(x.From)+"-"+strconv.Itoa(x.To))
	}
	switch {
	case x.CIDR != "":
		parts = append(parts, strings.ToLower(x.CIDR))
	case x.PeerGroupID != "":
		parts = append(parts, x.PeerGroupID)
	case x.PrefixListID != "":
		parts = append(parts, x.PrefixListID)
	}
	return strings.Join(parts, " ")
}

func cutRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// node adds a non-resource entity once under key. It reports false when the
// identity does not hash.
func (b *builder) node(kind, key string, idn map[string]string, attrs map[string]any) bool {
	if _, ok := b.seen[key]; ok {
		return true
	}
	id, err := identity.Hash(kind, idn)
	if err != nil {
		return false
	}
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: kind, Identity: idn, Attributes: attrs})
	b.seen[key] = string(id)
	b.attrs[key] = attrs
	return true
}
