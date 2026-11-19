package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// RuleID returns the stable rule_id of a security group rule: the provider
// identifier when present, else "d-" + hex of the first 16 bytes of the
// sha256 of direction|protocol|from|to|peerKind|peerValue joined by NUL. The
// id depends only on the rule's own fields.
func RuleID(r SGRule) string {
	if r.ID != "" {
		return r.ID
	}
	kind, value := "", ""
	switch {
	case r.CIDR != "":
		kind, value = "cidr", strings.ToLower(r.CIDR)
	case r.PeerGroupID != "":
		kind, value = "sg", r.PeerGroupID
	case r.PrefixListID != "":
		kind, value = "prefix_list", r.PrefixListID
	}
	canon := strings.Join([]string{
		r.Direction, r.Protocol, strconv.Itoa(r.From), strconv.Itoa(r.To), kind, value,
	}, "\x00")
	sum := sha256.Sum256([]byte(canon))
	return "d-" + hex.EncodeToString(sum[:16])
}

// internetOpen reports whether the CIDR is exactly 0.0.0.0/0 or ::/0.
func internetOpen(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

// capRules sorts rule ids ascending, keeps the first n and reports how many
// were omitted. The input is not modified; duplicates are kept as given.
func capRules(ids []string, n int) (kept []string, omitted int) {
	if n < 0 {
		n = 0
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	if len(sorted) <= n {
		return sorted, 0
	}
	return sorted[:n], len(sorted) - n
}
