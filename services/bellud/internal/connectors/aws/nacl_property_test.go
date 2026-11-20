package aws

import (
	"slices"
	"sort"
	"testing"

	"pgregory.net/rapid"
)

func genRule() *rapid.Generator[OpenRule] {
	return rapid.Custom(func(t *rapid.T) OpenRule {
		from := rapid.IntRange(0, 65000).Draw(t, "from")
		return OpenRule{ID: "r", Protocol: "tcp", From: from, To: from + rapid.IntRange(0, 500).Draw(t, "span")}
	})
}

func genEntries() *rapid.Generator[[]NACLEntry] {
	return rapid.SliceOfN(rapid.Custom(func(t *rapid.T) NACLEntry {
		from := rapid.IntRange(0, 65000).Draw(t, "ef")
		return NACLEntry{
			Number: rapid.IntRange(1, 40).Draw(t, "num"), Allow: rapid.Bool().Draw(t, "allow"),
			Protocol: rapid.SampledFrom([]string{"-1", "tcp", "udp"}).Draw(t, "proto"),
			CIDR:     rapid.SampledFrom([]string{"0.0.0.0/0", "::/0", "10.0.0.0/8"}).Draw(t, "cidr"),
			From:     from, To: from + rapid.IntRange(0, 2000).Draw(t, "espan"),
			AllPorts: rapid.Bool().Draw(t, "all"),
		}
	}), 0, 8)
}

// Feature: aws-relationship-registry, Property 16: NACL evaluation uses the first matching entry
//
// **Validates: Requirements 9.5**
func TestPropertyNACLFirstMatch(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		entries, r := genEntries().Draw(t, "entries"), genRule().Draw(t, "rule")
		got := NACLAllows(entries, r)
		// Order of input is irrelevant for distinct numbers.
		seen := map[int]bool{}
		distinct := true
		for _, e := range entries {
			distinct = distinct && !seen[e.Number]
			seen[e.Number] = true
		}
		if distinct {
			rev := slices.Clone(entries)
			slices.Reverse(rev)
			if NACLAllows(rev, r) != got {
				t.Fatalf("result depends on input order: %v", entries)
			}
		}
		// Oracle: walk by ascending number.
		sorted := slices.Clone(entries)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Number < sorted[j].Number })
		want := No
		for _, e := range sorted {
			if e.CIDR == "10.0.0.0/8" {
				continue
			}
			if e.Protocol != "-1" && e.Protocol != "tcp" {
				continue
			}
			ef, et := e.From, e.To
			if e.AllPorts || e.Protocol == "-1" {
				ef, et = 0, 65535
			}
			if ef <= r.From && r.To <= et {
				want = allowTri(e.Allow)
				break
			}
			if ef <= r.To && r.From <= et {
				want = Unknown
				break
			}
		}
		if got != want {
			t.Fatalf("got %v want %v for rule %+v entries %+v", got, want, r, entries)
		}
	})
}

func TestNACLImplicitDeny(t *testing.T) {
	if got := NACLAllows(nil, OpenRule{Protocol: "tcp", From: 22, To: 22}); got != No {
		t.Fatalf("empty ACL = %v, want No", got)
	}
	e := []NACLEntry{{Number: 100, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0", AllPorts: true}}
	if got := NACLAllows(e, OpenRule{Protocol: "tcp", From: 22, To: 22}); got != Yes {
		t.Fatalf("allow-all = %v, want Yes", got)
	}
}

// Feature: aws-relationship-registry, Property 17: Exposure evidence and confidence
//
// **Validates: Requirements 9.3, 9.6, 9.13**
func TestPropertyExposureEvidence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := rapid.SliceOfN(rapid.StringMatching(`sgr-[a-f0-9]{4}`), 1, 4).Draw(t, "ids")
		var open []OpenRule
		for _, id := range rules {
			open = append(open, OpenRule{ID: id, Protocol: "tcp", From: 443, To: 443})
		}
		derived := rapid.Bool().Draw(t, "derived")
		in := ExposureInput{
			Address: Yes, AddressFact: "eip:1.2.3.4", Ingress: Yes, OpenRules: open,
			Route: Yes, RouteFact: "rtb-1 0.0.0.0/0 -> igw-2", RouteDerived: derived,
			NACLKnown: true, NACLID: "acl-1", NACLEntries: []NACLEntry{{Number: 100, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0", AllPorts: true}},
		}
		got := Evaluate(in)
		if got.State != "true" {
			t.Fatalf("state %s", got.State)
		}
		wantConf := "extracted"
		if derived {
			wantConf = "inferred"
		}
		if got.Confidence != wantConf {
			t.Fatalf("confidence %s, want %s", got.Confidence, wantConf)
		}
		if !sort.StringsAreSorted(got.Evidence) || len(slices.Compact(slices.Clone(got.Evidence))) != len(got.Evidence) {
			t.Fatalf("evidence not sorted and unique: %v", got.Evidence)
		}
		for _, want := range []string{"eip:1.2.3.4", "rtb-1 0.0.0.0/0 -> igw-2", "acl:acl-1#100 allow"} {
			if !slices.Contains(got.Evidence, want) {
				t.Fatalf("evidence %v lacks %q", got.Evidence, want)
			}
		}
		for _, id := range rules {
			if !slices.Contains(got.Evidence, "sg-rule:"+id) {
				t.Fatalf("evidence %v lacks rule %s", got.Evidence, id)
			}
		}
		// Denying ACL gives partial with the deny entry as evidence.
		in.NACLEntries = []NACLEntry{{Number: 100, Allow: false, Protocol: "-1", CIDR: "0.0.0.0/0", AllPorts: true}}
		d := Evaluate(in)
		if d.State != "partial" || d.Reason != "nacl-denies" || !slices.Contains(d.Evidence, "acl:acl-1#100 deny") {
			t.Fatalf("deny result %+v", d)
		}
	})
}
