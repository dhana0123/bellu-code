package aws

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 5: Internet exposure follows security group rules and public address
//
// **Validates: Requirements 3.3**
func TestPropertyInternetExposure(t *testing.T) {
	v4 := rapid.SampledFrom([]string{"0.0.0.0/0", "10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/1", "203.0.113.7/32"})
	v6 := rapid.SampledFrom([]string{"::/0", "fe80::/10", "2001:db8::/32", "::/1"})

	type genGroup struct {
		sg   SecurityGroup
		open bool // oracle: some rule allows 0.0.0.0/0 or ::/0
	}

	rapid.Check(t, func(t *rapid.T) {
		nGroups := rapid.IntRange(0, 6).Draw(t, "groups")
		var groups []SecurityGroup
		var gens []genGroup
		for i := 0; i < nGroups; i++ {
			nPerms := rapid.IntRange(0, 3).Draw(t, "perms")
			var perms []ec2types.IpPermission
			open := false
			for j := 0; j < nPerms; j++ {
				var p ec2types.IpPermission
				for _, c := range rapid.SliceOfN(v4, 0, 3).Draw(t, "v4") {
					p.IpRanges = append(p.IpRanges, ec2types.IpRange{CidrIp: awssdk.String(c)})
					open = open || c == "0.0.0.0/0"
				}
				for _, c := range rapid.SliceOfN(v6, 0, 3).Draw(t, "v6") {
					p.Ipv6Ranges = append(p.Ipv6Ranges, ec2types.Ipv6Range{CidrIpv6: awssdk.String(c)})
					open = open || c == "::/0"
				}
				perms = append(perms, p)
			}
			g := SecurityGroup{ID: "sg-" + string(rune('a'+i)), OpenToInternet: openIngress(perms)}
			if g.OpenToInternet != open {
				t.Fatalf("openIngress=%v, want %v for %+v", g.OpenToInternet, open, perms)
			}
			groups = append(groups, g)
			gens = append(gens, genGroup{g, open})
		}

		// Attach a random subset of the known groups plus possibly unknown ids.
		var attached []string
		want := false
		hasIP := rapid.Bool().Draw(t, "hasPublicIP")
		for _, g := range gens {
			if rapid.Bool().Draw(t, "attach") {
				attached = append(attached, g.sg.ID)
				want = want || g.open
			}
		}
		if rapid.Bool().Draw(t, "unknownAttached") {
			attached = append(attached, "sg-unknown")
		}
		inst := Instance{ID: "i-1", SecurityGroupIDs: attached}
		if hasIP {
			inst.PublicIP = "203.0.113.10"
		}
		want = want && hasIP

		if got := exposed(inst, groups); got != want {
			t.Fatalf("exposed=%v, want %v (publicIP=%q attached=%v groups=%+v)",
				got, want, inst.PublicIP, attached, groups)
		}
	})
}
