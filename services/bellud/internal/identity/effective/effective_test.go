package effective

import "testing"

func TestEvaluate(t *testing.T) {
	allow := Policy{{Actions: []string{"s3:*"}, Resources: []string{"*"}}}
	allowUnk := Policy{{Actions: []string{"s3:*"}, Resources: []string{"*"}, Condition: CondUnknown, ConditionKeys: []string{"aws:SourceIp"}}}
	denyS3 := Policy{{Deny: true, Actions: []string{"s3:Delete*"}, Resources: []string{"*"}}}
	ec2 := Policy{{Actions: []string{"ec2:*"}, Resources: []string{"*"}}}
	denyUnk := Policy{{Deny: true, Actions: []string{"s3:*"}, Resources: []string{"*"}, Condition: CondUnknown, ConditionKeys: []string{"aws:MFA"}}}
	cases := []struct {
		name string
		in   Inputs
		act  string
		want Decision
	}{
		{"allow", Inputs{Identity: []Policy{allow}}, "s3:GetObject", Allow},
		{"implicit deny", Inputs{Identity: []Policy{allow}}, "ec2:Run", Deny},
		{"explicit deny", Inputs{Identity: []Policy{allow, denyS3}}, "s3:DeleteObject", Deny},
		{"unknown allow", Inputs{Identity: []Policy{allowUnk}}, "s3:Get", Unknown},
		{"unknown deny with allow", Inputs{Identity: []Policy{allow, denyUnk}}, "s3:Get", Unknown},
		{"boundary denies", Inputs{Identity: []Policy{allow}, Boundary: &ec2}, "s3:Get", Deny},
		{"boundary allows", Inputs{Identity: []Policy{allow}, Boundary: &allow}, "s3:Get", Allow},
		{"scp denies", Inputs{Identity: []Policy{allow}, SCPs: []Policy{allow, ec2}}, "s3:Get", Deny},
		{"scp unknown", Inputs{Identity: []Policy{allow}, SCPs: []Policy{allowUnk}}, "s3:Get", Unknown},
		{"unknown then deny wins", Inputs{Identity: []Policy{allowUnk}, Boundary: &ec2}, "s3:Get", Deny},
		{"uncollected scp skipped", Inputs{Identity: []Policy{allow}}, "s3:Get", Allow},
	}
	for _, c := range cases {
		if got := Evaluate(c.in, c.act, "arn:aws:s3:::b/k"); got.Decision != c.want {
			t.Errorf("%s: got %s want %s", c.name, got.Decision, c.want)
		}
	}
	r := Evaluate(Inputs{Identity: []Policy{allowUnk}}, "s3:Get", "x")
	if len(r.UnknownConditions) != 1 || r.UnknownConditions[0] != "aws:SourceIp" {
		t.Errorf("keys: %v", r.UnknownConditions)
	}
}
