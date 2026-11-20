package aws

import (
	"testing"

	"pgregory.net/rapid"
)

func genTri() *rapid.Generator[Tri] { return rapid.SampledFrom([]Tri{No, Yes, Unknown}) }

// Feature: aws-relationship-registry, Property 15: Exposure follows the truth table
//
// **Validates: Requirements 3.3, 9.3, 9.4, 9.6, 9.12, 9.13, 16.8**
func TestPropertyExposureTruthTable(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := ExposureInput{
			Address: genTri().Draw(t, "a"), Ingress: genTri().Draw(t, "b"),
			Route: genTri().Draw(t, "c"), NACL: genTri().Draw(t, "d"),
			RouteDerived: rapid.Bool().Draw(t, "derived"),
		}
		if rapid.Bool().Draw(t, "failed") {
			in.FailedCalls = []string{"ec2:DescribeRouteTables"}
		}
		got := Evaluate(in)
		all := in.Address == Yes && in.Ingress == Yes && in.Route == Yes && in.NACL == Yes
		if (got.State == "true") != all {
			t.Fatalf("state %s for %+v, all four hold=%v", got.State, in, all)
		}
		anyNo := in.Address == No || in.Ingress == No
		unknownFirst := !anyNo && (in.Address == Unknown || in.Ingress == Unknown)
		var want string
		switch {
		case anyNo, !unknownFirst && in.Route == No:
			want = "false"
		case all:
			want = "true"
		default:
			want = "partial"
		}
		if got.State != want {
			t.Fatalf("state %s, want %s for %+v", got.State, want, in)
		}
		if (got.State == "partial") != (got.Reason != "") {
			t.Fatalf("reason %q does not match state %s", got.Reason, got.State)
		}
		if got.Confidence != "extracted" && got.Confidence != "inferred" {
			t.Fatalf("confidence %q", got.Confidence)
		}
	})
}

func TestExposureBoundaries(t *testing.T) {
	yes := ExposureInput{Address: Yes, Ingress: Yes, Route: Yes, NACL: Yes}
	cases := []struct {
		name   string
		mod    func(*ExposureInput)
		state  string
		reason string
		conf   string
	}{
		{"all hold", func(*ExposureInput) {}, "true", "", "extracted"},
		{"derived route", func(i *ExposureInput) { i.RouteDerived = true }, "true", "", "inferred"},
		{"no address", func(i *ExposureInput) { i.Address = No; i.Route = Unknown }, "false", "", "extracted"},
		{"unknown ingress", func(i *ExposureInput) { i.Ingress = Unknown }, "partial", "call-failed", "inferred"},
		{"no route", func(i *ExposureInput) { i.Route = No }, "false", "", "extracted"},
		{"unknown route", func(i *ExposureInput) { i.Route = Unknown }, "partial", "route-unknown", "inferred"},
		{"route call failed", func(i *ExposureInput) { i.Route = Unknown; i.FailedCalls = []string{"x"} }, "partial", "call-failed", "inferred"},
		{"nacl unknown", func(i *ExposureInput) { i.NACL = Unknown }, "partial", "nacl-unknown", "inferred"},
		{"nacl denies", func(i *ExposureInput) { i.NACL = No }, "partial", "nacl-denies", "extracted"},
	}
	for _, c := range cases {
		in := yes
		c.mod(&in)
		got := Evaluate(in)
		if got.State != c.state || got.Reason != c.reason || got.Confidence != c.conf {
			t.Errorf("%s: got %+v, want state=%s reason=%q conf=%s", c.name, got, c.state, c.reason, c.conf)
		}
	}
}
