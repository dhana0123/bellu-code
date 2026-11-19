package aws

import (
	"reflect"
	"testing"
)

func TestRuleID(t *testing.T) {
	if got := RuleID(SGRule{ID: "sgr-1", CIDR: "10.0.0.0/8"}); got != "sgr-1" {
		t.Fatalf("provider id: %q", got)
	}
	a := SGRule{Direction: "ingress", Protocol: "tcp", From: 443, To: 443, CIDR: "10.0.0.0/8"}
	id := RuleID(a)
	if len(id) != 2+32 || id[:2] != "d-" {
		t.Fatalf("derived id shape: %q", id)
	}
	b := a
	b.CIDR = "10.0.0.0/8"
	b.Description = "ignored"
	if RuleID(b) != id {
		t.Fatal("description must not affect id")
	}
	c := a
	c.To = 444
	if RuleID(c) == id {
		t.Fatal("port change must change id")
	}
	d := SGRule{Direction: "ingress", Protocol: "tcp", From: 1, To: 1, CIDR: "ABCD::/16"}
	e := d
	e.CIDR = "abcd::/16"
	if RuleID(d) != RuleID(e) {
		t.Fatal("cidr must be lowercased")
	}
}

func TestInternetOpen(t *testing.T) {
	for cidr, want := range map[string]bool{
		"0.0.0.0/0": true, "::/0": true, "0.0.0.0/1": false, "10.0.0.0/8": false, "": false,
	} {
		if internetOpen(cidr) != want {
			t.Errorf("%q want %v", cidr, want)
		}
	}
}

func TestCapRules(t *testing.T) {
	in := []string{"c", "a", "d", "b"}
	kept, omitted := capRules(in, 2)
	if !reflect.DeepEqual(kept, []string{"a", "b"}) || omitted != 2 {
		t.Fatalf("got %v %d", kept, omitted)
	}
	if !reflect.DeepEqual(in, []string{"c", "a", "d", "b"}) {
		t.Fatal("input modified")
	}
	kept, omitted = capRules(in, 4)
	if len(kept) != 4 || omitted != 0 {
		t.Fatalf("got %v %d", kept, omitted)
	}
}
