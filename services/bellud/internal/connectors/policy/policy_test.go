package policy

import (
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
)

func testManifest() manifest.Manifest {
	return manifest.Manifest{
		ID: "x", Version: "1.0.0", Name: "X",
		AuthMethods: []manifest.AuthMethod{{ID: "a", Name: "A", Enabled: true}},
		Entities:    []string{"thing"},
		Egress:      []string{"ec2.{region}.amazonaws.com", "sts.amazonaws.com", "api.github.com"},
		Operations: []manifest.Operation{
			{Name: "ec2:DescribeInstances", Class: manifest.ClassRead, Host: "ec2.{region}.amazonaws.com"},
			{Name: "sts:GetCallerIdentity", Class: manifest.ClassAuth, Host: "sts.amazonaws.com"},
			{Name: "GET /repos/{o}/{r}/pulls", Class: manifest.ClassRead, Method: "GET", Host: "api.github.com", Path: "/repos/{o}/{r}/pulls"},
			{Name: "graphql", Class: manifest.ClassRead, Method: "POST", Host: "api.github.com", Path: "/graphql", Query: true},
		},
	}
}

func TestCheck(t *testing.T) {
	p, err := Compile(testManifest(), Selection{Regions: []string{"eu-west-1"}})
	if err != nil {
		t.Fatal(err)
	}
	ok := Request{Caller: CallerCollector, Method: "POST", Host: "ec2.eu-west-1.amazonaws.com", Operation: "ec2:DescribeInstances", Class: "read"}
	cases := []struct {
		name string
		mut  func(*Request)
		want Reason
	}{
		{"allowed", func(*Request) {}, ReasonOK},
		{"other region", func(r *Request) { r.Host = "ec2.us-east-1.amazonaws.com" }, ReasonHostBlocked},
		{"ip host", func(r *Request) { r.Host = "169.254.169.254" }, ReasonHostBlocked},
		{"unknown op", func(r *Request) { r.Operation = "ec2:RunInstances" }, ReasonOpNotListed},
		{"empty op", func(r *Request) { r.Operation = "" }, ReasonOpNotListed},
		{"auth by collector", func(r *Request) { r.Operation, r.Class, r.Host = "sts:GetCallerIdentity", "auth", "sts.amazonaws.com" }, ReasonScope},
		{"auth by lifecycle", func(r *Request) {
			r.Operation, r.Class, r.Host, r.Caller = "sts:GetCallerIdentity", "auth", "sts.amazonaws.com", CallerLifecycle
		}, ReasonOK},
		{"delete", func(r *Request) { r.Method = "DELETE" }, ReasonNotReadOnly},
		{"bad class", func(r *Request) { r.Class = "write" }, ReasonNotReadOnly},
		{"rest get", func(r *Request) {
			r.Method, r.Host, r.Operation, r.Path = "GET", "api.github.com", "GET /repos/{o}/{r}/pulls", "/repos/a/b/pulls"
		}, ReasonOK},
		{"rest wrong path", func(r *Request) {
			r.Method, r.Host, r.Operation, r.Path = "GET", "api.github.com", "GET /repos/{o}/{r}/pulls", "/repos/a/b/issues"
		}, ReasonOpNotListed},
		{"rest post on get op", func(r *Request) {
			r.Method, r.Host, r.Operation, r.Path = "POST", "api.github.com", "GET /repos/{o}/{r}/pulls", "/repos/a/b/pulls"
		}, ReasonNotReadOnly},
		{"graphql query", func(r *Request) {
			r.Method, r.Host, r.Operation, r.Path = "POST", "api.github.com", "graphql", "/graphql"
		}, ReasonOK},
	}
	for _, c := range cases {
		r := ok
		c.mut(&r)
		if got := p.Check(r); got.Reason != c.want || got.Allow != (c.want == ReasonOK) {
			t.Errorf("%s: got %+v want %s", c.name, got, c.want)
		}
	}
}

func TestCompileFailsClosed(t *testing.T) {
	if _, err := Compile(testManifest(), Selection{}); err == nil {
		t.Fatal("expected error without region")
	}
	if _, err := Compile(testManifest(), Selection{Regions: []string{"a.b"}}); err == nil {
		t.Fatal("expected error for bad region")
	}
	var nilp *Policy
	if nilp.Check(Request{}).Allow {
		t.Fatal("nil policy must deny")
	}
}

func TestWildcardAndGHES(t *testing.T) {
	m := testManifest()
	m.Egress = []string{"*.example.com", "{host}"}
	m.Operations = []manifest.Operation{{Name: "GET /a", Class: "read", Method: "GET", Host: "{host}", Path: "/a"}}
	p, err := Compile(m, Selection{Host: "ghes.corp.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	r := Request{Caller: "collector", Method: "GET", Host: "GHES.corp.example.com:443", Path: "/a", Operation: "GET /a", Class: "read"}
	if !p.Check(r).Allow {
		t.Fatal("expected allow")
	}
	r.Host = "example.com"
	if p.Check(r).Allow {
		t.Fatal("wildcard must not match apex")
	}
}
