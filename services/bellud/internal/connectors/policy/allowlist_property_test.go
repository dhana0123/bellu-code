package policy

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: cloud-connectors, Property 7: Policy decision equals allowlist membership
// (pure Check part; the broker-level zero-egress and audit assertion is task 4.8).
//
// **Validates: Requirements 3.12, 4.12, 5.1, 5.2, 8.11, 12.4, 16.1, 16.6**

// allowSpec is an independent statement of the testManifest allowlist for the
// eu-west-1 selection: per operation the class, method rule and allowed host.
type allowSpec struct {
	class, host string
	methods     []string // accepted request methods
	paths       []string // nil = any path
}

var allowSpecs = map[string]allowSpec{
	"ec2:DescribeInstances": {class: "read", host: "ec2.eu-west-1.amazonaws.com", methods: []string{"GET", "POST"}},
	"sts:GetCallerIdentity": {class: "auth", host: "sts.amazonaws.com", methods: []string{"GET", "POST"}},
	"GET /repos/{o}/{r}/pulls": {class: "read", host: "api.github.com", methods: []string{"GET"},
		paths: []string{"/repos/o/r/pulls", "/repos/acme/web/pulls", "/repos/o/r/pulls?state=open"}},
	"graphql": {class: "read", host: "api.github.com", methods: []string{"POST"}, paths: []string{"/graphql"}},
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestPropertyPolicyAllowlist(t *testing.T) {
	p, err := Compile(testManifest(), Selection{Regions: []string{"eu-west-1"}})
	if err != nil {
		t.Fatal(err)
	}
	ops := []string{
		"ec2:DescribeInstances", "sts:GetCallerIdentity", "GET /repos/{o}/{r}/pulls", "graphql",
		"", "ec2:RunInstances", "ec2:describeinstances", "iam:CreateUser", "DELETE /repos/{o}/{r}",
	}
	baseHosts := []string{
		"ec2.eu-west-1.amazonaws.com", "ec2.us-east-1.amazonaws.com", "sts.amazonaws.com",
		"api.github.com", "evil.example.com", "api.github.com.evil.com", "10.0.0.1", "127.0.0.1", "",
	}
	paths := []string{
		"", "/", "/graphql", "/graphql/x", "/repos/o/r/pulls", "/repos/acme/web/pulls",
		"/repos/o/r/pulls?state=open", "/repos//r/pulls", "/repos/../r/pulls", "/repos/o/r/issues",
	}

	rapid.Check(t, func(t *rapid.T) {
		op := rapid.SampledFrom(ops).Draw(t, "operation")
		class := rapid.SampledFrom([]string{"read", "auth", "write", "", "READ"}).Draw(t, "class")
		caller := rapid.SampledFrom([]string{CallerCollector, CallerLifecycle, "agent", ""}).Draw(t, "caller")
		method := rapid.SampledFrom([]string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "get", ""}).Draw(t, "method")
		base := rapid.SampledFrom(baseHosts).Draw(t, "host")
		deco := rapid.SampledFrom([]string{"none", "upper", "port", "dot"}).Draw(t, "decoration")
		path := rapid.SampledFrom(paths).Draw(t, "path")
		connector := rapid.SampledFrom([]string{"", "x", "other"}).Draw(t, "connector")

		host := base
		switch deco {
		case "upper":
			host = strings.ToUpper(base)
		case "port":
			host = base + ":443"
		case "dot":
			host = base + "."
		}

		got := p.Check(Request{
			ConnectionID: "c1", ConnectorID: connector, Caller: caller,
			Method: method, Host: host, Path: path, Operation: op, Class: class,
		})

		// Expected decision, derived from the allowlist spec only.
		spec, listed := allowSpecs[op]
		want := listed && connector != "other" && spec.class == class &&
			(class == "read" || (class == "auth" && caller == CallerLifecycle)) &&
			contains(spec.methods, method) &&
			base != "" && base == spec.host &&
			(spec.paths == nil || contains(spec.paths, path))
		// Unlisted-looking decorations never change membership; a bare port
		// or case change of an allowed host stays allowed (covered by want).

		if got.Allow != want {
			t.Fatalf("Allow=%v want %v for op=%q class=%q caller=%q method=%q host=%q path=%q connector=%q (%+v)",
				got.Allow, want, op, class, caller, method, host, path, connector, got)
		}
		if got.Allow && (got.Reason != ReasonOK || got.Violated != "") {
			t.Fatalf("allow decision carries violation: %+v", got)
		}
		if !got.Allow && (got.Reason == ReasonOK || got.Violated == "") {
			t.Fatalf("deny decision lacks reason or violated condition: %+v", got)
		}
		// An operation that cannot be resolved is always denied.
		if !listed && got.Allow {
			t.Fatalf("unresolved operation %q allowed", op)
		}
	})
}
