package policy_test

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/github"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
)

// Feature: github-app-signin, Property 17: Device endpoints are reachable only by the lifecycle caller
//
// Pure policy part; the zero-bytes-sent and single-audit-entry assertion
// belongs to the broker.
//
// **Validates: Requirements 8.1, 8.2, 8.4, 8.5**
func TestPropertyDeviceEndpointAllowlist(t *testing.T) {
	p, err := policy.Compile(github.Manifest("Iv1.testclientid"), policy.Selection{Host: "api.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	deviceOps := map[string]string{
		"POST /login/device/code":        "/login/device/code",
		"POST /login/oauth/access_token": "/login/oauth/access_token",
	}
	ops := []string{
		"POST /login/device/code", "POST /login/oauth/access_token", "GET /user",
		"GET /user/installations/{i}/repositories", "POST /graphql", "", "POST /login/oauth/authorize",
		"post /login/device/code",
	}
	callers := []string{"lifecycle", "collector", "agent:p1", "agent:", "", "Lifecycle"}
	classes := []string{"auth", "read", "write", "", "AUTH"}
	methods := []string{"POST", "GET", "PUT", "DELETE", "HEAD", "post", ""}
	hosts := []string{
		"github.com", "GITHUB.COM", "github.com:443", "github.com.", "api.github.com",
		"evil.github.com", "github.com.evil.com", "127.0.0.1", "",
	}
	paths := []string{
		"/login/device/code", "/login/device/code?x=1", "/login/oauth/access_token",
		"/login/device/code/", "/login/device", "/login/oauth/authorize", "/user",
		"/user/installations/7/repositories", "/graphql", "", "/",
	}
	rapid.Check(t, func(t *rapid.T) {
		r := policy.Request{
			ConnectorID: "github",
			Caller:      rapid.SampledFrom(callers).Draw(t, "caller"),
			Class:       rapid.SampledFrom(classes).Draw(t, "class"),
			Method:      rapid.SampledFrom(methods).Draw(t, "method"),
			Host:        rapid.SampledFrom(hosts).Draw(t, "host"),
			Path:        rapid.SampledFrom(paths).Draw(t, "path"),
			Operation:   rapid.SampledFrom(ops).Draw(t, "operation"),
		}
		if strings.HasPrefix(r.Caller, "agent:") {
			r.Agent = &policy.AgentInputs{InScope: true, LiveReads: true}
		}
		h := strings.TrimSuffix(strings.ToLower(r.Host), ".")
		h = strings.TrimSuffix(h, ":443")
		pathOnly, _, _ := strings.Cut(r.Path, "?")
		want := r.Caller == "lifecycle" && r.Class == "auth" && r.Method == "POST" &&
			h == "github.com" && deviceOps[r.Operation] != "" && deviceOps[r.Operation] == pathOnly
		got := p.Check(r).Allow
		if got != want {
			t.Fatalf("Check(%+v).Allow = %v, want %v", r, got, want)
		}
		// Any request to a device path/host or naming a device operation by a
		// non-lifecycle caller is denied.
		if r.Caller != "lifecycle" && (deviceOps[r.Operation] != "" || strings.HasPrefix(pathOnly, "/login/")) && got {
			t.Fatalf("non-lifecycle caller reached device endpoint: %+v", r)
		}
	})
}

// A User_Token request is allowed only for the existing read allowlist,
// including /user/installations/{i}/repositories.
func TestDeviceEndpointReadAllowlistUnchanged(t *testing.T) {
	p, err := policy.Compile(github.Manifest("Iv1.testclientid"), policy.Selection{Host: "api.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	rapid.Check(t, func(t *rapid.T) {
		inst := rapid.StringMatching(`[0-9]{1,10}`).Draw(t, "installation")
		caller := rapid.SampledFrom([]string{"lifecycle", "collector"}).Draw(t, "caller")
		ok := p.Check(policy.Request{ConnectorID: "github", Caller: caller, Class: "read", Method: "GET",
			Host: "api.github.com", Path: "/user/installations/" + inst + "/repositories",
			Operation: "GET /user/installations/{i}/repositories"})
		if !ok.Allow {
			t.Fatalf("installation repositories read denied: %+v", ok)
		}
		// A write method on the same endpoint, or the device host, is denied.
		for _, bad := range []policy.Request{
			{Method: "POST", Host: "api.github.com", Path: "/user/installations/" + inst + "/repositories"},
			{Method: "GET", Host: "github.com", Path: "/user/installations/" + inst + "/repositories"},
		} {
			bad.ConnectorID, bad.Caller, bad.Class = "github", caller, "read"
			bad.Operation = "GET /user/installations/{i}/repositories"
			if p.Check(bad).Allow {
				t.Fatalf("allowed %+v", bad)
			}
		}
	})
}
