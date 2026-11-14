package github

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

func TestManifestValidAndOrdered(t *testing.T) {
	m := Manifest("")
	if errs := manifest.Validate(m); len(errs) > 0 {
		t.Fatalf("invalid manifest: %v", errs)
	}
	if len(m.AuthMethods) != 1 || m.AuthMethods[0].ID != MethodPAT {
		t.Errorf("empty client id must list the PAT method only: %v", m.AuthMethods)
	}
	dm := Manifest("Iv1.abc")
	if errs := manifest.Validate(dm); len(errs) > 0 {
		t.Fatalf("invalid device manifest: %v", errs)
	}
	if len(dm.AuthMethods) != 2 || dm.AuthMethods[0].ID != MethodDevice || dm.AuthMethods[0].Device.ClientID != "Iv1.abc" {
		t.Errorf("device method: %v", dm.AuthMethods)
	}
	if got := EffectiveClientID(func(string) string { return "  Iv1.x " }); got != "Iv1.x" {
		t.Errorf("override: %q", got)
	}
	if got := EffectiveClientID(func(string) string { return " " }); got != ClientID {
		t.Errorf("fallback: %q", got)
	}
	var strip, userRepos, install bool
	for _, op := range m.Operations {
		strip = strip || (strings.HasSuffix(op.Name, "secret-scanning/alerts") && len(op.StripKeys) == 1 && op.StripKeys[0] == "secret")
		userRepos = userRepos || op.Name == "GET /user/repos"
		install = install || op.Name == "GET /installation/repositories"
	}
	if !strip || !userRepos || !install {
		t.Errorf("missing operations strip=%v user/repos=%v installation=%v", strip, userRepos, install)
	}
}

func check(p *policy.Policy, method, host, path, op string) bool {
	return p.Check(policy.Request{Method: method, Host: host, Path: path, Operation: op,
		Class: manifest.ClassRead, Caller: policy.CallerCollector}).Allow
}

func TestPolicyHosts(t *testing.T) {
	pr := NewProvider(ProviderConfig{HostFor: func(c store.Connection) string { return c.Alias }})
	for _, tc := range []struct {
		alias, host, base string
		okHost, badHost   string
	}{
		{"", "api.github.com", "", "api.github.com", "ghe.example.com"},
		{"ghe.example.com", "ghe.example.com", "/api/v3", "ghe.example.com", "api.github.com"},
	} {
		conn := store.Connection{Alias: tc.alias}
		d := pr.Describe(conn)
		if d.APIHost != tc.host || d.BasePath != tc.base || d.Auth != broker.AuthGitHubToken {
			t.Fatalf("describe %+v", d)
		}
		pol, err := policy.Compile(Manifest(""), policy.Selection{Host: d.Host})
		if err != nil {
			t.Fatal(err)
		}
		if !check(pol, "GET", tc.okHost, "/repos/o/r/pulls", "GET /repos/{o}/{r}/pulls") {
			t.Error("read on configured host denied")
		}
		if check(pol, "GET", tc.badHost, "/repos/o/r/pulls", "GET /repos/{o}/{r}/pulls") {
			t.Error("other host allowed")
		}
		if check(pol, "DELETE", tc.okHost, "/repos/o/r", "GET /repos/{o}/{r}") {
			t.Error("write allowed")
		}
	}
}

func TestInvalidGHESHostFallsBack(t *testing.T) {
	pr := NewProvider(ProviderConfig{HostFor: func(store.Connection) string { return "169.254.169.254" }})
	if h := pr.Describe(store.Connection{}).APIHost; h != DefaultAPIHost {
		t.Errorf("host %q", h)
	}
}

func TestValidateHost(t *testing.T) {
	for h, ok := range map[string]bool{
		"ghe.example.com": true, "github.internal.corp": true,
		"": false, "localhost": false, "10.0.0.1": false, "ghe.example.com:8443": false,
		"https://ghe.example.com": false, "ghe.example.com/x": false, "{host}": false, "Ghe.Example.com": false,
	} {
		if (ValidateHost(h) == nil) != ok {
			t.Errorf("%q: ok=%v", h, ok)
		}
	}
}

func TestValidateSelection(t *testing.T) {
	if ValidateSelection(nil) == nil || ValidateSelection([]string{"noslash"}) == nil || ValidateSelection([]string{"a/b/c"}) == nil {
		t.Error("invalid selections accepted")
	}
	if err := ValidateSelection([]string{"o/r", "o/r2"}); err != nil {
		t.Error(err)
	}
}

func TestValidateCredentialRejectsClassic(t *testing.T) {
	p := NewProvider(ProviderConfig{})
	if err := p.ValidateCredential([]byte("github_pat_abc")); err != nil {
		t.Error(err)
	}
	err := p.ValidateCredential([]byte("ghp_secretvalue"))
	var le *lifecycle.Error
	if !errors.As(err, &le) || le.Code != lifecycle.CodeValidationFailed || strings.Contains(le.Message, "ghp_") {
		t.Fatalf("err=%v", err)
	}
}

func TestIsGraphQLQuery(t *testing.T) {
	for q, ok := range map[string]bool{
		`{ viewer { login } }`:                                true,
		`query Q { viewer { login } }`:                        true,
		`mutation { addStar(input:{}) { clientMutationId } }`: false,
		`subscription { x }`:                                  false,
		`query A { a } mutation B { b }`:                      false,
		`not graphql {`:                                       false,
		``:                                                    false,
	} {
		if IsGraphQLQuery(q) != ok {
			t.Errorf("%q: want %v", q, ok)
		}
	}
}

func TestVerifyAndPermissions(t *testing.T) {
	rt := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
		switch r.URL.Path {
		case "/user":
			h := http.Header{}
			h.Set(TokenExpiryHeader, "2030-01-02 03:04:05 UTC")
			return 200, `{"login":"octo"}`, h
		case "/user/repos":
			return 200, `[{"full_name":"octo/a"}]`, nil
		}
		return 404, `{}`, nil
	}}
	p := NewProvider(ProviderConfig{})
	call := lifecycle.Call{Client: &http.Client{Transport: rt}}
	id, err := p.Verify(context.Background(), call)
	if err != nil || id.AccountLabel != "octo" || !id.ExpiresAt.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("id=%+v err=%v", id, err)
	}
	rep, err := p.CheckPermissions(context.Background(), call)
	if err != nil || !rep.Unverifiable || len(rep.WriteOffenders) != 0 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
	repos, err := p.Repositories(context.Background(), call)
	if err != nil || len(repos) != 1 {
		t.Fatalf("repos=%v err=%v", repos, err)
	}
}

func TestVerifyErrorMapping(t *testing.T) {
	for status, code := range map[int]lifecycle.Code{
		401: lifecycle.CodeInvalidCredential, 403: lifecycle.CodeInsufficientPermission, 429: lifecycle.CodeRateLimited,
	} {
		rt := &countingRT{routes: func(*http.Request) (int, string, http.Header) { return status, `{}`, nil }}
		_, err := NewProvider(ProviderConfig{}).Verify(context.Background(), lifecycle.Call{Client: &http.Client{Transport: rt}})
		var le *lifecycle.Error
		if !errors.As(err, &le) || le.Code != code {
			t.Errorf("status %d: %v", status, err)
		}
	}
}

func TestCollectorName(t *testing.T) {
	c := NewProvider(ProviderConfig{}).Collector(store.Connection{ID: "c1", IntervalSec: 60}, broker.ConnectionRef{})
	if c.Name() != "connector:github:c1" || c.Interval() != time.Minute {
		t.Errorf("%s %v", c.Name(), c.Interval())
	}
}

func TestProviderImplementsCredentialValidator(t *testing.T) {
	var _ lifecycle.CredentialValidator = (*Provider)(nil)
}

func TestIsGraphQLRequestBody(t *testing.T) {
	for body, want := range map[string]bool{
		`{"query":"query { viewer { login } }"}`: true,
		`{"query":"mutation { x }"}`:             false,
		`[{"query":"mutation { x }"}]`:           false,
		`not json`:                               false,
		`{}`:                                     false,
	} {
		if IsGraphQLRequestBody([]byte(body)) != want {
			t.Errorf("%s: want %v", body, want)
		}
	}
}

func TestValidateCredentialFor(t *testing.T) {
	p := NewProvider(ProviderConfig{})
	cases := []struct {
		method, secret string
		ok             bool
	}{
		{"pat", "github_pat_abc", true},
		{"pat", "ghu_abc", false},
		{"device", "ghu_abc", true},
		{"device", "github_pat_abc", false},
		{"device", "ghu_a bc", false},
		{"device", "ghu_abc\n", false},
		{"device", "ghu_", false},
		{"app", "ghu_abc", false},
	}
	for _, c := range cases {
		err := p.ValidateCredentialFor(c.method, []byte(c.secret))
		if (err == nil) != c.ok {
			t.Errorf("%s %q: err=%v", c.method, c.secret, err)
		}
	}
}
