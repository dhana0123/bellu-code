package mcptoken_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
)

func req(h func(*http.Request)) *http.Request {
	r := httptest.NewRequest("POST", mcptoken.Path, nil)
	if h != nil {
		h(r)
	}
	return r
}

func TestVerify(t *testing.T) {
	tok, err := mcptoken.New()
	if err != nil {
		t.Fatal(err)
	}
	a := auth.New("pw")
	session, _ := a.IssueSession(time.Now())
	cases := []struct {
		name string
		set  func(*http.Request)
		want bool
	}{
		{"right token", func(r *http.Request) { r.Header.Set("Authorization", tok.Header()) }, true},
		{"none", nil, false},
		{"wrong token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") }, false},
		{"password basic", func(r *http.Request) { r.SetBasicAuth(auth.Username, "pw") }, false},
		{"session basic", func(r *http.Request) { r.SetBasicAuth(auth.Username, session) }, false},
		{"token as basic password", func(r *http.Request) { r.SetBasicAuth(auth.Username, tok.String()) }, false},
		{"password as bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer pw") }, false},
	}
	for _, c := range cases {
		if got := tok.Verify(req(c.set)); got != c.want {
			t.Errorf("%s: Verify=%v want %v", c.name, got, c.want)
		}
	}
}

func TestZeroTokenRejectsEverything(t *testing.T) {
	var z mcptoken.Token
	if z.Verify(req(func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") })) {
		t.Fatal("zero token accepted")
	}
}

func TestTokensDifferAndAreLong(t *testing.T) {
	a, _ := mcptoken.New()
	b, _ := mcptoken.New()
	if a.String() == b.String() || a.Identity() == b.Identity() {
		t.Fatal("tokens must differ across New()")
	}
	if len(a.String()) < 43 { // 32 bytes base64url unpadded
		t.Fatalf("token too short: %d", len(a.String()))
	}
}

func TestIdentityNonReversibleAndMatchesFacade(t *testing.T) {
	tok, _ := mcptoken.New()
	if id := tok.Identity(); id != facade.TokenIdentity(tok.String()) || len(id) >= len(tok.String()) {
		t.Fatalf("identity %q", id)
	}
}

// Bearer on non-MCP routes: the existing Authenticator (Basic/cookie) rejects it,
// so no extra middleware is needed.
func TestBearerRejectedByAuthenticatorOnOtherRoutes(t *testing.T) {
	tok, _ := mcptoken.New()
	a := auth.New("pw")
	r := httptest.NewRequest("GET", "/api/session", nil)
	r.Header.Set("Authorization", tok.Header())
	if a.Authorize(r) {
		t.Fatal("bearer token authorized on a non-MCP route")
	}
}
