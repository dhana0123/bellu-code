package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func basicReq(user, pass string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://localhost:4096/x", nil)
	r.SetBasicAuth(user, pass)
	return r
}

func TestBasicWithPassword(t *testing.T) {
	a := New("secret")
	if !a.Authorize(basicReq("bellucode", "secret")) {
		t.Fatal("expected authorized")
	}
	if a.Authorize(basicReq("bellucode", "wrong")) {
		t.Fatal("wrong password accepted")
	}
	if a.Authorize(basicReq("other", "secret")) {
		t.Fatal("wrong username accepted")
	}
}

func TestBasicWithSessionToken(t *testing.T) {
	a := New("secret")
	tok, ok := a.IssueSession(time.Now())
	if !ok {
		t.Fatal("issue failed")
	}
	if !a.Authorize(basicReq("bellucode", tok)) {
		t.Fatal("valid token rejected")
	}
	if a.Authorize(basicReq("other", tok)) {
		t.Fatal("wrong username accepted with token")
	}
}

func TestCookieByHostPort(t *testing.T) {
	a := New("secret")
	tok, _ := a.IssueSession(time.Now())

	r := httptest.NewRequest(http.MethodGet, "http://localhost:4096/x", nil)
	r.AddCookie(&http.Cookie{Name: "bellucode_session_4096", Value: tok})
	if !a.Authorize(r) {
		t.Fatal("port cookie rejected")
	}

	r = httptest.NewRequest(http.MethodGet, "http://localhost:4096/x", nil)
	r.AddCookie(&http.Cookie{Name: "bellucode_session", Value: tok})
	if a.Authorize(r) {
		t.Fatal("cookie without port accepted for host with port")
	}

	r = httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	r.AddCookie(&http.Cookie{Name: "bellucode_session", Value: tok})
	if !a.Authorize(r) {
		t.Fatal("bare cookie rejected for host without port")
	}

	r = httptest.NewRequest(http.MethodGet, "http://localhost:4096/x", nil)
	r.AddCookie(&http.Cookie{Name: "bellucode_session_4096", Value: "bad.token"})
	if a.Authorize(r) {
		t.Fatal("invalid cookie accepted")
	}
}

func TestSessionCookieName(t *testing.T) {
	for host, want := range map[string]string{
		"localhost:4096": "bellucode_session_4096",
		"localhost":      "bellucode_session",
		"[::1]:4096":     "bellucode_session_4096",
	} {
		if got := SessionCookieName(host); got != want {
			t.Errorf("%q: got %q want %q", host, got, want)
		}
	}
}

func TestEmptyPasswordRejectsEverything(t *testing.T) {
	a := New("")
	if a.Required() {
		t.Fatal("Required should be false")
	}
	if a.Authorize(basicReq("bellucode", "")) {
		t.Fatal("empty password accepted")
	}
	if a.Authorize(httptest.NewRequest(http.MethodGet, "/x", nil)) {
		t.Fatal("anonymous accepted")
	}
	if tok, ok := a.IssueSession(time.Now()); ok || tok != "" {
		t.Fatal("issued token with empty password")
	}
	if a.VerifySession(".", time.Now()) || a.VerifySession("", time.Now()) {
		t.Fatal("empty token verified")
	}
}

func TestMalformedTokensRejected(t *testing.T) {
	a := New("secret")
	now := time.Now()
	tok, _ := a.IssueSession(now)
	for _, bad := range []string{"", "abc", "a.b.c", "x." + tok[len(tok)-5:], tok + "A", tok[:len(tok)-1]} {
		if a.VerifySession(bad, now) {
			t.Errorf("accepted %q", bad)
		}
	}
	if a.VerifySession(tok, now.Add(SessionTTL+time.Second)) {
		t.Error("expired token accepted")
	}
	if New("other").VerifySession(tok, now) {
		t.Error("token valid for different password")
	}
}

func TestWriteUnauthorized(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"", `Basic realm="Secure Area"`},
		{"navigate", `Basic realm="Secure Area"`},
		{"cors", ""},
		{"same-origin", ""},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://localhost:4096/api/info", nil)
		if tc.mode != "" {
			r.Header.Set("Sec-Fetch-Mode", tc.mode)
		}
		w := httptest.NewRecorder()
		WriteUnauthorized(w, r)
		if w.Code != http.StatusUnauthorized || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("mode %q: status %d type %q", tc.mode, w.Code, w.Header().Get("Content-Type"))
		}
		if got := w.Header().Get("WWW-Authenticate"); got != tc.want {
			t.Fatalf("mode %q: challenge %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestAuthTokenQuery(t *testing.T) {
	a := New("secret")
	ok := base64.StdEncoding.EncodeToString([]byte("bellucode:secret"))
	if !a.Authorize(httptest.NewRequest(http.MethodGet, "http://localhost:4096/x?auth_token="+ok, nil)) {
		t.Fatal("auth_token rejected")
	}
	bad := base64.StdEncoding.EncodeToString([]byte("bellucode:wrong"))
	if a.Authorize(httptest.NewRequest(http.MethodGet, "http://localhost:4096/x?auth_token="+bad, nil)) {
		t.Fatal("wrong auth_token accepted")
	}
}

func TestCookieRejectedCrossOrigin(t *testing.T) {
	a := New("secret")
	tok, _ := a.IssueSession(time.Now())
	r := httptest.NewRequest(http.MethodGet, "http://localhost:4096/x", nil)
	r.AddCookie(&http.Cookie{Name: "bellucode_session_4096", Value: tok})
	r.Header.Set("Origin", "http://localhost:5173")
	if a.Authorize(r) {
		t.Fatal("cross-origin cookie accepted")
	}
	r.Header.Set("Origin", "http://localhost:4096")
	if !a.Authorize(r) {
		t.Fatal("same-origin cookie rejected")
	}
}
