package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 12: Auth parity
// **Validates: Requirements 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.14**

var tokenShape = regexp.MustCompile(`^[0-9]+\.[A-Za-z0-9_-]{43}$`)

func genPassword() *rapid.Generator[string] { return rapid.StringN(1, 40, -1) }

func genNow() *rapid.Generator[time.Time] {
	return rapid.Map(rapid.Int64Range(0, 4_000_000_000), func(s int64) time.Time { return time.Unix(s, 0) })
}

// Fixture-driven parity: every TS vector, plus the expiry boundary (-1s, 0, +1s) for TS-issued tokens.
func TestPropertyAuthParityFixtures(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Cases {
		if got := New(c.Password).VerifySession(c.Token, time.UnixMilli(c.Now)); got != c.Expected {
			t.Errorf("%s: got %v, TS %v", c.Name, got, c.Expected)
		}
	}
	for _, i := range v.Issued {
		a := New(i.Password)
		exp := time.UnixMilli(i.Now).Add(SessionTTL)
		if !a.VerifySession(i.Token, exp.Add(-time.Second)) {
			t.Errorf("token %q should verify one second before expiry", i.Token)
		}
		if a.VerifySession(i.Token, exp) || a.VerifySession(i.Token, exp.Add(time.Second)) {
			t.Errorf("token %q should be rejected at and after expiry", i.Token)
		}
	}
}

// Issued tokens have the specified shape, verify strictly before expiry and fail at/after it.
func TestPropertyIssuedTokenLifecycle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pw := genPassword().Draw(t, "password")
		now := genNow().Draw(t, "now")
		a := New(pw)
		tok, ok := a.IssueSession(now)
		if !ok || !tokenShape.MatchString(tok) {
			t.Fatalf("bad token %q ok=%v", tok, ok)
		}
		if !strings.HasPrefix(tok, itoa(now.Add(SessionTTL).Unix())+".") {
			t.Fatalf("token %q has wrong expiry for now=%v", tok, now)
		}
		exp := now.Add(SessionTTL)
		if !a.VerifySession(tok, now) || !a.VerifySession(tok, exp.Add(-time.Second)) {
			t.Fatalf("token %q should verify before expiry", tok)
		}
		if a.VerifySession(tok, exp) || a.VerifySession(tok, exp.Add(time.Second)) {
			t.Fatalf("token %q should not verify at or after expiry", tok)
		}
	})
}

// Same password keeps tokens valid across a restart; a different password invalidates them.
func TestPropertyRotationInvalidatesTokens(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pw := genPassword().Draw(t, "old")
		next := genPassword().Draw(t, "new")
		now := genNow().Draw(t, "now")
		tok, _ := New(pw).IssueSession(now)
		if !New(pw).VerifySession(tok, now) {
			t.Fatal("token must survive restart with unchanged password")
		}
		if pw != next && New(next).VerifySession(tok, now) {
			t.Fatal("token must fail after password rotation")
		}
	})
}

// Empty password rejects everything.
func TestPropertyEmptyPasswordRejects(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := New("")
		tok := rapid.String().Draw(t, "token")
		if a.VerifySession(tok, time.Now()) {
			t.Fatal("empty password verified a token")
		}
		if _, ok := a.IssueSession(time.Now()); ok {
			t.Fatal("empty password issued a token")
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth(Username, tok)
		if a.Authorize(r) {
			t.Fatal("empty password authorized")
		}
	})
}

// Authorize: username must be "bellucode"; password or session token as Basic password; session cookie by port.
func TestPropertyAuthorizeCredentials(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pw := genPassword().Draw(t, "password")
		user := rapid.String().Draw(t, "user")
		port := rapid.IntRange(1025, 65535).Draw(t, "port")
		a := New(pw)
		tok, _ := a.IssueSession(time.Now())

		for _, cred := range []string{pw, tok} {
			r := httptest.NewRequest("GET", "/", nil)
			r.SetBasicAuth(Username, cred)
			if !a.Authorize(r) {
				t.Fatalf("bellucode:%q should authorize", cred)
			}
			r = httptest.NewRequest("GET", "/", nil)
			r.SetBasicAuth(user, cred)
			if user != Username && a.Authorize(r) {
				t.Fatalf("user %q must be rejected", user)
			}
		}

		host := "example.com:" + itoa(int64(port))
		name := SessionCookieName(host)
		if name != "bellucode_session_"+itoa(int64(port)) {
			t.Fatalf("cookie name %q", name)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		r.AddCookie(&http.Cookie{Name: name, Value: tok})
		if !a.Authorize(r) {
			t.Fatal("session cookie should authorize")
		}
		r = httptest.NewRequest("GET", "/", nil)
		r.Host = "example.com"
		r.AddCookie(&http.Cookie{Name: "bellucode_session", Value: tok})
		if !a.Authorize(r) {
			t.Fatal("portless session cookie should authorize")
		}
		r = httptest.NewRequest("GET", "/", nil)
		r.Host = host
		r.AddCookie(&http.Cookie{Name: "bellucode_session", Value: tok})
		if a.Authorize(r) {
			t.Fatal("cookie with wrong name for port must be rejected")
		}
	})
}

// Malformed tokens and Authorization headers never panic and never authorize.
func TestPropertyMalformedInputNeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := New("secret")
		now := genNow().Draw(t, "now")
		tok := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`[0-9]{0,25}(\.[A-Za-z0-9_=-]{0,50}){0,3}`),
		).Draw(t, "token")
		valid, _ := a.IssueSession(now)
		parts := strings.Split(tok, ".")
		if tok != valid && (len(parts) != 2 || len(parts[1]) != 43) && a.VerifySession(tok, now) {
			t.Fatalf("malformed token %q verified", tok)
		}
		a.VerifySession(valid+"."+tok, now) // extra parts: must not panic
		if a.VerifySession(valid+".x", now) {
			t.Fatal("three-part token verified")
		}

		hdr := rapid.OneOf(
			rapid.String(),
			rapid.Map(rapid.String(), func(s string) string { return "Basic " + s }),
			rapid.Map(rapid.String(), func(s string) string {
				return "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
			}),
		).Draw(t, "header")
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", hdr)
		r.Host = rapid.String().Draw(t, "host")
		a.Authorize(r)
		SessionCookieName(r.Host)

		// No-colon decoded value must be rejected.
		nc := strings.ReplaceAll(hdr, ":", "")
		r = httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(nc)))
		if a.Authorize(r) {
			t.Fatal("basic value without ':' authorized")
		}
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
