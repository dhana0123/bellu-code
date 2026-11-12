// Package auth mirrors packages/server/src/auth.ts so existing clients keep working.
//
// The username, cookie name and HMAC context string keep their bellucode names
// because existing clients and the TS implementation depend on them
// (compatibility names).
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Username is the Basic-auth username (compatibility name).
	Username = "bellucode"
	// SessionTTL is how long an issued session token stays valid.
	SessionTTL = 30 * 24 * time.Hour

	cookieBase  = "bellucode_session"    // compatibility name
	hmacContext = "bellucode-session-v1" // compatibility name
)

// Authenticator authorizes requests and issues/verifies session tokens.
type Authenticator interface {
	// Authorize accepts Basic (username "bellucode") with the password or a valid
	// session token as the password, or the session cookie named by SessionCookieName(host).
	Authorize(r *http.Request) bool
	IssueSession(now time.Time) (token string, ok bool)
	VerifySession(token string, now time.Time) bool
	// Required reports whether a non-empty password is configured.
	Required() bool
}

type auth struct {
	password string
}

// New returns an Authenticator for password. An empty password rejects everything.
func New(password string) Authenticator { return &auth{password: password} }

func (a *auth) Required() bool { return a.password != "" }

func (a *auth) Authorize(r *http.Request) bool {
	if a.password == "" {
		return false
	}
	if user, pass, ok := r.BasicAuth(); ok {
		return user == Username && (ctEq(pass, a.password) || a.VerifySession(pass, time.Now()))
	}
	if c, err := r.Cookie(SessionCookieName(r.Host)); err == nil {
		return a.VerifySession(c.Value, time.Now())
	}
	return false
}

// IssueSession returns "<expiresUnixSec>.<base64url(HMAC)>".
func (a *auth) IssueSession(now time.Time) (string, bool) {
	if a.password == "" {
		return "", false
	}
	expires := strconv.FormatInt(now.Add(SessionTTL).Unix(), 10)
	return expires + "." + a.sign(expires), true
}

func (a *auth) VerifySession(token string, now time.Time) bool {
	if a.password == "" {
		return false
	}
	exp, sig, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(sig, ".") {
		return false
	}
	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || expires > 1<<53-1 || expires*1000 <= now.UnixMilli() {
		return false
	}
	return ctEq(sig, a.sign(exp))
}

// SessionCookieName returns "bellucode_session_<port>" when the Host has a port, else "bellucode_session".
// Browsers share cookies across ports on one host, so the port keeps local servers apart.
// Like URL.parse in the TS version, a default http port (80) counts as no port.
func SessionCookieName(host string) string {
	u, err := url.Parse("http://" + host)
	if err != nil {
		return cookieBase
	}
	port := u.Port()
	if port == "" || port == "80" {
		return cookieBase
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return cookieBase
	}
	return cookieBase + "_" + port
}

// WriteUnauthorized writes a 401 with WWW-Authenticate: Basic.
func WriteUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (a *auth) sign(payload string) string {
	k := hmac.New(sha256.New, []byte(a.password))
	k.Write([]byte(hmacContext))
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func ctEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
