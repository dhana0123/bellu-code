package connectors

import (
	"net"
	"net/http"
	"strings"
)

// RoleUser is the caller role of an authenticated Bellu Code user. Only this
// role may write credentials; agent and MCP token roles are rejected.
const RoleUser = "user"

// ClientHeader must be present on credential-bearing writes. A custom header
// forces a CORS preflight, so it defends against CSRF; it is not authentication.
const ClientHeader = "X-Bellucode-Client"

// maxBody is the request body limit, enforced before parsing (Req 11.12).
const maxBody = 1 << 20

// hostAllowed reports whether the Host header names this machine. Ports are
// ignored. extra holds additional lower-case host names from configuration.
func hostAllowed(host string, extra []string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	for _, e := range extra {
		if h == e {
			return true
		}
	}
	return false
}

// isLoopback reports whether the peer address is a loopback IP.
func isLoopback(remote string) bool {
	h, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// guardReason returns why a credential write is rejected, or "" when allowed.
func (h *Handler) guardReason(r *http.Request, role string) string {
	switch {
	case role != RoleUser:
		return "role"
	case !isLoopback(r.RemoteAddr):
		return "not_local"
	case !hostAllowed(r.Host, h.hosts):
		return "host"
	case strings.TrimSpace(r.Header.Get(ClientHeader)) == "":
		return "client_header"
	}
	return ""
}

// optionWords mark a request option that asks the service to reveal a credential.
var optionWords = []string{"debug", "reveal", "unmask", "plaintext", "expose", "decrypt", "export", "dump", "masterkey", "wrappedkey"}

// optionSubjects name secret material; combined with an action word (or used
// on their own in a query or header) they request it.
var optionSubjects = []string{"credential", "secret", "password", "apikey", "privatekey"}

var optionVerbs = []string{"show", "include", "return", "with", "get", "raw", "plain", "full", "send", "unredact", "unmask", "no", "disable"}

func normalizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isCredentialOption reports whether a query parameter, header or body field
// name asks for credential material. standalone makes a bare subject name
// (for example `credential` or `secret`) count; body fields pass false because
// the route's own credential field legitimately carries that name.
func isCredentialOption(name string, standalone bool) bool {
	n := normalizeName(name)
	if n == "" {
		return false
	}
	for _, w := range optionWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	for _, s := range optionSubjects {
		if !strings.Contains(n, s) {
			continue
		}
		if standalone {
			return true
		}
		for _, v := range optionVerbs {
			if strings.HasPrefix(n, v) {
				return true
			}
		}
	}
	return false
}

// credentialOptions lists the names (kind:name) of every credential-requesting
// option in the query, headers and, when present, the top-level body fields.
// known are the route's own legitimate body fields.
func credentialOptions(r *http.Request, body map[string]any, known map[string]bool) []string {
	var out []string
	add := func(kind, name string) {
		if len(name) > 64 {
			name = name[:64]
		}
		if len(out) < 8 {
			out = append(out, kind+":"+name)
		}
	}
	for k := range r.URL.Query() {
		if isCredentialOption(k, true) {
			add("query", k)
		}
	}
	for k := range r.Header {
		if isCredentialOption(k, true) {
			add("header", k)
		}
	}
	for k := range body {
		if known[k] {
			continue
		}
		if isCredentialOption(k, true) {
			add("body", k)
		}
	}
	return out
}
