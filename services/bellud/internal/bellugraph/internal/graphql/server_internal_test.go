// Modified by the Bellu project from upstream Toise (see NOTICE and UPSTREAM.md).

package graphql

import (
	"net/http"
	"testing"
)

func TestOriginChecker(t *testing.T) {
	check := originChecker([]string{"https://grafana.example.com"})
	cases := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{"no origin (non-browser client)", "", "bellugraph.local:8080", true},
		{"same origin", "http://bellugraph.local:8080", "bellugraph.local:8080", true},
		{"allowlisted origin", "https://grafana.example.com", "bellugraph.local:8080", true},
		{"cross-site origin rejected", "https://evil.example.com", "bellugraph.local:8080", false},
		{"different host rejected", "http://other.local:8080", "bellugraph.local:8080", false},
	}
	for _, c := range cases {
		r := &http.Request{Host: c.host, Header: http.Header{}}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if got := check(r); got != c.want {
			t.Errorf("%s: checkOrigin = %v, want %v", c.name, got, c.want)
		}
	}
}
