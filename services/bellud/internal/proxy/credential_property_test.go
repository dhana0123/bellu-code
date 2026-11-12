package proxy

import (
	"bytes"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/tschild"
)

// Feature: go-server-bellu-graph, Property 8: Credential isolation
// **Validates: Requirements 7.1, 7.2, 4.2, 4.13**
func TestPropertyCredentialIsolation(t *testing.T) {
	var recorded http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorded = r.Header.Clone()
		w.WriteHeader(204)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)

	var logs bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOut)
	defer log.SetFlags(prevFlags)

	rapid.Check(t, func(t *rapid.T) {
		logs.Reset()
		recorded = nil
		external := "EXT-" + rapid.StringMatching(`[A-Za-z0-9_\-]{8,40}`).Draw(t, "external")
		internal := "INT-" + rapid.StringMatching(`[A-Za-z0-9_\-]{8,40}`).Draw(t, "internal")
		child := &tschild.Child{URL: u, Password: internal}
		h := New(func() *tschild.Child { return child })

		req := httptest.NewRequest("GET", "http://client.example/x", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		switch rapid.IntRange(0, 3).Draw(t, "mode") {
		case 0:
			req.SetBasicAuth(rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "user"), external)
		case 1:
			req.Header.Set("Authorization", "Bearer "+external)
		case 2:
			req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("bellucode:"+external)))
			req.Header.Add("Authorization", "Bearer "+external)
		}
		req.Header.Set("Cookie", "bellucode_session="+external+"; other=1")
		req.Header.Set("X-Custom", "v")

		h.ServeHTTP(httptest.NewRecorder(), req)
		if recorded == nil {
			t.Fatal("upstream saw no request")
		}

		auth := recorded.Values("Authorization")
		if len(auth) != 1 {
			t.Fatalf("expected one Authorization header, got %v", auth)
		}
		user, pw, ok := (&http.Request{Header: http.Header{"Authorization": auth}}).BasicAuth()
		if !ok || user != tschild.Username || pw != internal {
			t.Fatalf("upstream credential is not the internal one: %q", auth)
		}
		if len(recorded.Values("Cookie")) != 0 {
			t.Fatalf("cookie forwarded: %v", recorded.Values("Cookie"))
		}
		b64 := base64.StdEncoding.EncodeToString([]byte(external))
		for k, vs := range recorded {
			for _, v := range vs {
				if strings.Contains(v, external) || strings.Contains(k, external) || strings.Contains(v, b64) {
					t.Fatalf("external credential in header %s: %q", k, v)
				}
			}
		}
		if strings.Contains(logs.String(), external) || strings.Contains(logs.String(), internal) {
			t.Fatalf("credential in logs: %q", logs.String())
		}
	})
}
