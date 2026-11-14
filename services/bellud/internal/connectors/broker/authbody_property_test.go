package broker

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
)

// Feature: github-app-signin, Property 15: Device-flow request bodies contain
// only allowed keys. The broker allows a body iff it parses, is within
// MaxAuthBody, is non-empty and every key is in {client_id, device_code,
// grant_type, scope}; anything else is blocked with zero bytes sent.
// **Validates: Requirements 4.4, 8.3, 9.7**
func TestPropertyAuthBodyOnlyAllowedKeys(tt *testing.T) {
	ref := devicePreRef(tt)
	allowed := []string{"client_id", "device_code", "grant_type", "scope"}
	extra := rapid.OneOf(
		rapid.SampledFrom([]string{"client_secret", "refresh_token", "Client_Secret", "redirect_uri", "code"}),
		rapid.StringMatching(`[a-z]{3,12}`).Filter(func(s string) bool {
			for _, a := range allowed {
				if s == a {
					return false
				}
			}
			return true
		}),
	)
	rapid.Check(tt, func(t *rapid.T) {
		keys := map[string]string{}
		val := rapid.StringMatching(`[A-Za-z0-9._-]{0,20}`)
		for _, k := range rapid.SliceOfNDistinct(rapid.SampledFrom(allowed), 0, 4, func(s string) string { return s }).Draw(t, "allowed") {
			keys[k] = val.Draw(t, "v")
		}
		for _, k := range rapid.SliceOfN(extra, 0, 2).Draw(t, "extra") {
			keys[k] = val.Draw(t, "v")
		}
		asJSON := rapid.Bool().Draw(t, "json")
		mode := rapid.SampledFrom([]string{"plain", "plain", "oversize", "malformed"}).Draw(t, "mode")
		if mode == "oversize" {
			keys["scope"] = strings.Repeat("a", MaxAuthBody+rapid.IntRange(0, 100).Draw(t, "over"))
		}

		var body, ctype string
		if asJSON {
			ctype = "application/json"
			raw, _ := json.Marshal(keys)
			body = string(raw)
			if mode == "malformed" {
				body = body[:len(body)-1]
			}
		} else {
			ctype = "application/x-www-form-urlencoded"
			q := url.Values{}
			for k, v := range keys {
				q.Set(k, v)
			}
			body = q.Encode()
			if mode == "malformed" {
				body += "&%zz=1"
			}
		}

		want := mode != "malformed" && len(keys) > 0 && len(body) <= MaxAuthBody
		for k := range keys {
			if !authBodyKeys[k] {
				want = false
			}
		}

		rt := &countingRT{fn: respond(200, `{}`)}
		b, a := newBroker(rt, fakeOpener{secret: token}, 100)
		resp, err := postForm(b, ref, "/login/oauth/access_token", ctype, body)
		if want {
			if err != nil {
				t.Fatalf("body %q should be allowed: %v", body, err)
			}
			resp.Body.Close()
			if rt.n.Load() != 1 {
				t.Fatalf("allowed body not sent: %q", body)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			if resp != nil {
				resp.Body.Close()
			}
			t.Fatalf("body %.80q should be blocked, err=%v", body, err)
		}
		if rt.n.Load() != 0 {
			t.Fatalf("blocked body sent bytes: %.80q", body)
		}
		if es := a.entries(); len(es) != 1 || es[0].Event != audit.EventBlockedOperation {
			t.Fatalf("audit: %+v", es)
		}
	})
}
