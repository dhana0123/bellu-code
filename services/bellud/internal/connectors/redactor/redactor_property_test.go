package redactor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// Feature: cloud-connectors, Property 5: Secret redaction on every output channel
//
// Validates: Requirements 6.16, 12.3, 15.5, 16.3, 16.4
func TestPropertySecretRedactionEveryChannel(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// 8..4096 characters, any valid rune incl. non-ASCII and control chars.
		runes := rapid.SliceOfN(rapid.OneOf(
			runeIn(0, 0x7f),
			runeIn(0x80, 0xd7ff),
			runeIn(0xe000, 0x10ffff),
		), 8, 4096).Draw(rt, "secret")
		secret := string(runes)
		if len([]rune(secret)) < 8 {
			rt.Skip("surrogate normalisation shortened secret")
		}
		const pre, post = "ctx<", ">end"
		if strings.Contains(pre+post, secret) {
			rt.Skip()
		}

		r := New()
		defer r.Register([]byte(secret))()

		// fail prints only redacted output so counterexamples never leak credentials.
		fail := func(format string, a ...any) {
			rt.Fatalf("%s", r.String(fmt.Sprintf(format, a...)))
		}
		jb, _ := json.Marshal(secret)
		independent := []string{
			secret,
			string(jb[1 : len(jb)-1]),
			base64.StdEncoding.EncodeToString([]byte(secret)),
			base64.URLEncoding.EncodeToString([]byte(secret)),
			base64.RawStdEncoding.EncodeToString([]byte(secret)),
			base64.RawURLEncoding.EncodeToString([]byte(secret)),
			url.QueryEscape(secret),
			url.PathEscape(secret),
		}
		clean := func(channel, out string) {
			for _, f := range independent {
				if strings.Contains(out, f) {
					fail("channel %s still contains a secret form (len %d)", channel, len(f))
				}
			}
			if r.Contains(out) {
				fail("channel %s: Contains reports a leak", channel)
			}
		}

		// Text channels: log line and error message, one pass per encoding.
		for i, f := range independent {
			line := fmt.Sprintf("level=info msg=%s%s%s", pre, f, post)
			got := r.String(line)
			clean("log", got)
			if want := "level=info msg=" + pre + Marker + post; got != want {
				fail("log form %d: remainder changed", i)
			}
			err := fmt.Errorf("connector: %w", fmt.Errorf("%s%s%s", pre, f, post))
			got = r.String(err.Error())
			clean("error", got)
			if want := "connector: " + pre + Marker + post; got != want {
				fail("error form %d: remainder changed", i)
			}
		}

		// JSON channels: audit entry, API response, Proxy_Request result.
		type payload struct {
			Actor  string            `json:"actor"`
			Detail string            `json:"detail"`
			Tags   []string          `json:"tags"`
			Extra  map[string]string `json:"extra"`
		}
		mk := func(v string) payload {
			return payload{Actor: "u1", Detail: pre + v + post, Tags: []string{"a", v}, Extra: map[string]string{"k": v}}
		}
		for _, channel := range []string{"audit", "api", "proxy"} {
			raw, err := json.Marshal(mk(secret))
			if err != nil {
				rt.Fatal("marshal")
			}
			got := r.JSON(raw)
			clean(channel, string(got))
			if !json.Valid(got) {
				fail("channel %s: output not valid JSON", channel)
			}
			want, _ := json.Marshal(mk(Marker))
			if string(got) != string(want) {
				fail("channel %s: remainder changed", channel)
			}
			// A body that carries the credential as base64 text.
			b64 := mk(base64.StdEncoding.EncodeToString([]byte(secret)))
			raw, _ = json.Marshal(b64)
			clean(channel+"/b64", string(r.JSON(raw)))
		}

		// Graph batch: Guard detects the credential in any position, and the
		// serialised batch is clean once redacted.
		g := r.Guard(redact.New())
		b := batch.Batch{Collector: "c", Entities: []batch.Entity{{
			Type: "t", Identity: map[string]string{"id": "1"},
			Attributes: map[string]any{"note": pre + secret + post, "list": []any{"x", map[string]any{"deep": secret}}},
		}}}
		if !g.Leaks(b) {
			rt.Fatal("guard missed a registered credential in a batch")
		}
		raw, _ := json.Marshal(b)
		clean("graph", string(r.JSON(raw)))
	})
}

func runeIn(lo, hi int) *rapid.Generator[rune] {
	return rapid.Map(rapid.IntRange(lo, hi), func(i int) rune { return rune(i) })
}
