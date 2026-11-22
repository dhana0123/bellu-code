package seek_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/seek"
	"github.com/bellu/bellucode/services/bellud/internal/seek/bskg"
	"github.com/bellu/bellucode/services/bellud/internal/seek/seektest"
)

const rkAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~+/="

// rkPaths are the URLs the retriever may request for the plan below.
var rkPaths = []string{
	"/v1/graph/neighborhood",
	"/v1/weaknesses/CWE-79", "/v1/weaknesses/CWE-79/vulnerabilities",
	"/v1/weaknesses/CWE-89", "/v1/weaknesses/CWE-89/vulnerabilities",
}

// Feature: bellu-seek-planner, Property 13: The BSKG key never appears in any output
// **Validates: Requirements 9.3, 9.4, 10.8, 12.4**
func TestPropKeyNeverAppearsInOutput(t *testing.T) {
	fake := seektest.New(t)

	// A 5xx server whose body and headers echo the bearer key.
	echo5xx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Debug", token)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, `{"error":{"code":"internal","message":"bad key %s"}}`, token)
	}))
	t.Cleanup(echo5xx.Close)

	modes := []string{"success", "unreachable", "timeout", "401", "5xx echo", "200 echo", "redirect"}

	rapid.Check(t, func(t *rapid.T) {
		key := string(rapid.SliceOfN(rapid.SampledFrom([]byte(rkAlphabet)), 16, 40).Draw(t, "key"))
		mode := rapid.SampledFrom(modes).Draw(t, "mode")
		plan := rtPlan(rtUnit("CWE-79", rtXSS), rtUnit("CWE-89", "SQL injection username"))

		fake.Clear()
		base, request := fake.URL, 2*time.Second
		switch mode {
		case "unreachable":
			base = "http://127.0.0.1:1"
		case "timeout":
			request = 100 * time.Millisecond
			for _, p := range rkPaths {
				fake.Inject(p, seektest.Rule{Delay: 5 * time.Second})
			}
		case "401":
			for _, p := range rkPaths {
				fake.Inject(p, seektest.Rule{Status: 401})
			}
		case "5xx echo":
			base = echo5xx.URL
		case "200 echo":
			for _, p := range rkPaths {
				fake.Inject(p, seektest.Rule{EchoKey: true})
			}
		case "redirect":
			for _, p := range rkPaths {
				fake.Inject(p, seektest.Rule{RedirectTo: fake.Foreign().URL})
			}
		}
		sentBefore, foreignBefore := len(fake.Requests()), len(fake.ForeignRequests())

		cfg := rtConfig(request, 3*time.Second)
		secret := bskg.Secret(key)
		bcfg := bskg.Config{BaseURL: base, Key: secret, Timeout: request}
		client, err := bskg.New(bcfg)
		if err != nil {
			t.Fatal(err)
		}
		logs := &rtLogs{}
		logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		res := seek.NewRetriever(client, cfg, logger).Run(context.Background(), plan, 4)

		outputs := []string{logs.String()}
		body, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(body))
		for _, f := range []string{"%v", "%+v", "%#v"} {
			outputs = append(outputs,
				fmt.Sprintf(f, res), fmt.Sprintf(f, res.Error), fmt.Sprintf(f, res.Units),
				fmt.Sprintf(f, bcfg), fmt.Sprintf(f, secret), fmt.Sprintf(f, &bcfg))
		}
		if j, err := json.Marshal(bcfg); err == nil {
			outputs = append(outputs, string(j))
		}
		infos := []*seek.ErrInfo{res.Error}
		for _, u := range res.Units {
			infos = append(infos, u.Error)
		}
		for _, e := range infos {
			if e != nil {
				outputs = append(outputs, e.Category, e.Message, fmt.Sprintf("%v|%+v|%#v", *e, *e, *e))
			}
		}
		// Errors returned by the client itself, in every failure mode.
		if _, err := client.Weakness(context.Background(), "CWE-79"); err != nil {
			outputs = append(outputs, err.Error(), fmt.Sprintf("%v|%+v|%#v", err, err, err))
		}

		for _, s := range outputs {
			if strings.Contains(s, key) {
				t.Fatalf("mode %q: key leaked in %q", mode, s)
			}
		}

		// The key is only ever sent as the Authorization header to the configured host.
		if n := len(fake.ForeignRequests()) - foreignBefore; n != 0 {
			t.Fatalf("mode %q: foreign host received %d requests", mode, n)
		}
		// Late requests from an earlier iteration (timeout mode) may still be
		// recorded here; they carry an older key and are ignored.
		authorized := 0
		for _, r := range fake.Requests()[sentBefore:] {
			if r.Header.Get("Authorization") == "Bearer "+key {
				authorized++
			}
			rest := r.Path + "?" + r.RawQuery + r.RawPath + r.Body
			for name, vs := range r.Header {
				if name != "Authorization" {
					rest += strings.Join(vs, ",")
				}
			}
			if strings.Contains(rest, key) {
				t.Fatalf("mode %q: key sent outside the Authorization header: %q", mode, rest)
			}
		}
		if mode == "success" && authorized == 0 {
			t.Fatal("no request carried the key as the Authorization header")
		}
	})
}
