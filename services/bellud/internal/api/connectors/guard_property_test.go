package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	svc "github.com/bellu/bellucode/services/bellud/internal/connectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/keysource"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

// propEnv is one real connectors.Service shared by every iteration of a
// property, with a pre-created connection for the id-addressed routes.
type propEnv struct {
	s    *svc.Service
	dir  string
	base string
	role string
	h    *Handler
	seq  atomic.Int64
}

func newPropEnv(t *testing.T) *propEnv {
	t.Helper()
	ctx := context.Background()
	eng, err := graph.Open(ctx, graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close(ctx) })
	e := &propEnv{dir: t.TempDir(), role: RoleUser}
	e.s, err = svc.New(ctx, svc.Options{
		Dir: e.dir, Engine: eng, Order: []keysource.Source{&apiKeys{slots: map[string][]byte{}}}, Transport: ghOK{},
		Getenv: func(k string) string {
			if k == "BELLUCODE_FLAGS" {
				return "connectors"
			}
			return ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.s.Close(ctx) })
	e.h = NewAPI(APIConfig{Service: e.s, Role: func(*http.Request) string { return e.role }})
	w := do(e.h, "POST", Prefix+"/connections", createBody(""), writeHdr)
	if w.Code != 200 {
		t.Fatalf("base connection %d %s", w.Code, w.Body)
	}
	e.base = decode(t, w)["id"].(string)
	return e
}

type snapshot struct {
	conns, authConfigs int
	vault              string
}

func (e *propEnv) snap(t testing.TB) snapshot {
	t.Helper()
	ac, err := e.s.AuthConfigs("github")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(e.dir, "vault", "vault.json"))
	if err != nil {
		raw = []byte("absent")
	}
	return snapshot{len(e.s.Connections()), len(ac), string(raw)}
}

// allAudit pages through the whole global audit log.
func (e *propEnv) allAudit(t testing.TB) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	cursor := ""
	for {
		pg, err := e.s.ListAudit("", cursor, svc.DefaultPageSize)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pg.Entries...)
		if pg.NextCursor == "" {
			return out
		}
		cursor = pg.NextCursor
	}
}

func countEvent(es []audit.Entry, ev string) int {
	n := 0
	for _, e := range es {
		if e.Event == ev {
			n++
		}
	}
	return n
}

func auditHas(es []audit.Entry, needle string) bool {
	for _, e := range es {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}

// Feature: cloud-connectors, Property 17: Credential write authorization
//
// For any combination of role, remote address, Host, client header and
// Sec-Fetch-Site, a credential write is accepted if and only if every guard
// condition holds; otherwise it is rejected 403 forbidden, stores nothing and
// appends exactly one blocked_operation audit entry without credential values.
//
// **Validates: Requirements 6.14, 6.15**
func TestProperty17CredentialWriteAuthorization(t *testing.T) {
	e := newPropEnv(t)
	type remote struct {
		addr  string
		local bool
	}
	remotes := []remote{
		{"127.0.0.1:5555", true}, {"[::1]:5555", true}, {"127.5.5.5:9", true},
		{"192.168.1.5:4000", false}, {"10.0.0.1:1", false}, {"8.8.8.8:80", false},
		{"[2001:db8::1]:80", false}, {"", false}, {"garbage", false}, {"127.0.0.1", false},
	}
	type host struct {
		name    string
		allowed bool
	}
	hosts := []host{
		{"localhost", true}, {"localhost:4096", true}, {"LOCALHOST:80", true}, {"127.0.0.1:80", true},
		{"[::1]:4096", true}, {"evil.example", false}, {"localhost.evil.com", false},
		{"127.0.0.1.evil.com:80", false}, {"", false}, {"192.168.1.5:4096", false},
	}
	routes := []struct {
		name, method, path string
		body               func(secret string) string
	}{
		{"createConnection", "POST", "/connections", func(s string) string {
			return fmt.Sprintf(`{"alias":"a%d","connectorId":"github","method":"pat","params":{"repos":"octo/hello"},"credential":{"token":%q}}`, e.seq.Add(1), s)
		}},
		{"rotateCredential", "POST", "/connections/" + e.base + "/rotate", func(s string) string {
			return fmt.Sprintf(`{"credential":{"token":%q}}`, s)
		}},
		{"reconnectConnection", "POST", "/connections/" + e.base + "/reconnect", func(s string) string {
			return fmt.Sprintf(`{"credential":{"token":%q}}`, s)
		}},
		{"createAuthConfig", "POST", "/connectors/github/auth-configs", func(s string) string {
			return fmt.Sprintf(`{"name":"n%d","method":"pat","secrets":{"token":%q}}`, e.seq.Add(1), s)
		}},
	}
	rapid.Check(t, func(rt *rapid.T) {
		route := rapid.SampledFrom(routes).Draw(rt, "route")
		role := rapid.SampledFrom([]string{RoleUser, "agent", "graph", "mcp", ""}).Draw(rt, "role")
		rem := rapid.SampledFrom(remotes).Draw(rt, "remote")
		hst := rapid.SampledFrom(hosts).Draw(rt, "host")
		client := rapid.SampledFrom([]string{"", " ", "\t", "web", "x"}).Draw(rt, "client")
		fetch := rapid.SampledFrom([]string{"", "same-origin", "same-site", "none", "cross-site", "Cross-Site", "CROSS-SITE"}).Draw(rt, "fetchSite")
		secret := "github_pat_" + rapid.StringMatching(`[A-Za-z0-9]{30,40}`).Draw(rt, "secret")

		wantOK := role == RoleUser && rem.local && hst.allowed && strings.TrimSpace(client) != "" &&
			!strings.EqualFold(fetch, "cross-site")

		before, auditBefore := e.snap(t), e.allAudit(t)
		e.role = role
		r := httptest.NewRequest(route.method, Prefix+route.path, strings.NewReader(route.body(secret)))
		r.RemoteAddr, r.Host = rem.addr, hst.name
		if client != "" {
			r.Header.Set(ClientHeader, client)
		}
		if fetch != "" {
			r.Header.Set("Sec-Fetch-Site", fetch)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		auditAfter := e.allAudit(t)

		if strings.Contains(w.Body.String(), secret) || auditHas(auditAfter, secret) {
			rt.Fatalf("%s: credential value leaked", route.name)
		}
		blocked := countEvent(auditAfter, audit.EventBlockedOperation) - countEvent(auditBefore, audit.EventBlockedOperation)
		if wantOK {
			if w.Code == http.StatusForbidden {
				rt.Fatalf("%s: allowed request rejected: %s", route.name, w.Body)
			}
			if blocked != 0 {
				rt.Fatalf("%s: allowed request audited as blocked", route.name)
			}
			return
		}
		if w.Code != http.StatusForbidden || decode(t, w)["code"] != "forbidden" {
			rt.Fatalf("%s: want 403 forbidden, got %d %s", route.name, w.Code, w.Body)
		}
		if blocked != 1 {
			rt.Fatalf("%s: blocked_operation entries = %d, want 1", route.name, blocked)
		}
		if after := e.snap(t); after != before {
			rt.Fatalf("%s: rejected write changed state", route.name)
		}
	})
}

// ---- Property 18 ----

const planted = "PLANTEDVALUE-9f8e7d6c"

type fieldSpec struct {
	name     string
	required bool
	valid    func(e *propEnv, t *rapid.T) any // nil: only absent counts as valid
	invalid  []any
}

type bodyRoute struct {
	name, method, path string
	fields             []fieldSpec
}

func uniqueAlias(e *propEnv, t *rapid.T) any {
	return rapid.StringMatching(`[A-Za-z0-9]{1,20}`).Draw(t, "alias") + fmt.Sprintf("-%d", e.seq.Add(1))
}

func strField(name string, required bool, max int, valid func(*propEnv, *rapid.T) any) fieldSpec {
	inv := []any{5, true, nil, []any{planted}, map[string]any{planted: planted}}
	if required {
		inv = append(inv, "")
	}
	if max > 0 {
		inv = append(inv, planted+strings.Repeat("x", max))
	}
	return fieldSpec{name: name, required: required, valid: valid, invalid: inv}
}

func mapField(name string, required bool, valid func(*propEnv, *rapid.T) any) fieldSpec {
	return fieldSpec{name: name, required: required, valid: valid, invalid: []any{
		planted, 7, true, []any{planted}, map[string]any{"token": 5, planted: planted}, map[string]any{planted: nil},
	}}
}

func intField(name string, min, max, step int) fieldSpec {
	// step 60 mirrors the service's whole-minute rule for intervalSec.
	return fieldSpec{name: name, valid: func(_ *propEnv, t *rapid.T) any { return rapid.IntRange(min/step, max/step).Draw(t, name) * step },
		invalid: []any{min - 1, max + 1, 1.5, planted, true, nil, []any{planted}}}
}

func bodyRoutes(e *propEnv) []bodyRoute {
	tok := func(*propEnv, *rapid.T) any { return map[string]any{"token": apiToken} }
	return []bodyRoute{
		{"createConnection", "POST", "/connections", []fieldSpec{
			strField("alias", true, aliasMax, uniqueAlias),
			strField("connectorId", true, 0, func(*propEnv, *rapid.T) any { return "github" }),
			strField("authConfigId", false, 0, nil),
			strField("method", true, 0, func(*propEnv, *rapid.T) any { return "pat" }),
			mapField("params", false, func(*propEnv, *rapid.T) any { return map[string]any{"repos": "octo/hello"} }),
			mapField("credential", true, tok),
			intField("intervalSec", intervalMin, intervalMax, 60),
		}},
		{"rotateCredential", "POST", "/connections/" + e.base + "/rotate", []fieldSpec{mapField("credential", true, tok)}},
		{"reconnectConnection", "POST", "/connections/" + e.base + "/reconnect", []fieldSpec{mapField("credential", true, tok)}},
		{"createAuthConfig", "POST", "/connectors/github/auth-configs", []fieldSpec{
			strField("name", true, authConfigNameMax, func(e *propEnv, t *rapid.T) any { return fmt.Sprintf("cfg%d", e.seq.Add(1)) }),
			strField("method", true, 0, func(*propEnv, *rapid.T) any { return "pat" }),
			{name: "scopes", invalid: []any{planted, 3, []any{1}, []any{planted, 2}, map[string]any{planted: planted}}},
			mapField("settings", false, func(*propEnv, *rapid.T) any { return map[string]any{} }),
			mapField("secrets", false, nil),
		}},
		{"updateConnection", "PATCH", "/connections/" + e.base, []fieldSpec{
			strField("alias", false, aliasMax, uniqueAlias),
			intField("intervalSec", intervalMin, intervalMax, 60),
			{name: "allowAgentLiveReads", valid: func(_ *propEnv, t *rapid.T) any { return rapid.Bool().Draw(t, "live") },
				invalid: []any{planted, 1, nil, []any{true}}},
			{name: "selection", invalid: []any{planted, 4, map[string]any{"regions": []any{}},
				map[string]any{"regions": []any{1}, "repos": []any{}}, map[string]any{"regions": planted, "repos": []any{planted}}}},
			intField("rotationIntervalDays", rotationMin, rotationMax, 1),
		}},
	}
}

// Feature: cloud-connectors, Property 18: Request body validation
//
// A body above 1 MiB is rejected before parsing (413); a body failing schema
// validation is rejected 400 naming exactly the failing fields, containing no
// submitted value and changing no state; a valid body passes.
//
// **Validates: Requirements 11.10, 11.11, 11.12**
func TestProperty18RequestBodyValidation(t *testing.T) {
	e := newPropEnv(t)
	routes := bodyRoutes(e)
	rapid.Check(t, func(rt *rapid.T) {
		route := rapid.SampledFrom(routes).Draw(rt, "route")
		oversize := rapid.IntRange(0, 9).Draw(rt, "oversizeRoll") == 0
		before := e.snap(t)

		var body []byte
		var want []string
		if oversize {
			pad := strings.Repeat("p", maxBody+rapid.IntRange(0, 5000).Draw(rt, "extra"))
			body = []byte(`{"` + planted + `":"` + pad + `"}`)
		} else {
			obj := map[string]any{}
			for _, f := range route.fields {
				state := rapid.IntRange(0, 2).Draw(rt, f.name+"State") // 0 valid, 1 absent, 2 invalid
				switch {
				case state == 0 && f.valid != nil:
					obj[f.name] = f.valid(e, rt)
				case state == 2:
					obj[f.name] = rapid.SampledFrom(f.invalid).Draw(rt, f.name+"Bad")
					want = append(want, f.name)
				case f.required:
					want = append(want, f.name) // absent or no valid generator for a required field
				}
			}
			for i, n := 0, rapid.IntRange(0, 3).Draw(rt, "unknownCount"); i < n; i++ {
				obj["zz"+rapid.StringMatching(`[a-z]{1,8}`).Draw(rt, "unknownName")] = planted
			}
			var err error
			if body, err = json.Marshal(obj); err != nil {
				rt.Fatal(err)
			}
		}

		r := httptest.NewRequest(route.method, Prefix+route.path, bytes.NewReader(body))
		if rapid.Bool().Draw(rt, "chunked") {
			r.ContentLength = -1
		}
		r.RemoteAddr, r.Host = "127.0.0.1:1", "localhost:4096"
		r.Header.Set(ClientHeader, "web")
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)

		if oversize {
			if w.Code != http.StatusRequestEntityTooLarge || decode(t, w)["code"] != "payload_too_large" {
				rt.Fatalf("%s oversize: %d", route.name, w.Code)
			}
		} else if len(want) > 0 {
			m := decode(t, w)
			if w.Code != http.StatusBadRequest || m["code"] != "validation_failed" {
				rt.Fatalf("%s: want 400 validation_failed for %v, got %d %s", route.name, want, w.Code, w.Body)
			}
			var got []string
			offenders, _ := m["offenders"].([]any)
			for _, o := range offenders {
				got = append(got, o.(string))
			}
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				rt.Fatalf("%s offenders %v, want %v (body %s)", route.name, got, want, body)
			}
		} else if offenders, _ := decode(t, w)["offenders"].([]any); w.Code == http.StatusRequestEntityTooLarge ||
			w.Code == http.StatusForbidden || (len(offenders) > 0 && route.name != "createAuthConfig") {
			// Lifecycle outcomes (e.g. transition_rejected on reconnect) are not schema failures;
			// createAuthConfig also has service rules (scopes, settings) beyond the body schema.
			rt.Fatalf("%s: valid body rejected by validation: %d %s (body %s)", route.name, w.Code, w.Body, body)
		}

		if strings.Contains(w.Body.String(), planted) || auditHas(e.allAudit(t), planted) {
			rt.Fatalf("%s: submitted value echoed or audited", route.name)
		}
		if len(want) > 0 || oversize {
			if after := e.snap(t); after != before {
				rt.Fatalf("%s: rejected body changed state", route.name)
			}
		}
	})
}
