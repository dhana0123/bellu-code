package connectors

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/github"
)

func TestRouteTableCoversProtocol(t *testing.T) {
	want := []string{
		"status", "catalog", "listConnections", "createConnection", "getConnection", "updateConnection",
		"deleteConnection", "testConnection", "syncConnection", "pauseConnection", "resumeConnection",
		"reconnectConnection", "rotateCredential", "listAudit", "listAuthConfigs", "createAuthConfig",
		"deleteAuthConfig", "awsSetup", "listGithubRepos", "getScope", "putScope", "unlockVault",
		"rotateMasterKey", "forgetAll",
	}
	got := map[string]Route{}
	for _, r := range Routes() {
		got[r.Name] = r
	}
	if len(got) != len(want) {
		t.Fatalf("routes = %d, want %d", len(got), len(want))
	}
	for _, n := range want {
		if _, ok := got[n]; !ok {
			t.Errorf("route %s missing", n)
		}
	}
	for _, n := range []string{"createConnection", "reconnectConnection", "rotateCredential", "createAuthConfig"} {
		if !got[n].Credential {
			t.Errorf("%s must use the credential write guard", n)
		}
	}
}

func TestLifecycleRoutes(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	w := do(h, "POST", Prefix+"/connections", createBody(""), writeHdr)
	if w.Code != 200 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	id := decode(t, w)["id"].(string)
	base := Prefix + "/connections/" + id

	w = do(h, "POST", base+"/test", "", writeHdr)
	m := decode(t, w)
	if w.Code != 200 || m["ok"] != true || m["accountLabel"] != "octo" || m["permissionCheck"] != "unverifiable" {
		t.Fatalf("test %d %s", w.Code, w.Body)
	}
	if ws := m["warnings"].([]any); len(ws) != 1 || ws[0] != github.UnverifiableMessage {
		t.Fatalf("warnings %v", ws)
	}
	if len(m["offenders"].([]any)) != 0 {
		t.Fatalf("offenders %v", m["offenders"])
	}

	if w = do(h, "POST", base+"/pause", "", writeHdr); w.Code != 200 || decode(t, w)["status"] != "PAUSED" {
		t.Fatalf("pause %d %s", w.Code, w.Body)
	}
	if w = do(h, "POST", base+"/resume", "", writeHdr); w.Code != 200 || decode(t, w)["status"] != "ACTIVE" {
		t.Fatalf("resume %d %s", w.Code, w.Body)
	}
	// The fake GitHub transport cannot serve a full collection, so the run may
	// end in a typed collection error; it must never be an untyped one.
	switch w = do(h, "POST", base+"/sync", "", writeHdr); w.Code {
	case 200:
		if decode(t, w)["started"] != true {
			t.Fatalf("sync %s", w.Body)
		}
	case 409:
		// The sync started by the create is still running.
		if decode(t, w)["_tag"] != "ConflictError" {
			t.Fatalf("sync %s", w.Body)
		}
	case 400:
		if decode(t, w)["_tag"] != "ConnectorError" {
			t.Fatalf("sync %s", w.Body)
		}
	default:
		t.Fatalf("sync %d %s", w.Code, w.Body)
	}

	w = do(h, "GET", base+"/audit", "", nil)
	m = decode(t, w)
	if w.Code != 200 || len(m["items"].([]any)) == 0 || len(m["items"].([]any)) > 50 {
		t.Fatalf("audit %d %s", w.Code, w.Body)
	}
	if w = do(h, "GET", base+"/github/repos", "", nil); w.Code != 200 || decode(t, w)["items"] == nil {
		t.Fatalf("repos %d %s", w.Code, w.Body)
	}

	for _, rt := range []struct{ method, path string }{
		{"POST", "/test"}, {"POST", "/sync"}, {"POST", "/pause"}, {"POST", "/resume"},
		{"POST", "/reconnect"}, {"POST", "/rotate"}, {"GET", "/audit"}, {"GET", "/github/repos"},
	} {
		body := ""
		if rt.path == "/reconnect" || rt.path == "/rotate" {
			body = `{"credential":{"token":"` + apiToken + `"}}`
		}
		if w := do(h, rt.method, Prefix+"/connections/nope"+rt.path, body, writeHdr); w.Code != 404 {
			t.Errorf("%s unknown connection: %d", rt.path, w.Code)
		}
	}
}

func TestRotateAndReconnectGuardAndValidation(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	w := do(h, "POST", Prefix+"/connections", createBody(""), writeHdr)
	id := decode(t, w)["id"].(string)
	body := `{"credential":{"token":"` + apiToken + `"}}`
	for _, op := range []string{"rotate", "reconnect"} {
		p := Prefix + "/connections/" + id + "/" + op
		if w := do(h, "POST", p, body, nil); w.Code != 403 || decode(t, w)["code"] != "forbidden" {
			t.Errorf("%s without client header: %d %s", op, w.Code, w.Body)
		}
		if w := do(h, "POST", p, `{}`, writeHdr); w.Code != 400 {
			t.Errorf("%s empty body: %d", op, w.Code)
		}
	}
	if w := do(h, "POST", Prefix+"/connections/"+id+"/rotate", body, writeHdr); w.Code != 200 {
		t.Fatalf("rotate %d %s", w.Code, w.Body)
	}
	if strings.Contains(do(h, "GET", Prefix+"/connections/"+id+"/audit", "", nil).Body.String(), "abcdefgh") {
		t.Fatal("audit leaks credential")
	}
}

func TestAuthConfigRoutes(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	w := do(h, "GET", Prefix+"/connectors/github/auth-configs", "", nil)
	if w.Code != 200 || len(decode(t, w)["items"].([]any)) == 0 {
		t.Fatalf("list %d %s", w.Code, w.Body)
	}
	body := `{"name":"mine","method":"pat"}`
	if w := do(h, "POST", Prefix+"/connectors/github/auth-configs", body, nil); w.Code != 403 {
		t.Fatalf("create without client header: %d", w.Code)
	}
	if w := do(h, "POST", Prefix+"/connectors/github/auth-configs", `{"name":""}`, writeHdr); w.Code != 400 {
		t.Fatalf("invalid body: %d", w.Code)
	}
	if w := do(h, "DELETE", Prefix+"/auth-configs/nope", "", writeHdr); w.Code != 400 && w.Code != 404 {
		t.Fatalf("delete unknown: %d", w.Code)
	}
}

func TestAWSSetupAndVaultRoutes(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	w := do(h, "POST", Prefix+"/aws/setup", `{}`, writeHdr)
	m := decode(t, w)
	if w.Code != 200 {
		t.Fatalf("setup %d %s", w.Code, w.Body)
	}
	id, _ := m["externalId"].(string)
	if !strings.HasPrefix(id, "BELLU-") || !strings.Contains(m["cloudFormation"].(string), id) || !strings.Contains(m["terraform"].(string), id) {
		t.Fatalf("setup %v", m)
	}
	if w := do(h, "POST", Prefix+"/aws/setup", `{"alias":""}`, writeHdr); w.Code != 400 {
		t.Fatalf("setup bad alias %d", w.Code)
	}
	if w := do(h, "POST", Prefix+"/vault/unlock", `{"passphrase":""}`, writeHdr); w.Code != 400 {
		t.Fatalf("unlock empty %d", w.Code)
	}
	if w := do(h, "POST", Prefix+"/vault/unlock", `{"passphrase":"correct horse battery"}`, writeHdr); w.Code != 400 {
		t.Fatalf("unlock without passphrase source %d %s", w.Code, w.Body)
	}
	do(h, "POST", Prefix+"/connections", createBody(""), writeHdr)
	if w := do(h, "POST", Prefix+"/vault/rotate", "", writeHdr); w.Code != http.StatusOK {
		t.Fatalf("rotate %d %s", w.Code, w.Body)
	}
	if w := do(h, "POST", Prefix+"/vault/forget", "", writeHdr); w.Code != 200 || len(s.Connections()) != 0 {
		t.Fatalf("forget %d %s conns=%d", w.Code, w.Body, len(s.Connections()))
	}
}

func TestScopeRoutes(t *testing.T) {
	s := newService(t, "connectors")
	h := NewAPI(APIConfig{Service: s})
	w := do(h, "GET", Prefix+"/scopes/agent", "", nil)
	m := decode(t, w)
	if w.Code != 200 || m["principal"] != "agent" || len(m["connectors"].([]any)) != 0 {
		t.Fatalf("get %d %s", w.Code, w.Body)
	}
	ok := `{"connectors":["github"],"connections":[],"operations":{"github":[]}}`
	if w := do(h, "PUT", Prefix+"/scopes/agent", ok, writeHdr); w.Code != 200 || decode(t, w)["principal"] != "agent" {
		t.Fatalf("put %d %s", w.Code, w.Body)
	}
	w = do(h, "PUT", Prefix+"/scopes/agent", `{"connectors":["github"],"connections":[],"operations":{"github":["DeleteRepo"]}}`, writeHdr)
	m = decode(t, w)
	if w.Code != 400 || m["code"] != "validation_failed" || m["offenders"].([]any)[0] != "DeleteRepo" {
		t.Fatalf("bad op %d %s", w.Code, w.Body)
	}
	if w := do(h, "PUT", Prefix+"/scopes/other", ok, writeHdr); w.Code != 400 {
		t.Fatalf("unknown principal %d", w.Code)
	}
	if w := do(h, "PUT", Prefix+"/scopes/agent", `{"connectors":[]}`, writeHdr); w.Code != 400 {
		t.Fatalf("missing fields %d", w.Code)
	}
	if got := decode(t, do(h, "GET", Prefix+"/scopes/agent", "", nil)); len(got["connectors"].([]any)) != 1 {
		t.Fatalf("scope changed by rejected put: %v", got)
	}
}
