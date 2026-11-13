package github

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// ---- generators and fakes ---------------------------------------------------

var (
	propOwners = []string{"acme", "globex"}
	propNames  = []string{"api", "web", "infra"}
	// Mirrors the graph's secret-name rule (bge/ident.IsSecretName), which sits
	// behind an internal package boundary and cannot be imported here.
	secretFragments = []string{"secret", "token", "password", "passwd", "credential", "private", "apikey", "api_key", "hash"}
)

func isSecretName(n string) bool {
	l := strings.ToLower(n)
	for _, f := range secretFragments {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

func drawSelection(t *rapid.T) []string {
	var pool []string
	for _, o := range propOwners {
		for _, n := range propNames {
			pool = append(pool, o+"/"+n)
		}
	}
	return rapid.SliceOfNDistinct(rapid.SampledFrom(pool), 1, len(pool), func(s string) string { return s }).Draw(t, "selection")
}

func drawMarker(t *rapid.T, prefix string) string {
	return prefix + hex.EncodeToString([]byte(rapid.StringMatching(`[a-z0-9]{6,12}`).Draw(t, prefix)))
}

// genAPI is a typed fake whose content-bearing fields carry a forbidden marker.
type genAPI struct {
	failTypes map[string]bool // collection type -> every call of that type fails
	failRepos map[string]bool // "owner/name" -> Repo fails
	n         map[string]int  // collection type -> items per repo
	forbidden string
	detector  string
	calls     []string // "Method:owner/name" (Org: "Org:owner")
}

var errFake = errors.New("fake failure")

func (g *genAPI) rec(m, o, r string) {
	if r == "" {
		g.calls = append(g.calls, m+":"+o)
		return
	}
	g.calls = append(g.calls, m+":"+o+"/"+r)
}

func (g *genAPI) Org(_ context.Context, org string) (Org, error) {
	g.rec("Org", org, "")
	if g.failTypes[typeOrg] {
		return Org{}, errFake
	}
	return Org{Login: org, Name: "Org " + org}, nil
}

func (g *genAPI) Repo(_ context.Context, o, r string) (Repo, error) {
	g.rec("Repo", o, r)
	if g.failRepos[o+"/"+r] {
		return Repo{}, &StatusError{Status: 404}
	}
	return Repo{FullName: o + "/" + r, DefaultBranch: "main", HTMLURL: g.forbidden,
		Owner: Owner{Login: o, Type: "Organization"}}, nil
}

func (g *genAPI) Workflows(_ context.Context, o, r string) ([]Workflow, error) {
	g.rec("Workflows", o, r)
	if g.failTypes[typeWorkflow] {
		return nil, errFake
	}
	var out []Workflow
	for i := 0; i < g.n[typeWorkflow]; i++ {
		out = append(out, Workflow{Name: "wf", Path: ".github/workflows/" + strconv.Itoa(i) + ".yml", State: "active"})
	}
	return out, nil
}

func (g *genAPI) OpenPullRequests(_ context.Context, o, r string) ([]PullRequest, error) {
	g.rec("PRs", o, r)
	if g.failTypes[typePullRequest] {
		return nil, errFake
	}
	var out []PullRequest
	for i := 1; i <= g.n[typePullRequest]; i++ {
		p := PullRequest{Number: i, Title: g.forbidden, HTMLURL: g.forbidden, State: "open", CreatedAt: time.Unix(1700000000, 0)}
		p.User.Login = "alice"
		p.Base.Ref = "main"
		out = append(out, p)
	}
	return out, nil
}

func (g *genAPI) CodeScanningAlerts(_ context.Context, o, r string) ([]CodeScanningAlert, error) {
	g.rec("CodeScanning", o, r)
	if g.failTypes[typeCodeScanning] {
		return nil, errFake
	}
	var out []CodeScanningAlert
	for i := 1; i <= g.n[typeCodeScanning]; i++ {
		a := CodeScanningAlert{Number: i, State: "open"}
		a.Rule.ID = "go/sql"
		a.Tool.Name = g.forbidden
		out = append(out, a)
	}
	return out, nil
}

func (g *genAPI) DependabotAlerts(_ context.Context, o, r string) ([]DependabotAlert, error) {
	g.rec("Dependabot", o, r)
	if g.failTypes[typeDependabot] {
		return nil, errFake
	}
	var out []DependabotAlert
	for i := 1; i <= g.n[typeDependabot]; i++ {
		a := DependabotAlert{Number: i, State: "open"}
		a.Dependency.Package.Name = "lodash"
		a.Dependency.Package.Ecosystem = g.forbidden
		out = append(out, a)
	}
	return out, nil
}

func (g *genAPI) SecretScanningAlerts(_ context.Context, o, r string) ([]SecretScanningAlert, error) {
	g.rec("SecretScanning", o, r)
	if g.failTypes[typeSecretScanning] {
		return nil, errFake
	}
	var out []SecretScanningAlert
	for i := 1; i <= g.n[typeSecretScanning]; i++ {
		out = append(out, SecretScanningAlert{Number: i, State: "open", Detector: g.detector})
	}
	return out, nil
}

var itemTypes = []string{typeWorkflow, typePullRequest, typeCodeScanning, typeDependabot, typeSecretScanning}

func drawGen(t *rapid.T) (*genAPI, []string) {
	g := &genAPI{
		failTypes: map[string]bool{}, failRepos: map[string]bool{}, n: map[string]int{},
		forbidden: drawMarker(t, "FORBIDDEN-"),
		detector:  rapid.SampledFrom([]string{"github_personal_access_token", "slack_api_token", "aws_access_key_id"}).Draw(t, "detector"),
	}
	for _, ty := range itemTypes {
		g.n[ty] = rapid.IntRange(0, 3).Draw(t, "n_"+ty)
	}
	return g, drawSelection(t)
}

// ---- Property 28 (fake API) ---------------------------------------------------

func checkHygiene(t tb, b graph.Batch, connID, name, forbidden string) {
	t.Helper()
	kinds := map[string]bool{}
	for _, k := range Manifest().Entities {
		kinds[k] = true
	}
	ids := map[string]bool{}
	for _, e := range b.Entities {
		if !kinds[e.Type] {
			t.Fatalf("unregistered kind %q", e.Type)
		}
		if e.Identity["connection"] != connID {
			t.Fatalf("%s identity lacks connection: %v", e.Type, e.Identity)
		}
		if e.Attributes["source"] != name {
			t.Fatalf("%s source = %v", e.Type, e.Attributes["source"])
		}
		for k, v := range e.Attributes {
			if isSecretName(k) {
				t.Fatalf("attribute name %q on %s matches the secret-name rule", k, e.Type)
			}
			if s, ok := v.(string); ok && forbidden != "" && strings.Contains(s, forbidden) {
				t.Fatalf("forbidden content in attribute %q of %s", k, e.Type)
			}
		}
		for k, v := range e.Identity {
			if isSecretName(k) || (forbidden != "" && strings.Contains(v, forbidden)) {
				t.Fatalf("identity %q=%q on %s is not clean", k, v, e.Type)
			}
		}
		h, err := identity.Hash(e.Type, e.Identity)
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		ids[string(h)] = true
	}
	for _, r := range b.Relations {
		if r.Type != "owned_by" || !ids[r.From] || !ids[r.To] {
			t.Fatalf("bad relation %+v", r)
		}
	}
}

// Feature: cloud-connectors, Property 28: Collector output hygiene
//
// **Validates: Requirements 7.8, 7.13, 10.4**
func TestProperty28CollectorOutputHygieneFake(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g, sel := drawGen(t)
		conn := drawMarker(t, "cn_")
		c := NewCollector(conn, g, sel, time.Minute)
		b, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		checkHygiene(t, b, conn, c.Name(), g.forbidden)
		if b.Collector != c.Name() {
			t.Fatalf("collector %q", b.Collector)
		}
		if g.detector != "" {
			sawDetector := false
			for _, e := range b.Entities {
				if e.Attributes["detector"] == g.detector {
					sawDetector = true
				}
			}
			if g.n[typeSecretScanning] > 0 && !sawDetector {
				t.Fatal("detector attribute missing")
			}
		}
	})
}

// ---- real Client (optionally through the broker) -------------------------------

type propRT struct {
	mu     sync.Mutex
	paths  []string
	secret string
	forb   string
	calls  int
}

func (p *propRT) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	p.paths = append(p.paths, r.URL.Path)
	p.mu.Unlock()
	path := r.URL.Path
	var body string
	switch {
	case strings.HasPrefix(path, "/orgs/"):
		body = fmt.Sprintf(`{"login":%q,"name":"Org","description":%q}`, strings.TrimPrefix(path, "/orgs/"), p.forb)
	case strings.HasSuffix(path, "/actions/workflows"):
		body = `{"workflows":[{"id":1,"name":"CI","path":".github/workflows/ci.yml","state":"active"}]}`
	case strings.HasSuffix(path, "/pulls"):
		body = fmt.Sprintf(`[{"number":4,"title":%q,"body":%q,"state":"open","user":{"login":"bob"},"base":{"ref":"main"}}]`, p.forb, p.forb)
	case strings.HasSuffix(path, "/code-scanning/alerts"), strings.HasSuffix(path, "/dependabot/alerts"):
		body = `[]`
	case strings.HasSuffix(path, "/secret-scanning/alerts"):
		// GitHub reports the leaked value in "secret" (also nested, as a hostile fixture).
		body = fmt.Sprintf(`[{"number":9,"state":"open","html_url":"https://github.com/x/y/security/secret-scanning/9","secret_type":"slack_api_token","secret":%q,"locations":{"secret":%q},"first_location_detected":{"secret":%q}}]`,
			p.secret, p.secret, p.secret)
	case strings.HasPrefix(path, "/repos/"):
		o, n, _ := strings.Cut(strings.TrimPrefix(path, "/repos/"), "/")
		body = fmt.Sprintf(`{"full_name":"%s/%s","private":true,"default_branch":"main","description":%q,"owner":{"login":%q,"type":"Organization"}}`, o, n, p.forb, o)
	default:
		return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

type propAudit struct{}

func (propAudit) Append(context.Context, audit.Entry) error    { return nil }
func (propAudit) List(string, string, int) (audit.Page, error) { return audit.Page{}, nil }
func (propAudit) Prune(time.Time, int) error                   { return nil }

type propOpener struct{ token string }

func (o propOpener) Use(_ context.Context, _ vault.Ref, fn func([]byte) error) error {
	return fn([]byte(o.token))
}

// realClient builds the real Client over rt, directly or through the broker.
func realClient(t tb, rt http.RoundTripper, viaBroker bool) *Client {
	t.Helper()
	if !viaBroker {
		return NewClient(&http.Client{Transport: rt}, DefaultAPIHost, "")
	}
	m := Manifest()
	pol, err := policy.Compile(m, policy.Selection{Host: DefaultAPIHost})
	if err != nil {
		t.Fatal(err)
	}
	token := PATPrefix + "propertytesttoken0123456789"
	b := broker.New(broker.Config{Opener: propOpener{token}, Audit: propAudit{}, Redactor: redactor.New(), Inner: rt, RatePerSecond: 1000})
	ref := broker.ConnectionRef{ID: "cn_prop", ConnectorID: ConnectorID, Manifest: m, Policy: pol, Auth: broker.AuthGitHubToken,
		Credential: vault.Ref{Owner: vault.OwnerConnection, OwnerID: "cn_prop", Slot: "token"}}
	return NewClient(b.HTTPClient(ref, policy.CallerCollector), DefaultAPIHost, "")
}

// Feature: cloud-connectors, Property 28: Collector output hygiene
// (GitHub fixtures with a secret-scanning response carrying a `secret` value,
// decoded by the real Client, directly and through the broker.)
//
// **Validates: Requirements 7.8, 7.13, 10.4**
func TestProperty28CollectorOutputHygieneRealClient(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sel := drawSelection(t)
		secret := drawMarker(t, "SECRETVALUE-")
		forb := drawMarker(t, "FORBIDDEN-")
		via := rapid.Bool().Draw(t, "viaBroker")
		rt := &propRT{secret: secret, forb: forb}
		conn := drawMarker(t, "cn_")
		c := NewCollector(conn, realClient(t, rt, via), sel, time.Minute)
		b, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		checkHygiene(t, b, conn, c.Name(), forb)
		enc, _ := json.Marshal(b)
		if strings.Contains(string(enc), secret) {
			t.Fatalf("secret value reached the batch (viaBroker=%v)", via)
		}
		alerts := 0
		for _, e := range b.Entities {
			if e.Type == "github_alert" && e.Identity["alert_type"] == "secret_scanning" {
				alerts++
				if e.Attributes["detector"] != "slack_api_token" {
					t.Fatalf("detector = %v", e.Attributes["detector"])
				}
			}
		}
		if alerts != len(sel) {
			t.Fatalf("secret-scanning alerts = %d, want %d", alerts, len(sel))
		}
	})
}

// ---- Property 32 ---------------------------------------------------------------

func inSelection(sel []string, o, r string) bool {
	for _, s := range sel {
		if strings.EqualFold(s, o+"/"+r) {
			return true
		}
	}
	return false
}

// Feature: cloud-connectors, Property 32: Selection confinement (repositories)
//
// **Validates: Requirements 4.11**
func TestProperty32SelectionConfinement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g, sel := drawGen(t)
		if _, err := NewCollector("cn_1", g, sel, time.Minute).Collect(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(g.calls) == 0 {
			t.Fatal("no calls recorded")
		}
		owners := map[string]bool{}
		for _, s := range sel {
			owners[strings.ToLower(strings.SplitN(s, "/", 2)[0])] = true
		}
		for _, call := range g.calls {
			m, target, _ := strings.Cut(call, ":")
			if m == "Org" {
				if !owners[strings.ToLower(target)] {
					t.Fatalf("org call outside selection: %s", call)
				}
				continue
			}
			o, r, _ := strings.Cut(target, "/")
			if !inSelection(sel, o, r) {
				t.Fatalf("call outside selection: %s (selection %v)", call, sel)
			}
		}

		// Same through the real Client: every request on the wire targets the selection.
		rt := &propRT{secret: "SECRETVALUE-x", forb: "FORBIDDEN-x"}
		via := rapid.Bool().Draw(t, "viaBroker")
		if _, err := NewCollector("cn_1", realClient(t, rt, via), sel, time.Minute).Collect(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(rt.paths) == 0 {
			t.Fatal("no requests recorded")
		}
		for _, p := range rt.paths {
			parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
			switch parts[0] {
			case "orgs":
				if !owners[strings.ToLower(parts[1])] {
					t.Fatalf("request outside selection: %s", p)
				}
			case "repos":
				if !inSelection(sel, parts[1], parts[2]) {
					t.Fatalf("request outside selection: %s", p)
				}
			default:
				t.Fatalf("unexpected request path %s", p)
			}
		}
	})
}

// ---- Property 33 ---------------------------------------------------------------

// Feature: cloud-connectors, Property 33: Partial failure isolation
//
// **Validates: Requirements 7.8, 7.13**
func TestProperty33PartialFailureIsolation(t *testing.T) {
	allTypes := append([]string{typeOrg}, itemTypes...)
	rapid.Check(t, func(t *rapid.T) {
		g, sel := drawGen(t)
		failed := map[string]bool{}
		for _, ty := range allTypes {
			if rapid.Bool().Draw(t, "fail_"+ty) {
				g.failTypes[ty] = true
				failed[ty] = true
			}
		}
		// Fail a proper subset of the selected repositories (at least one stays readable).
		if len(sel) > 1 {
			k := rapid.IntRange(0, len(sel)-1).Draw(t, "failedRepos")
			for _, s := range sel[:k] {
				g.failRepos[s] = true
			}
			if k > 0 {
				failed[typeRepo] = true
			}
		}
		var resolved []string
		owners := map[string]bool{}
		for _, s := range sel {
			if !g.failRepos[s] {
				resolved = append(resolved, s)
				owners[strings.SplitN(s, "/", 2)[0]] = true
			}
		}

		b, err := NewCollector("cn_1", g, sel, time.Minute).Collect(context.Background())

		if len(failed) == 0 {
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
		} else {
			var pe collectors.PartialError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want PartialError", err)
			}
			want := make([]string, 0, len(failed))
			for ty := range failed {
				want = append(want, ty)
			}
			sort.Strings(want)
			if strings.Join(pe.Types, ",") != strings.Join(want, ",") {
				t.Fatalf("reported %v, want exactly %v", pe.Types, want)
			}
		}

		counts := map[string]int{}
		for _, e := range b.Entities {
			k := e.Type
			if k == "github_alert" {
				k = "alert:" + e.Identity["alert_type"]
			}
			counts[k]++
		}
		expect := func(key string, want int) {
			if counts[key] != want {
				t.Fatalf("%s = %d, want %d (failed=%v, counts=%v)", key, counts[key], want, failed, counts)
			}
		}
		expect("github_repo", len(resolved))
		expect("github_org", len(owners)) // present even when the org lookup failed
		per := func(ty string) int {
			if failed[ty] {
				return 0
			}
			return len(resolved) * g.n[ty]
		}
		expect("github_workflow", per(typeWorkflow))
		expect("github_pull_request", per(typePullRequest))
		expect("alert:code_scanning", per(typeCodeScanning))
		expect("alert:dependabot", per(typeDependabot))
		expect("alert:secret_scanning", per(typeSecretScanning))
	})
}

// tb is the subset of testing.TB shared by *testing.T and *rapid.T.
type tb interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}
