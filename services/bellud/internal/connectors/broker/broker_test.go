package broker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

const token = "ghp_supersecrettoken123456"

// countingRT counts requests that reach the "network".
type countingRT struct {
	n    atomic.Int32
	mu   sync.Mutex
	last *http.Request
	fn   func(*http.Request) (*http.Response, error)
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	c.mu.Lock()
	c.last = r
	c.mu.Unlock()
	return c.fn(r)
}

func respond(status int, body string, h ...string) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		hdr := http.Header{}
		for i := 0; i+1 < len(h); i += 2 {
			hdr.Set(h[i], h[i+1])
		}
		return &http.Response{StatusCode: status, Header: hdr, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
}

type memAudit struct {
	mu sync.Mutex
	es []audit.Entry
}

func (a *memAudit) Append(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.es = append(a.es, e)
	return nil
}
func (a *memAudit) List(string, string, int) (audit.Page, error) { return audit.Page{}, nil }
func (a *memAudit) Prune(time.Time, int) error                   { return nil }
func (a *memAudit) entries() []audit.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Entry(nil), a.es...)
}

type fakeOpener struct {
	secret string
	err    error
}

func (f fakeOpener) Use(_ context.Context, _ vault.Ref, fn func([]byte) error) error {
	if f.err != nil {
		return f.err
	}
	return fn([]byte(f.secret))
}

func ghManifest() manifest.Manifest {
	return manifest.Manifest{
		ID: "github", Version: "1.0.0", Name: "GitHub",
		AuthMethods: []manifest.AuthMethod{{ID: "pat", Name: "PAT", Enabled: true}},
		Entities:    []string{"github_repo"},
		Egress:      []string{"api.github.com", "sts.{region}.amazonaws.com"},
		Operations: []manifest.Operation{
			{Name: "GET /repos/{o}/{r}", Class: manifest.ClassRead, Method: "GET", Host: "api.github.com", Path: "/repos/{o}/{r}", StripKeys: []string{"secret"}},
			{Name: "GET /big", Class: manifest.ClassRead, Method: "GET", Host: "api.github.com", Path: "/big"},
			{Name: "sts:GetCallerIdentity", Class: manifest.ClassAuth, Host: "sts.{region}.amazonaws.com"},
		},
	}
}

func newRef(t *testing.T, auth AuthKind) ConnectionRef {
	t.Helper()
	m := ghManifest()
	p, err := policy.Compile(m, policy.Selection{Regions: []string{"us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	return ConnectionRef{ID: "c1", ConnectorID: "github", Manifest: m, Policy: p, Auth: auth,
		Credential: vault.Ref{Owner: vault.OwnerConnection, OwnerID: "c1", Slot: "token"}}
}

// allowAgents is a gate that puts every agent request in scope.
type allowAgents struct{}

func (allowAgents) AgentInputs(_, _, _, _ string) policy.AgentInputs {
	return policy.AgentInputs{InScope: true, LiveReads: true}
}

func newBroker(rt *countingRT, op vault.Opener, rps float64) (*Broker, *memAudit) {
	a := &memAudit{}
	return New(Config{Opener: op, Audit: a, Redactor: redactor.New(), Inner: rt, RatePerSecond: rps, AgentGate: allowAgents{}}), a
}

func TestDoInjectsCredentialRedactsAndStrips(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{"name":"r","secret":"x","nested":{"secret":"y","echo":"`+token+`"}}`)}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	res, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b", "page": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.last.Header.Get("Authorization"); got != "Bearer "+token {
		t.Fatalf("authorization not injected: %q", got)
	}
	if rt.last.URL.String() != "https://api.github.com/repos/a/b?page=2" {
		t.Fatalf("url: %s", rt.last.URL)
	}
	body := string(res.Body)
	if strings.Contains(body, token) || strings.Contains(body, `"secret"`) {
		t.Fatalf("body not projected: %s", body)
	}
	if !strings.Contains(body, "[REDACTED") {
		t.Fatalf("expected redaction marker: %s", body)
	}
}

func TestBlockedCallsSendNothingAndAuditFirst(t *testing.T) {
	ref := newRef(t, AuthGitHubToken)
	cases := []struct {
		name string
		do   func(b *Broker) error
		want policy.Reason
	}{
		{"unknown op", func(b *Broker) error {
			_, err := b.Do(context.Background(), Call{Connection: ref, Caller: "agent:p", Operation: "DELETE /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}})
			return err
		}, policy.ReasonOpNotListed},
		{"auth op by collector", func(b *Broker) error {
			_, err := b.Do(context.Background(), Call{Connection: ref, Caller: policy.CallerCollector, Operation: "sts:GetCallerIdentity"})
			return err
		}, policy.ReasonOpNotListed},
		{"delete via client", func(b *Broker) error {
			req, _ := http.NewRequest("DELETE", "https://api.github.com/repos/a/b", nil)
			_, err := b.HTTPClient(ref, policy.CallerCollector).Do(req)
			return unwrapClientError(err)
		}, policy.ReasonNotReadOnly},
		{"other host", func(b *Broker) error {
			req, _ := http.NewRequest("GET", "https://evil.example.com/repos/a/b", nil)
			_, err := b.HTTPClient(ref, policy.CallerCollector).Do(req)
			return unwrapClientError(err)
		}, policy.ReasonHostBlocked},
		{"plain http", func(b *Broker) error {
			req, _ := http.NewRequest("GET", "http://api.github.com/repos/a/b", nil)
			_, err := b.HTTPClient(ref, policy.CallerCollector).Do(req)
			return unwrapClientError(err)
		}, policy.ReasonHostBlocked},
		{"unlisted path", func(b *Broker) error {
			req, _ := http.NewRequest("GET", "https://api.github.com/user/keys", nil)
			_, err := b.HTTPClient(ref, policy.CallerCollector).Do(req)
			return unwrapClientError(err)
		}, policy.ReasonOpNotListed},
	}
	for _, c := range cases {
		rt := &countingRT{fn: respond(200, `{}`)}
		b, a := newBroker(rt, fakeOpener{secret: token}, 100)
		err := c.do(b)
		var be *BlockedError
		if !errors.As(err, &be) || be.Reason != c.want {
			t.Errorf("%s: err=%v want reason %s", c.name, err, c.want)
		}
		if rt.n.Load() != 0 {
			t.Errorf("%s: %d requests reached the transport", c.name, rt.n.Load())
		}
		es := a.entries()
		if len(es) != 1 || es[0].Event != audit.EventBlockedOperation || es[0].Outcome != audit.OutcomeBlocked ||
			es[0].ConnectionID != "c1" || es[0].Detail["caller"] == "" || es[0].Detail["violated"] == "" {
			t.Errorf("%s: audit entries: %+v", c.name, es)
		}
	}
}

func TestVaultFailureSendsNothing(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{}`)}
	b, a := newBroker(rt, fakeOpener{err: errors.New("boom " + token)}, 100)
	_, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}})
	var ce *CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("want CredentialError, got %v", err)
	}
	if strings.Contains(err.Error(), token) || rt.n.Load() != 0 {
		t.Fatalf("leak or request sent: %v n=%d", err, rt.n.Load())
	}
	if es := a.entries(); len(es) != 1 || es[0].Event != audit.EventCredentialRelease || es[0].Outcome != audit.OutcomeFailure {
		t.Fatalf("audit: %+v", es)
	}
}

func TestRetryAfterPausesConnection(t *testing.T) {
	rt := &countingRT{fn: respond(429, `{}`, "Retry-After", "5")}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	call := Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}}
	res, err := b.Do(context.Background(), call)
	if err != nil || res.Status != 429 {
		t.Fatalf("first call: %v %d", err, res.Status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = b.Do(ctx, call)
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter < 3*time.Second {
		t.Fatalf("want RateLimitedError, got %v", err)
	}
	if rt.n.Load() != 1 {
		t.Fatalf("second call reached the transport")
	}
}

func TestRateLimitResetHeader(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rt := &countingRT{fn: respond(403, `{}`, "X-RateLimit-Remaining", "0", "X-RateLimit-Reset", "1700000020")}
	a := &memAudit{}
	b := New(Config{Opener: fakeOpener{secret: token}, Audit: a, Inner: rt, RatePerSecond: 100, Now: func() time.Time { return now }})
	call := Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}}
	if _, err := b.Do(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	if until := b.state("c1").until; !until.Equal(now.Add(20 * time.Second)) {
		t.Fatalf("pause until %v", until)
	}
}

func TestLimiterSpacesRequests(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{}`)}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 20) // burst 20, so 25 calls need ~0.25 s extra
	call := Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}}
	start := time.Now()
	for i := 0; i < 25; i++ {
		if _, err := b.Do(context.Background(), call); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatalf("limiter did not slow requests: %v", time.Since(start))
	}
}

func TestSizeCap(t *testing.T) {
	rt := &countingRT{fn: respond(200, strings.Repeat("a", DoMaxBytes+1))}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	_, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: "agent:p", Operation: "GET /big"})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestRedirectHopIsRechecked(t *testing.T) {
	rt := &countingRT{fn: respond(302, ``, "Location", "https://evil.example.com/steal")}
	b, a := newBroker(rt, fakeOpener{secret: token}, 100)
	_, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}})
	var be *BlockedError
	if !errors.As(err, &be) || be.Reason != policy.ReasonHostBlocked {
		t.Fatalf("want host_blocked, got %v", err)
	}
	if rt.n.Load() != 1 {
		t.Fatalf("redirect target was contacted: %d", rt.n.Load())
	}
	if es := a.entries(); len(es) != 1 || es[0].Detail["host"] != "evil.example.com" {
		t.Fatalf("audit: %+v", es)
	}
}

func TestPanicIsRecovered(t *testing.T) {
	rt := &countingRT{fn: func(*http.Request) (*http.Response, error) { panic("secret " + token) }}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	_, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}})
	if !errors.Is(err, ErrInternal) || strings.Contains(err.Error(), token) {
		t.Fatalf("got %v", err)
	}
}

func TestDeadlineIsTypedNetworkError(t *testing.T) {
	rt := &countingRT{fn: func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := b.Do(ctx, Call{Connection: newRef(t, AuthGitHubToken), Caller: policy.CallerCollector,
		Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a", "r": "b"}})
	var ne *NetworkError
	if !errors.As(err, &ne) || !ne.Timeout {
		t.Fatalf("want timeout NetworkError, got %v", err)
	}
}

func TestMissingPathParamSendsNothing(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{}`)}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	_, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: "agent:p", Operation: "GET /repos/{o}/{r}", Params: map[string]any{"o": "a"}})
	if !errors.Is(err, ErrBadParams) || rt.n.Load() != 0 {
		t.Fatalf("err=%v n=%d", err, rt.n.Load())
	}
}

const stsXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:role/r</Arn><UserId>U</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`

type awsVaultOpener struct{ err error }

func (o awsVaultOpener) Use(_ context.Context, _ vault.Ref, fn func([]byte) error) error {
	if o.err != nil {
		return o.err
	}
	return fn([]byte(`{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`))
}

func stsClient(b *Broker, ref ConnectionRef, caller string) *sts.Client {
	return sts.New(sts.Options{
		Region: "us-east-1", HTTPClient: b.HTTPClient(ref, caller),
		Credentials: b.AWSCredentials(ref, caller), RetryMaxAttempts: 1,
	})
}

func TestAWSOperationResolutionAndCredentials(t *testing.T) {
	ref := newRef(t, AuthAWSVault)
	rt := &countingRT{fn: respond(200, stsXML, "Content-Type", "text/xml")}
	b, _ := newBroker(rt, awsVaultOpener{}, 100)

	// Lifecycle may call the auth operation.
	out, err := stsClient(b, ref, policy.CallerLifecycle).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(out.Account) != "123456789012" {
		t.Fatalf("lifecycle call: %v", err)
	}
	if !strings.Contains(rt.last.Header.Get("Authorization"), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("request was not signed with the vault credential")
	}

	// A collector may not (auth class), and nothing is sent.
	before := rt.n.Load()
	_, err = stsClient(b, ref, policy.CallerCollector).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	var be *BlockedError
	if !errors.As(err, &be) || rt.n.Load() != before {
		t.Fatalf("collector call: %v", err)
	}

	// An unlisted operation is blocked.
	_, err = stsClient(b, ref, policy.CallerLifecycle).GetSessionToken(context.Background(), &sts.GetSessionTokenInput{})
	if !errors.As(err, &be) || rt.n.Load() != before {
		t.Fatalf("unlisted op: %v", err)
	}
}

func TestAWSVaultFailureSendsNothing(t *testing.T) {
	ref := newRef(t, AuthAWSVault)
	rt := &countingRT{fn: respond(200, stsXML)}
	b, _ := newBroker(rt, awsVaultOpener{err: errors.New("sealed")}, 100)
	_, err := stsClient(b, ref, policy.CallerLifecycle).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	var ce *CredentialError
	if !errors.As(err, &ce) || rt.n.Load() != 0 {
		t.Fatalf("err=%v n=%d", err, rt.n.Load())
	}
}

func TestAmbientIsLimitedToSTS(t *testing.T) {
	ref := newRef(t, AuthAWSAmbient)
	rt := &countingRT{fn: respond(200, stsXML)}
	b, _ := newBroker(rt, fakeOpener{}, 100)
	cl := sts.New(sts.Options{Region: "us-east-1", HTTPClient: b.HTTPClient(ref, policy.CallerLifecycle),
		Credentials: aws.NewCredentialsCache(staticCreds{}), RetryMaxAttempts: 1})
	if _, err := cl.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal(err)
	}
	if b.IMDSClient(newRef(t, AuthAWSVault)) != nil || b.IMDSClient(ref) == nil {
		t.Fatal("IMDS client must exist only for the ambient source")
	}
}

type staticCreds struct{}

func (staticCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "secretsecretsecretsecret"}, nil
}

func TestBlockedAddresses(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "0.0.0.0", "::ffff:127.0.0.1", "224.0.0.1"}
	for _, s := range blocked {
		if !blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	for _, s := range []string{"140.82.112.3", "52.94.0.1", "10.1.2.3", "2606:4700::1"} {
		if blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestDialerRefusesLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer ln.Close()
	var accepted atomic.Bool
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted.Store(true)
			c.Close()
		}
	}()
	tr := newTransport(false)
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("loopback dial must fail")
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() {
		t.Fatal("connection reached the loopback listener")
	}
}

func TestIMDSTransportOnlyReachesMetadata(t *testing.T) {
	rt := &countingRT{fn: respond(200, `ok`)}
	tr := imdsTransport{inner: rt}
	for _, u := range []string{"http://127.0.0.1/latest/meta-data/", "http://169.254.169.254/other", "https://169.254.169.254/latest/api/token"} {
		req, _ := http.NewRequest("GET", u, nil)
		if _, err := tr.RoundTrip(req); err == nil {
			t.Errorf("%s must be blocked", u)
		}
	}
	req, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if _, err := tr.RoundTrip(req); err != nil || rt.n.Load() != 1 {
		t.Fatalf("IMDS token request: %v", err)
	}
}

func TestStripKeys(t *testing.T) {
	got := string(stripKeys([]byte(`{"a":1,"secret":"s","l":[{"secret":2,"b":"<x>"}]}`), []string{"secret"}))
	if got != `{"a":1,"l":[{"b":"<x>"}]}` {
		t.Fatalf("got %s", got)
	}
	if !bytes.Equal(stripKeys([]byte("<xml/>"), []string{"secret"}), []byte("<xml/>")) {
		t.Fatal("non-JSON must pass through")
	}
}

func gqlRef(t *testing.T) ConnectionRef {
	t.Helper()
	ref := newRef(t, AuthGitHubToken)
	ref.Manifest.Operations = append(ref.Manifest.Operations, manifest.Operation{
		Name: "POST /graphql", Class: manifest.ClassRead, Method: "POST", Query: true, Host: "api.github.com", Path: "/graphql"})
	p, err := policy.Compile(ref.Manifest, policy.Selection{Regions: []string{"us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	ref.Policy = p
	return ref
}

func gqlValidator(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "query {") && !strings.Contains(s, "mutation")
}

func TestQueryOperationBodyIsInspected(t *testing.T) {
	ref := gqlRef(t)
	post := func(b *Broker, body string) error {
		req, _ := http.NewRequest("POST", "https://api.github.com/graphql", strings.NewReader(body))
		resp, err := b.HTTPClient(ref, policy.CallerCollector).Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil {
			return nil
		}
		return unwrapClientError(err)
	}
	mk := func(vals map[string]func([]byte) bool) (*Broker, *countingRT, *memAudit) {
		rt := &countingRT{fn: respond(200, `{}`)}
		a := &memAudit{}
		return New(Config{Opener: fakeOpener{secret: token}, Audit: a, Redactor: redactor.New(), Inner: rt,
			RatePerSecond: 100, QueryValidators: vals}), rt, a
	}
	vals := map[string]func([]byte) bool{"github": gqlValidator}

	b, rt, a := mk(vals)
	err := post(b, `{"query":"mutation { addStar(input:{}) { clientMutationId } }"}`)
	var be *BlockedError
	if !errors.As(err, &be) || rt.n.Load() != 0 {
		t.Fatalf("mutation: err=%v sends=%d", err, rt.n.Load())
	}
	if es := a.entries(); len(es) != 1 || es[0].Event != audit.EventBlockedOperation || es[0].Detail["violated"] != "query" {
		t.Fatalf("audit: %+v", es)
	}

	b, rt, _ = mk(vals)
	if err := post(b, `{"query":"query { viewer { login } }"}`); err != nil || rt.n.Load() != 1 {
		t.Fatalf("query: err=%v sends=%d", err, rt.n.Load())
	}
	got, _ := io.ReadAll(rt.last.Body)
	if !strings.Contains(string(got), "viewer") {
		t.Fatalf("body not restored: %q", got)
	}

	// No validator registered: fail closed.
	b, rt, _ = mk(nil)
	if err := post(b, `{"query":"query { viewer { login } }"}`); !errors.As(err, &be) || rt.n.Load() != 0 {
		t.Fatalf("no validator: err=%v sends=%d", err, rt.n.Load())
	}
}

// toggleGate lets a test flip the agent decision between calls.
type toggleGate struct {
	in atomic.Pointer[policy.AgentInputs]
}

func (g *toggleGate) AgentInputs(_, _, _, _ string) policy.AgentInputs { return *g.in.Load() }

func TestAgentCallerIsDeniedWithoutGate(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{}`)}
	a := &memAudit{}
	b := New(Config{Opener: fakeOpener{secret: token}, Audit: a, Inner: rt, RatePerSecond: 100})
	_, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: "agent:agent", Operation: "GET /big"})
	var be *BlockedError
	if !errors.As(err, &be) || be.Reason != policy.ReasonScope || rt.n.Load() != 0 {
		t.Fatalf("err=%v n=%d", err, rt.n.Load())
	}
	if es := a.entries(); len(es) != 1 || es[0].Event != audit.EventScopeDenied || es[0].Detail["caller"] != "agent:agent" || es[0].Detail["operation"] != "GET /big" {
		t.Fatalf("audit: %+v", es)
	}
}

func TestAgentGateRecheckedAfterRateLimitWait(t *testing.T) {
	g := &toggleGate{}
	g.in.Store(&policy.AgentInputs{InScope: true, LiveReads: true})
	rt := &countingRT{fn: respond(200, `{}`)}
	a := &memAudit{}
	b := New(Config{Opener: fakeOpener{secret: token}, Audit: a, Inner: rt, RatePerSecond: 100, AgentGate: g,
		// The scope is revoked while the call waits for its rate-limit slot.
		Sleep: func(context.Context, time.Duration) error {
			g.in.Store(&policy.AgentInputs{InScope: true, LiveReads: false, Why: "live_reads_disabled"})
			return nil
		}})
	st := b.state("c1")
	st.until = b.now().Add(time.Second)
	_, err := b.Do(context.Background(), Call{Connection: newRef(t, AuthGitHubToken), Caller: "agent:agent", Operation: "GET /big"})
	var be *BlockedError
	if !errors.As(err, &be) || be.Violated != "live_reads" || rt.n.Load() != 0 {
		t.Fatalf("err=%v n=%d", err, rt.n.Load())
	}
}
