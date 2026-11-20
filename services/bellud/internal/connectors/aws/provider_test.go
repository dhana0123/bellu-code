package aws

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// stubClient overrides the calls Verify and CheckPermissions make.
type stubClient struct {
	Client
	id      Identity
	idErr   error
	allowed []AllowedAction
	simErr  error
	simArgs []string
}

func (s *stubClient) Identity(context.Context) (Identity, error) { return s.id, s.idErr }
func (s *stubClient) SimulateWrites(_ context.Context, principal string, actions []string) ([]AllowedAction, error) {
	s.simArgs = append([]string{principal}, actions...)
	return s.allowed, s.simErr
}
func (s *stubClient) Instances(context.Context, string) (Listing[Instance], error) {
	return Listing[Instance]{}, s.idErr
}
func (s *stubClient) Buckets(context.Context) ([]Bucket, error) { return nil, nil }
func (s *stubClient) SecurityGroups(context.Context, string) (Listing[SecurityGroup], error) {
	return Listing[SecurityGroup]{}, nil
}
func (s *stubClient) VPCs(context.Context, string) (Listing[VPC], error)        { return Listing[VPC]{}, nil }
func (s *stubClient) Roles(context.Context) ([]Role, error)                     { return nil, nil }
func (s *stubClient) Functions(context.Context, string) ([]Function, error)     { return nil, nil }
func (s *stubClient) DBInstances(context.Context, string) ([]DBInstance, error) { return nil, nil }

func stubProvider(t *testing.T, c Client, params Params) *Provider {
	t.Helper()
	b := newBroker(&countingRT{handle: func(int, url.Values, *http.Request) (int, string) {
		return 200, assumeXML(time.Now().Add(time.Hour))
	}})
	p, err := NewProvider(ProviderConfig{
		Broker:    b,
		Params:    func(context.Context, store.Connection) (Params, error) { return params, nil },
		NewClient: func(Config) (Client, error) { return c, nil },
		Sleep:     func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func staticConn() store.Connection {
	return store.Connection{ID: "c1", ConnectorID: ConnectorID, Alias: "a", Method: MethodStaticKeys,
		Selection: store.Selection{Regions: []string{"us-east-1"}}}
}

func callFor(t *testing.T, conn store.Connection) lifecycle.Call {
	t.Helper()
	return lifecycle.Call{Connection: conn, Ref: newRef(t, broker.AuthAWSVault), Client: &http.Client{}}
}

func wantCode(t *testing.T, err error, code lifecycle.Code) {
	t.Helper()
	var le *lifecycle.Error
	if !errors.As(err, &le) || le.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestManifestRegistersAndHasExpectedShape(t *testing.T) {
	if errs := manifest.Validate(Manifest()); len(errs) != 0 {
		t.Fatal(errs)
	}
	r := registry.New()
	if err := Register(r); err != nil {
		t.Fatal(err)
	}
	e, ok := r.Get(ConnectorID)
	if !ok || e.Plugin {
		t.Fatalf("entry %+v ok=%v", e, ok)
	}
	var sso, assume, auth int
	for _, a := range e.Manifest.AuthMethods {
		switch a.ID {
		case MethodSSO:
			sso++
			if a.Enabled {
				t.Error("sso must be disabled")
			}
		case MethodAssumeRole:
			assume++
		}
	}
	for _, op := range e.Manifest.Operations {
		if op.Class == manifest.ClassAuth {
			auth++
			if op.Name != "sts:AssumeRole" {
				t.Errorf("unexpected auth op %s", op.Name)
			}
		} else if manifest.IsWrite(op) {
			t.Errorf("%s is a write", op.Name)
		}
	}
	if sso != 1 || assume != 1 || auth != 1 || len(e.Manifest.Operations) != 28 {
		t.Fatalf("sso=%d assume=%d auth=%d ops=%d", sso, assume, auth, len(e.Manifest.Operations))
	}
	// At least one region is required; only selected regions are reachable.
	if _, err := policy.Compile(e.Manifest, policy.Selection{}); err == nil {
		t.Error("compile without a region must fail")
	}
	p, err := policy.Compile(e.Manifest, policy.Selection{Regions: []string{"eu-west-1"}})
	if err != nil {
		t.Fatal(err)
	}
	ok1 := p.Check(policy.Request{Caller: policy.CallerCollector, Method: "POST", Host: "ec2.eu-west-1.amazonaws.com", Operation: "ec2:DescribeInstances", Class: "read"})
	ok2 := p.Check(policy.Request{Caller: policy.CallerCollector, Method: "POST", Host: "ec2.us-east-1.amazonaws.com", Operation: "ec2:DescribeInstances", Class: "read"})
	if !ok1.Allow || ok2.Allow {
		t.Fatalf("region scoping: %+v %+v", ok1, ok2)
	}
}

func TestVerifyRejectsRootAndDropsSession(t *testing.T) {
	cl := &stubClient{id: Identity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:root"}}
	p := stubProvider(t, cl, Params{})
	_, err := p.Verify(context.Background(), callFor(t, staticConn()))
	wantCode(t, err, lifecycle.CodeInvalidCredential)
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("message must state root is not allowed: %v", err)
	}
}

func TestVerifyReturnsAccountLabel(t *testing.T) {
	cl := &stubClient{id: Identity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:user/x"}}
	id, err := stubProvider(t, cl, Params{}).Verify(context.Background(), callFor(t, staticConn()))
	if err != nil || id.AccountLabel != "123456789012" || !id.ExpiresAt.IsZero() {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestVerifyErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		code lifecycle.Code
	}{
		{ErrInvalidCredential, lifecycle.CodeInvalidCredential},
		{ErrAccessDenied, lifecycle.CodeInvalidCredential},
		{ErrThrottled, lifecycle.CodeRateLimited},
		{ErrExpired, lifecycle.CodeExpired},
	}
	for _, c := range cases {
		p := stubProvider(t, &stubClient{idErr: c.err}, Params{})
		_, err := p.Verify(context.Background(), callFor(t, staticConn()))
		wantCode(t, err, c.code)
	}
	// Policy blocks and network errors are left to the manager's classifier.
	be := &broker.BlockedError{}
	p := stubProvider(t, &stubClient{idErr: be}, Params{})
	if _, err := p.Verify(context.Background(), callFor(t, staticConn())); !errors.Is(err, be) {
		t.Fatalf("blocked error must pass through: %v", err)
	}
}

func TestVerifyRequiresARegion(t *testing.T) {
	conn := staticConn()
	conn.Selection.Regions = nil
	_, err := stubProvider(t, &stubClient{}, Params{}).Verify(context.Background(), callFor(t, conn))
	wantCode(t, err, lifecycle.CodeValidationFailed)
}

func TestCheckPermissionsReportsAllowedWrites(t *testing.T) {
	cl := &stubClient{
		id:      Identity{PrincipalARN: testRole},
		allowed: []AllowedAction{{Action: "s3:PutObject"}, {Action: "ec2:RunInstances"}, {Action: "s3:GetObject"}},
	}
	rep, err := stubProvider(t, cl, Params{}).CheckPermissions(context.Background(), callFor(t, staticConn()))
	if err != nil {
		t.Fatal(err)
	}
	// Sorted; actions outside the fixed write list are never offenders.
	if len(rep.WriteOffenders) != 2 || rep.WriteOffenders[0] != "ec2:RunInstances" || rep.WriteOffenders[1] != "s3:PutObject" {
		t.Fatalf("offenders %v", rep.WriteOffenders)
	}
	if cl.simArgs[0] != testRole || len(cl.simArgs)-1 != len(WriteActions) {
		t.Fatalf("simulated %v", cl.simArgs)
	}
}

func TestCheckPermissionsReadOnlyRolePasses(t *testing.T) {
	cl := &stubClient{id: Identity{PrincipalARN: testRole}}
	rep, err := stubProvider(t, cl, Params{}).CheckPermissions(context.Background(), callFor(t, staticConn()))
	if err != nil || len(rep.WriteOffenders) != 0 || rep.Unverifiable {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestSimulationAccessDeniedIsInsufficientPermission(t *testing.T) {
	cl := &stubClient{id: Identity{PrincipalARN: testRole}, simErr: ErrAccessDenied}
	_, err := stubProvider(t, cl, Params{}).CheckPermissions(context.Background(), callFor(t, staticConn()))
	wantCode(t, err, lifecycle.CodeInsufficientPermission)
}

func TestDataReadWarningsAreSeparate(t *testing.T) {
	cl := &stubClient{id: Identity{PrincipalARN: testRole}, allowed: []AllowedAction{{Action: "s3:GetObject"}, {Action: "iam:CreateUser"}}}
	p := stubProvider(t, cl, Params{})
	w, err := p.DataReadWarnings(context.Background(), callFor(t, staticConn()))
	if err != nil || len(w) != 1 || w[0] != "s3:GetObject" {
		t.Fatalf("%v %v", w, err)
	}
	if len(cl.simArgs)-1 != len(DataReadActions) {
		t.Fatalf("simulated %v", cl.simArgs)
	}
}

func TestDescribeAndStaticRefresh(t *testing.T) {
	p := stubProvider(t, &stubClient{}, Params{})
	if d := p.Describe(staticConn()); d.Auth != broker.AuthAWSVault {
		t.Fatalf("%+v", d)
	}
	exp, err := p.Refresh(context.Background(), callFor(t, staticConn()))
	if err != nil || !exp.IsZero() {
		t.Fatalf("%v %v", exp, err)
	}
}

// brokerProvider uses the real broker and policy transport with a fake network.
func brokerProvider(t *testing.T, rt *countingRT, params Params) *Provider {
	t.Helper()
	p, err := NewProvider(ProviderConfig{
		Broker: newBroker(rt),
		Params: func(context.Context, store.Connection) (Params, error) { return params, nil },
		Getenv: func(k string) string {
			return map[string]string{"AWS_ACCESS_KEY_ID": "AKIAAMBIENTEXAMPLE1", "AWS_SECRET_ACCESS_KEY": "ambientsecretvalue1234567890"}[k]
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func roleConn() store.Connection {
	c := staticConn()
	c.Method = MethodAssumeRole
	return c
}

func TestAssumeRoleVerifyThroughBrokerAndRefresh(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	rt := &countingRT{handle: func(_ int, f url.Values, r *http.Request) (int, string) {
		if f.Get("Action") == "AssumeRole" {
			return 200, assumeXML(exp)
		}
		return 200, callerXML
	}}
	p := brokerProvider(t, rt, Params{RoleARN: testRole, ExternalID: testExt, Source: SourceVault})
	conn := roleConn()
	b := newBroker(rt)
	call := lifecycle.Call{Connection: conn, Ref: newRef(t, broker.AuthAWSVault),
		Client: b.HTTPClient(newRef(t, broker.AuthAWSVault), policy.CallerLifecycle)}
	id, err := p.Verify(context.Background(), call)
	if err != nil || id.AccountLabel != "123456789012" {
		t.Fatalf("%+v %v", id, err)
	}
	if f := rt.forms[0]; f.Get("Action") != "AssumeRole" || f.Get("ExternalId") != testExt {
		t.Fatalf("first call %v", f)
	}
	n := rt.n.Load()
	if _, err := p.Verify(context.Background(), call); err != nil || rt.n.Load() != n+1 {
		t.Fatalf("session must be reused: err=%v calls=%d", err, rt.n.Load()-n)
	}
	got, err := p.Refresh(context.Background(), call)
	if err != nil || !got.Equal(exp) {
		t.Fatalf("refresh %v %v", got, err)
	}
	if rt.forms[len(rt.forms)-1].Get("Action") != "AssumeRole" {
		t.Fatalf("refresh must call AssumeRole again: %v", rt.forms)
	}
}

func TestAmbientSourceIsRestrictedToSTS(t *testing.T) {
	rt := &countingRT{handle: func(_ int, f url.Values, r *http.Request) (int, string) {
		if f.Get("Action") == "AssumeRole" {
			return 200, assumeXML(time.Now().Add(time.Hour))
		}
		return 200, callerXML
	}}
	p := brokerProvider(t, rt, Params{RoleARN: testRole, ExternalID: testExt, Source: SourceAmbient})
	ref := newRef(t, broker.AuthAWSVault)
	call := lifecycle.Call{Connection: roleConn(), Ref: ref, Client: newBroker(rt).HTTPClient(ref, policy.CallerLifecycle)}
	if _, err := p.Verify(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	for _, h := range rt.hosts {
		if !strings.HasPrefix(h, "sts.") {
			t.Fatalf("unexpected host %s", h)
		}
	}
}

func TestRefreshFailureExpiresAndDropsSession(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) { return 403, deniedXML }}
	p := brokerProvider(t, rt, Params{RoleARN: testRole, ExternalID: testExt, Source: SourceVault})
	ref := newRef(t, broker.AuthAWSVault)
	call := lifecycle.Call{Connection: roleConn(), Ref: ref, Client: newBroker(rt).HTTPClient(ref, policy.CallerLifecycle)}
	_, err := p.Refresh(context.Background(), call)
	wantCode(t, err, lifecycle.CodeExpired)
	if rt.n.Load() != 1+RefreshRetries {
		t.Fatalf("calls=%d", rt.n.Load())
	}
	p.mu.Lock()
	n := len(p.sessions)
	p.mu.Unlock()
	if n != 0 {
		t.Fatal("expired session must not be retained")
	}
	// A first verification with a rejected role is invalid_credential, not expired.
	_, err = p.Verify(context.Background(), call)
	wantCode(t, err, lifecycle.CodeInvalidCredential)
}

func TestCollectorUsesConstructorAndNaming(t *testing.T) {
	p := stubProvider(t, &stubClient{}, Params{})
	conn := staticConn()
	conn.ID = "c9"
	c := p.Collector(conn, newRef(t, broker.AuthAWSVault))
	if c.Name() != "connector:aws:c9" {
		t.Fatal(c.Name())
	}
	to, ok := c.(collectors.Timeouter)
	if !ok || to.Timeout() != 120*time.Second {
		t.Fatal("timeout")
	}
}

func TestCollectorWithoutRegionFailsRuns(t *testing.T) {
	conn := staticConn()
	conn.Selection.Regions = nil
	c := stubProvider(t, &stubClient{}, Params{}).Collector(conn, newRef(t, broker.AuthAWSVault))
	_, err := c.Collect(context.Background())
	wantCode(t, err, lifecycle.CodeValidationFailed)
}

func TestCollectorClientTagsHTTPStatus(t *testing.T) {
	cl := &stubClient{idErr: ErrAccessDenied}
	_, err := statusClient{Client: cl}.Instances(context.Background(), "us-east-1")
	var hs interface{ HTTPStatus() int }
	if !errors.As(err, &hs) || hs.HTTPStatus() != 403 || !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("%v", err)
	}
	cl.idErr = ErrExpired
	_, err = statusClient{Client: cl}.Instances(context.Background(), "us-east-1")
	if !errors.As(err, &hs) || hs.HTTPStatus() != 401 {
		t.Fatalf("%v", err)
	}
}
