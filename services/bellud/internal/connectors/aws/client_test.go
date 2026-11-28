package aws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

const (
	testRole = "arn:aws:iam::123456789012:role/bellu-read"
	testExt  = "BELLU-TESTEXTERNALID234567ABCDEFGHIJKLMNOPQRSTUV"
)

// countingRT counts requests that reach the "network" and records their form
// bodies.
type countingRT struct {
	n      atomic.Int32
	mu     sync.Mutex
	forms  []url.Values
	hosts  []string
	handle func(n int, form url.Values, r *http.Request) (int, string)
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	n := int(c.n.Add(1))
	var form url.Values
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(b))
	}
	c.mu.Lock()
	c.forms = append(c.forms, form)
	c.hosts = append(c.hosts, r.URL.Host)
	c.mu.Unlock()
	status, body := c.handle(n, form, r)
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)), Request: r,
	}, nil
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

type keyOpener struct{}

func (keyOpener) Use(_ context.Context, _ vault.Ref, fn func([]byte) error) error {
	return fn([]byte(`{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`))
}

func testManifest() manifest.Manifest {
	r := func(name, host string) manifest.Operation {
		return manifest.Operation{Name: name, Class: manifest.ClassRead, Host: host}
	}
	return manifest.Manifest{
		ID: "aws", Version: "1.0.0", Name: "AWS",
		AuthMethods: []manifest.AuthMethod{{ID: "assume-role", Name: "AssumeRole", Enabled: true}},
		Entities:    []string{"aws_resource"},
		Egress:      []string{"sts.{region}.amazonaws.com", "iam.amazonaws.com", "ec2.{region}.amazonaws.com"},
		Operations: []manifest.Operation{
			{Name: "sts:AssumeRole", Class: manifest.ClassAuth, Method: "POST", Query: true, Host: "sts.{region}.amazonaws.com"},
			r("sts:GetCallerIdentity", "sts.{region}.amazonaws.com"),
			r("iam:SimulatePrincipalPolicy", "iam.amazonaws.com"),
			r("ec2:DescribeInstances", "ec2.{region}.amazonaws.com"),
		},
	}
}

func newRef(t *testing.T, auth broker.AuthKind) broker.ConnectionRef {
	t.Helper()
	m := testManifest()
	p, err := policy.Compile(m, policy.Selection{Regions: []string{"us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	return broker.ConnectionRef{ID: "c1", ConnectorID: "aws", Manifest: m, Policy: p, Auth: auth,
		Credential: vault.Ref{Owner: vault.OwnerConnection, OwnerID: "c1", Slot: "primary"}}
}

func newBroker(rt http.RoundTripper) *broker.Broker {
	return broker.New(broker.Config{Opener: keyOpener{}, Audit: &memAudit{}, Redactor: redactor.New(), Inner: rt, RatePerSecond: 1000})
}

func newTestClient(t *testing.T, b *broker.Broker, caller string) Client {
	t.Helper()
	ref := newRef(t, broker.AuthAWSVault)
	c, err := NewClient(Config{HTTPClient: b.HTTPClient(ref, caller), Credentials: b.AWSCredentials(ref, caller), HomeRegion: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const callerXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/bellu-read/sess</Arn><UserId>U</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`

const simXML = `<SimulatePrincipalPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><SimulatePrincipalPolicyResult><IsTruncated>false</IsTruncated><EvaluationResults>` +
	`<member><EvalActionName>s3:PutObject</EvalActionName><EvalDecision>allowed</EvalDecision></member>` +
	`<member><EvalActionName>s3:DeleteObject</EvalActionName><EvalDecision>implicitDeny</EvalDecision></member>` +
	`</EvaluationResults></SimulatePrincipalPolicyResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></SimulatePrincipalPolicyResponse>`

const instancesXML = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r</requestId><reservationSet><item><instancesSet><item>` +
	`<instanceId>i-0abc</instanceId><instanceType>t3.micro</instanceType><vpcId>vpc-1</vpcId><subnetId>subnet-1</subnetId>` +
	`<instanceState><code>16</code><name>running</name></instanceState>` +
	`<groupSet><item><groupId>sg-1</groupId></item></groupSet>` +
	`<tagSet><item><key>Name</key><value>web</value></item></tagSet>` +
	`</item></instancesSet></item></reservationSet></DescribeInstancesResponse>`

func TestClientProjectsTypedResults(t *testing.T) {
	rt := &countingRT{handle: func(_ int, f url.Values, r *http.Request) (int, string) {
		switch {
		case strings.HasPrefix(r.URL.Host, "sts."):
			return 200, callerXML
		case strings.HasPrefix(r.URL.Host, "iam."):
			return 200, simXML
		}
		return 200, instancesXML
	}}
	c := newTestClient(t, newBroker(rt), policy.CallerCollector)
	ctx := context.Background()

	id, err := c.Identity(ctx)
	if err != nil || id.Account != "123456789012" || id.PrincipalARN != testRole {
		t.Fatalf("identity %+v err %v", id, err)
	}
	allowed, err := c.SimulateWrites(ctx, testRole, []string{"s3:PutObject", "s3:DeleteObject"})
	if err != nil || len(allowed) != 1 || allowed[0].Action != "s3:PutObject" {
		t.Fatalf("simulate %+v err %v", allowed, err)
	}
	l, err := c.Instances(ctx, "us-east-1")
	ins := l.Items
	if err != nil || len(ins) != 1 || ins[0].ID != "i-0abc" || ins[0].Name != "web" || ins[0].State != "running" ||
		ins[0].VPCID != "vpc-1" || len(ins[0].SecurityGroupIDs) != 1 || ins[0].TagCount != 1 {
		t.Fatalf("instances %+v err %v", ins, err)
	}
	if rt.n.Load() != 3 {
		t.Fatalf("expected 3 requests, got %d", rt.n.Load())
	}
}

func TestClientUnlistedOperationNeverReachesNetwork(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) { return 200, "" }}
	c := newTestClient(t, newBroker(rt), policy.CallerCollector)
	_, err := c.VPCs(context.Background(), "us-east-1") // ec2:DescribeVpcs is not in the manifest
	var be *broker.BlockedError
	if !errors.As(err, &be) || rt.n.Load() != 0 {
		t.Fatalf("err=%v n=%d", err, rt.n.Load())
	}
}

func TestClientMapsAccessDenied(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) {
		return 403, `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>nope</Message></Error><RequestId>r</RequestId></ErrorResponse>`
	}}
	c := newTestClient(t, newBroker(rt), policy.CallerLifecycle)
	_, err := c.SimulateWrites(context.Background(), testRole, []string{"s3:PutObject"})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewClientRequiresBrokerPieces(t *testing.T) {
	if _, err := NewClient(Config{HomeRegion: "us-east-1"}); err == nil {
		t.Fatal("expected error without http client and credentials")
	}
}

func TestPrincipalAndRootARNs(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sts::123456789012:assumed-role/bellu-read/sess": testRole,
		"arn:aws-us-gov:sts::123456789012:assumed-role/r/s":      "arn:aws-us-gov:iam::123456789012:role/r",
		"arn:aws:iam::123456789012:user/alice":                   "arn:aws:iam::123456789012:user/alice",
		"arn:aws:sts::123456789012:assumed-role/onlyrole":        "arn:aws:sts::123456789012:assumed-role/onlyrole",
		"garbage": "garbage",
	}
	for in, want := range cases {
		if got := PrincipalFromARN(in); got != want {
			t.Errorf("PrincipalFromARN(%q)=%q want %q", in, got, want)
		}
	}
	for arn, root := range map[string]bool{
		"arn:aws:iam::123456789012:root":      true,
		"arn:aws-cn:iam::123456789012:root":   true,
		"arn:aws:iam::12345678901:root":       false,
		"arn:aws:iam::123456789012:role/root": false,
		"arn:aws:iam::123456789012:user/root": false,
		"arn:aws:iam::12345678901a:root":      false,
	} {
		if IsRootARN(arn) != root {
			t.Errorf("IsRootARN(%q) != %v", arn, root)
		}
	}
}

func TestAmbientCredentialsFromEnvironmentOnly(t *testing.T) {
	env := map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY": "s3cr3tkey"}
	p := AmbientCredentials(nil, func(k string) string { return env[k] })
	c, err := p.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("%+v %v", c, err)
	}
	empty := AmbientCredentials(nil, func(string) string { return "" })
	if _, err := empty.Retrieve(context.Background()); !errors.Is(err, ErrNoAmbientCredentials) {
		t.Fatalf("err=%v", err)
	}
}

var _ awssdk.CredentialsProvider = (*RoleProvider)(nil)
