package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
)

func assumeXML(expires time.Time) string {
	return `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials>` +
		`<AccessKeyId>ASIAEXAMPLESESSION1</AccessKeyId><SecretAccessKey>sessionsecretkeyvalue1234567890</SecretAccessKey>` +
		`<SessionToken>sessiontokenvalue</SessionToken><Expiration>` + expires.UTC().Format(time.RFC3339) + `</Expiration>` +
		`</Credentials></AssumeRoleResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></AssumeRoleResponse>`
}

const deniedXML = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>no</Message></Error><RequestId>r</RequestId></ErrorResponse>`

func newRoleProvider(t *testing.T, rt *countingRT, mut func(*AssumeRoleConfig)) *RoleProvider {
	t.Helper()
	b := newBroker(rt)
	ref := newRef(t, broker.AuthAWSVault)
	cfg := AssumeRoleConfig{
		RoleARN: testRole, ExternalID: testExt, Region: "us-east-1",
		Base: b.AWSCredentials(ref, policy.CallerLifecycle), HTTPClient: b.HTTPClient(ref, policy.CallerLifecycle),
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	if mut != nil {
		mut(&cfg)
	}
	p, err := NewAssumeRoleProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAssumeRoleSendsExternalIDAndCachesSession(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) {
		return 200, assumeXML(time.Now().Add(time.Hour))
	}}
	p := newRoleProvider(t, rt, nil)
	for i := 0; i < 3; i++ {
		c, err := p.Retrieve(context.Background())
		if err != nil || c.AccessKeyID != "ASIAEXAMPLESESSION1" || c.SessionToken == "" {
			t.Fatalf("retrieve %d: %+v %v", i, c, err)
		}
	}
	if rt.n.Load() != 1 {
		t.Fatalf("session was not cached: %d STS calls", rt.n.Load())
	}
	f := rt.forms[0]
	if f.Get("Action") != "AssumeRole" || f.Get("ExternalId") != testExt || f.Get("RoleArn") != testRole || f.Get("DurationSeconds") != "3600" {
		t.Fatalf("unexpected AssumeRole form: %v", f)
	}
}

func TestAssumeRoleRefreshesInsideWindow(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) {
		return 200, assumeXML(time.Now().Add(200 * time.Second)) // inside the 300 s window
	}}
	p := newRoleProvider(t, rt, nil)
	for i := 0; i < 2; i++ {
		if _, err := p.Retrieve(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if rt.n.Load() != 2 {
		t.Fatalf("expected a refresh on each call, got %d STS calls", rt.n.Load())
	}
	// ExternalId is sent in every call.
	for i, f := range rt.forms {
		if f.Get("ExternalId") != testExt {
			t.Fatalf("call %d lacks the external id", i)
		}
	}
}

func TestAssumeRoleRetriesThenExpires(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) { return 403, deniedXML }}
	var expired atomic.Int32
	var sleeps []time.Duration
	p := newRoleProvider(t, rt, func(c *AssumeRoleConfig) {
		c.OnExpired = func(error) { expired.Add(1) }
		c.Sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
	})
	_, err := p.Retrieve(context.Background())
	if !errors.Is(err, ErrExpired) || !p.Expired() {
		t.Fatalf("err=%v expired=%v", err, p.Expired())
	}
	if rt.n.Load() != 1+RefreshRetries || expired.Load() != 1 {
		t.Fatalf("calls=%d expired=%d", rt.n.Load(), expired.Load())
	}
	if len(sleeps) != 3 || !(sleeps[0] < sleeps[1] && sleeps[1] < sleeps[2]) {
		t.Fatalf("delays must increase: %v", sleeps)
	}
	// Once expired nothing more is sent.
	before := rt.n.Load()
	if _, err := p.Retrieve(context.Background()); !errors.Is(err, ErrExpired) || rt.n.Load() != before {
		t.Fatalf("err=%v sent=%d", err, rt.n.Load()-before)
	}
}

func TestAssumeRoleRecoversOnRetry(t *testing.T) {
	rt := &countingRT{handle: func(n int, _ url.Values, _ *http.Request) (int, string) {
		if n < 3 {
			return 403, deniedXML
		}
		return 200, assumeXML(time.Now().Add(time.Hour))
	}}
	p := newRoleProvider(t, rt, nil)
	if _, err := p.Retrieve(context.Background()); err != nil || p.Expired() {
		t.Fatalf("err=%v expired=%v", err, p.Expired())
	}
}

func TestAssumeRoleClampsDurationAndValidates(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) {
		return 200, assumeXML(time.Now().Add(time.Hour))
	}}
	p := newRoleProvider(t, rt, func(c *AssumeRoleConfig) { c.Duration = 12 * time.Hour })
	if _, err := p.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := rt.forms[0].Get("DurationSeconds"); got != "3600" {
		t.Fatalf("DurationSeconds=%s", got)
	}
	b := newBroker(rt)
	ref := newRef(t, broker.AuthAWSVault)
	base := AssumeRoleConfig{RoleARN: testRole, ExternalID: testExt, Region: "us-east-1",
		Base: b.AWSCredentials(ref, policy.CallerLifecycle), HTTPClient: b.HTTPClient(ref, policy.CallerLifecycle)}
	for name, mut := range map[string]func(*AssumeRoleConfig){
		"role":     func(c *AssumeRoleConfig) { c.RoleARN = "arn:aws:iam::1:role/x" },
		"external": func(c *AssumeRoleConfig) { c.ExternalID = "" },
		"client":   func(c *AssumeRoleConfig) { c.HTTPClient = nil },
	} {
		c := base
		mut(&c)
		if _, err := NewAssumeRoleProvider(c); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestAssumeRoleBlockedForCollectorCaller(t *testing.T) {
	rt := &countingRT{handle: func(int, url.Values, *http.Request) (int, string) { return 200, assumeXML(time.Now().Add(time.Hour)) }}
	p := newRoleProvider(t, rt, nil)
	// Rebuild with a collector-caller HTTP client: class auth is lifecycle only.
	b := newBroker(rt)
	ref := newRef(t, broker.AuthAWSVault)
	cp, err := NewAssumeRoleProvider(AssumeRoleConfig{RoleARN: testRole, ExternalID: testExt, Region: "us-east-1",
		Base: b.AWSCredentials(ref, policy.CallerCollector), HTTPClient: b.HTTPClient(ref, policy.CallerCollector),
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	_ = p
	_, err = cp.Retrieve(context.Background())
	if err == nil || rt.n.Load() != 0 {
		t.Fatalf("err=%v sent=%d (%s)", err, rt.n.Load(), fmt.Sprint(rt.hosts))
	}
}
