package broker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
)

const deviceToken = "ghu_0123456789abcdefghijklmnopqrstuvwxyz"

func deviceManifest() manifest.Manifest {
	m := ghManifest()
	m.Egress = append(m.Egress, "github.com")
	m.Operations = append(m.Operations,
		manifest.Operation{Name: "POST /login/device/code", Class: manifest.ClassAuth, Method: "POST", Query: true,
			Host: "github.com", Path: "/login/device/code", MaxBytes: 16 << 10},
		manifest.Operation{Name: "POST /login/oauth/access_token", Class: manifest.ClassAuth, Method: "POST", Query: true,
			Host: "github.com", Path: "/login/oauth/access_token", MaxBytes: 16 << 10, IssuesCredential: true},
	)
	return m
}

func devicePreRef(t *testing.T) ConnectionRef {
	t.Helper()
	m := deviceManifest()
	p, err := policy.Compile(m, policy.Selection{Regions: []string{"us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	return PreConnectionRef("github", m, p, "a1")
}

func postForm(b *Broker, ref ConnectionRef, path, ctype, body string) (*http.Response, error) {
	return b.HTTPClient(ref, policy.CallerLifecycle).Post("https://github.com"+path, ctype, strings.NewReader(body))
}

func TestPreConnectionRef(t *testing.T) {
	ref := devicePreRef(t)
	if ref.Auth != AuthNone || ref.ID != "device:a1" || ref.ConnectorID != "github" {
		t.Fatalf("unexpected ref %+v", ref)
	}
}

func TestAuthNoneInjectsNoAuthorization(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{"device_code":"x"}`)}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	resp, err := postForm(b, devicePreRef(t), "/login/device/code", "application/x-www-form-urlencoded", "client_id=Iv1.abc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if rt.n.Load() != 1 || rt.last.Header.Get("Authorization") != "" {
		t.Fatalf("sent=%d auth=%q", rt.n.Load(), rt.last.Header.Get("Authorization"))
	}
	got, _ := io.ReadAll(rt.last.Body)
	if string(got) != "client_id=Iv1.abc" {
		t.Fatalf("body not restored: %q", got)
	}
}

func TestCheckAuthBodyBlocks(t *testing.T) {
	form := "application/x-www-form-urlencoded"
	cases := []struct{ name, ctype, body string }{
		{"form client_secret", form, "client_id=a&client_secret=s"},
		{"form client_secret case", form, "client_id=a&Client_Secret=s"},
		{"json client_secret", "application/json", `{"client_id":"a","client_secret":"s"}`},
		{"unknown key", form, "client_id=a&redirect_uri=x"},
		{"empty", form, ""},
		{"bad json", "application/json", `{"client_id":`},
		{"oversized", form, "client_id=" + strings.Repeat("a", MaxAuthBody)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt := &countingRT{fn: respond(200, `{}`)}
			b, a := newBroker(rt, fakeOpener{secret: token}, 100)
			_, err := postForm(b, devicePreRef(t), "/login/oauth/access_token", c.ctype, c.body)
			if err == nil || !strings.Contains(err.Error(), "blocked") {
				t.Fatalf("want blocked, got %v", err)
			}
			if rt.n.Load() != 0 {
				t.Fatal("blocked call sent bytes")
			}
			es := a.entries()
			if len(es) != 1 || es[0].Event != audit.EventBlockedOperation || es[0].ConnectionID != "device:a1" {
				t.Fatalf("audit: %+v", es)
			}
		})
	}
}

func TestCheckAuthBodyAllows(t *testing.T) {
	for _, c := range []struct{ ctype, body string }{
		{"application/x-www-form-urlencoded", "client_id=a&device_code=d&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"},
		{"application/json", `{"client_id":"a","scope":"x"}`},
	} {
		rt := &countingRT{fn: respond(200, `{}`)}
		b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
		resp, err := postForm(b, devicePreRef(t), "/login/oauth/access_token", c.ctype, c.body)
		if err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		resp.Body.Close()
	}
}

func TestIssuesCredentialSkipsTokenPatternButKeepsRegistered(t *testing.T) {
	registered := "registeredsecretvalue99"
	body := `{"access_token":"` + deviceToken + `","token_type":"bearer","echo":"` + registered + `"}`
	rt := &countingRT{fn: respond(200, body)}
	a := &memAudit{}
	rd := redactor.New()
	rd.Register([]byte(registered))
	b := New(Config{Opener: fakeOpener{secret: token}, Audit: a, Redactor: rd, Inner: rt, RatePerSecond: 100})
	res, err := b.Do(context.Background(), Call{Connection: devicePreRef(t), Caller: policy.CallerLifecycle,
		Operation: "POST /login/oauth/access_token", Params: map[string]any{"client_id": "Iv1.abc", "device_code": "d"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Body), deviceToken) {
		t.Fatalf("ghu_ token was replaced: %s", res.Body)
	}
	if strings.Contains(string(res.Body), registered) || !strings.Contains(string(res.Body), redactor.Marker) {
		t.Fatalf("registered secret not redacted: %s", res.Body)
	}
	for _, e := range a.entries() {
		if strings.Contains(strings.Join(mapValues(e.Detail), " "), deviceToken) {
			t.Fatal("token in audit")
		}
	}
}

func TestOtherOperationsStillRedactTokenPatterns(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{"device_code":"`+deviceToken+`"}`)}
	b, _ := newBroker(rt, fakeOpener{secret: token}, 100)
	res, err := b.Do(context.Background(), Call{Connection: devicePreRef(t), Caller: policy.CallerLifecycle,
		Operation: "POST /login/device/code", Params: map[string]any{"client_id": "Iv1.abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Body), deviceToken) {
		t.Fatalf("token pattern not redacted: %s", res.Body)
	}
}

func TestDeviceEndpointsDeniedToCollector(t *testing.T) {
	rt := &countingRT{fn: respond(200, `{}`)}
	b, a := newBroker(rt, fakeOpener{secret: token}, 100)
	_, err := b.HTTPClient(devicePreRef(t), policy.CallerCollector).Post("https://github.com/login/oauth/access_token",
		"application/x-www-form-urlencoded", strings.NewReader("client_id=a"))
	if err == nil || rt.n.Load() != 0 || len(a.entries()) != 1 {
		t.Fatalf("err=%v sent=%d audit=%d", err, rt.n.Load(), len(a.entries()))
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
