package ident

import (
	"errors"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

func TestHashGolden(t *testing.T) {
	cases := []struct {
		kind string
		id   map[string]string
		want string
	}{
		{"host", map[string]string{"hostname": "web-1"}, "host:fe1c72acbf340314776943d30489cf82"},
		{"container", map[string]string{"id": "abc123"}, "container:519e9b3282adbda5e91413d99f2c5f3c"},
		{"listening_port", map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "443", "extra": "x"}, "listening_port:96ec1501c61e5d9662f329fe8fccc242"},
	}
	for _, c := range cases {
		got, err := Hash(c.kind, c.id)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v want %q", c.kind, got, err, c.want)
		}
	}
}

func TestHashErrors(t *testing.T) {
	if _, err := Hash("nope", nil); !errors.Is(err, errs.Validation) {
		t.Errorf("unknown kind: %v", err)
	}
	if _, err := Hash("host", map[string]string{"hostname": ""}); !errors.Is(err, errs.Validation) {
		t.Errorf("empty attr: %v", err)
	}
}

func TestKinds(t *testing.T) {
	if n := len(Kinds()); n != 28 {
		t.Fatalf("kinds = %d", n)
	}
	a, _ := IdentityAttributes("endpoint")
	if len(a) != 3 || a[0] != "protocol" {
		t.Fatalf("endpoint attrs %v", a)
	}
}

func TestConnectorKindsAreConnectionScoped(t *testing.T) {
	for _, k := range []string{"aws_account", "aws_resource", "github_org", "github_repo", "github_workflow", "github_pull_request", "github_alert"} {
		a, ok := IdentityAttributes(k)
		if !ok || len(a) == 0 || a[0] != "connection" {
			t.Errorf("%s attrs %v", k, a)
		}
		if IsSecretName(k) {
			t.Errorf("%s matches secret rule", k)
		}
		for _, n := range a {
			if IsSecretName(n) {
				t.Errorf("%s attr %s matches secret rule", k, n)
			}
		}
	}
}
func TestDirection(t *testing.T) {
	if d, def := DirectionOf("found_in"); d != Forward || def {
		t.Error("found_in")
	}
	if d, def := DirectionOf("runs_on"); d != Reverse || def {
		t.Error("runs_on")
	}
	if d, def := DirectionOf("whatever"); d != Reverse || !def {
		t.Error("default")
	}
}

func TestLabel(t *testing.T) {
	id := map[string]string{"host": "h", "protocol": "tcp", "address": "a", "port": "1"}
	if got := Label("listening_port", id, nil); got != "h/tcp/a/1" {
		t.Error(got)
	}
	if got := Label("listening_port", id, map[string]any{"name": "web"}); got != "web" {
		t.Error(got)
	}
	if got := Label("listening_port", id, map[string]any{"name": ""}); got != "h/tcp/a/1" {
		t.Error(got)
	}
}

func TestSecretAndState(t *testing.T) {
	for _, n := range []string{"API_KEY", "dbPassword", "x_hash", "Private", "apikey", "auth_token"} {
		if !IsSecretName(n) {
			t.Errorf("%s should be secret", n)
		}
	}
	if IsSecretName("hostname") {
		t.Error("hostname")
	}
	if !IsStateAttr("state") || !IsStateAttr("status") || IsStateAttr("name") {
		t.Error("state attr")
	}
}
