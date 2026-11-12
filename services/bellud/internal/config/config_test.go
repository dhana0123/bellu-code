package config

import (
	"path/filepath"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Hostname != "127.0.0.1" || c.Port != 4096 || c.Password != "" || c.Addr() != "127.0.0.1:4096" {
		t.Fatalf("unexpected defaults: %+v addr=%s", c, c.Addr())
	}
	if len(c.Warnings()) != 0 {
		t.Fatalf("unexpected warnings: %v", c.Warnings())
	}
}

func TestPasswordPrecedence(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"bellu only", map[string]string{"BELLUCODE_PASSWORD": "b"}, "b"},
		{"opencode fallback", map[string]string{"OPENCODE_PASSWORD": "o"}, "o"},
		{"bellu wins", map[string]string{"BELLUCODE_PASSWORD": "b", "OPENCODE_PASSWORD": "o"}, "b"},
		{"none", nil, ""},
	}
	for _, tc := range cases {
		c, err := Load(env(tc.env))
		if err != nil || c.Password != tc.want {
			t.Errorf("%s: got %q err=%v, want %q", tc.name, c.Password, err, tc.want)
		}
	}
}

func TestOverridesAndPortValidation(t *testing.T) {
	c, err := Load(env(map[string]string{
		"BELLUCODE_HOSTNAME": "0.0.0.0", "BELLUCODE_PORT": "5000",
		"BELLUCODE_CORS": "http://x", "BELLUCODE_WEB_DIST": "/w",
	}))
	if err != nil || c.Addr() != "0.0.0.0:5000" || c.CORS != "http://x" || c.WebDist != "/w" {
		t.Fatalf("got %+v err=%v", c, err)
	}
	for _, bad := range []string{"abc", "-1", "70000"} {
		if _, err := Load(env(map[string]string{"BELLUCODE_PORT": bad})); err == nil {
			t.Errorf("port %q should fail", bad)
		}
	}
}

func TestWarnings(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if w := (Config{Hostname: h}).Warnings(); len(w) != 0 {
			t.Errorf("%s: unexpected warning %v", h, w)
		}
	}
	if w := (Config{Hostname: "0.0.0.0"}).Warnings(); len(w) != 1 {
		t.Errorf("expected warning for non-loopback without password")
	}
	if w := (Config{Hostname: "0.0.0.0", Password: "p"}).Warnings(); len(w) != 0 {
		t.Errorf("no warning expected with password: %v", w)
	}
}

func TestPathHelpers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cd, err := ConfigDir()
	if err != nil || cd != filepath.Join(home, ".config", "bellucode") {
		t.Errorf("ConfigDir = %q, %v", cd, err)
	}
	dd, err := DataDir()
	if err != nil || dd != filepath.Join(home, ".local", "share", "bellucode") {
		t.Errorf("DataDir = %q, %v", dd, err)
	}
}

func TestLoadEnv(t *testing.T) {
	t.Setenv("BELLUCODE_PASSWORD", "")
	t.Setenv("OPENCODE_PASSWORD", "fallback")
	t.Setenv("BELLUCODE_PORT", "")
	c, err := LoadEnv()
	if err != nil || c.Password != "fallback" {
		t.Fatalf("got %+v err=%v", c, err)
	}
}
