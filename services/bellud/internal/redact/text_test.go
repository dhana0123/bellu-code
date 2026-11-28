package redact

import (
	"strings"
	"testing"
)

func TestTextScrubsAWSKeyInFreeText(t *testing.T) {
	secret := "AKIAABCDEFGHIJKLMNOP"
	got, err := Text("found key " + secret + " in config")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED:value_aws_access_key]") {
		t.Fatalf("got %q", got)
	}
}

func TestTextScrubsSecretKeyAssignments(t *testing.T) {
	cases := map[string]string{
		"password=hunter2xyz":               "hunter2xyz",
		`db_password: "s3cr3t value"`:       "s3cr3t value",
		"API_KEY=abc123def456 other=fine":   "abc123def456",
		"url?access_token=tok9876543&x=1":   "tok9876543",
		"aws_secret_access_key = wJalrXUtn": "wJalrXUtn",
	}
	for in, secret := range cases {
		got, err := Text(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED:") {
			t.Errorf("%q -> %q", in, got)
		}
	}
	got, _ := Text("API_KEY=abc123def456 other=fine")
	if !strings.Contains(got, "other=fine") {
		t.Errorf("non-secret pair changed: %q", got)
	}
}

func TestTextLeavesNormalTextUnchanged(t *testing.T) {
	for _, in := range []string{"", "scan finished in 3s", "name=web port: 8080", "password=[REDACTED:key_password]"} {
		got, err := Text(in)
		if err != nil || got != in {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
}

func TestTextRemovesPrivateKeyBody(t *testing.T) {
	in := "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\ny"
	got, err := Text(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "MIIBOg") || strings.Contains(got, "BEGIN") {
		t.Fatalf("got %q", got)
	}
}

func TestTextOutputNeverContainsSecret(t *testing.T) {
	secrets := []string{"AKIAABCDEFGHIJKLMNOP", "ghp_" + strings.Repeat("a", 36), "xoxb-1234567890-abcdef"}
	for _, s := range secrets {
		got, err := Text("a " + s + " b token=" + s)
		if err != nil || strings.Contains(got, s) {
			t.Errorf("%q leaked: %q %v", s, got, err)
		}
	}
}
