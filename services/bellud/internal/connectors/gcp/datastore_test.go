package gcp

import (
	"encoding/json"
	"testing"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBucketAttrs(t *testing.T) {
	a := bucketAttrs(decode(t, `{"location":"US","versioning":{"enabled":true},"logging":{"logBucket":"l"},"iamConfiguration":{"publicAccessPrevention":"enforced"}}`))
	for k, v := range map[string]string{"encryption_at_rest": "enabled", "encryption_in_transit": "unknown",
		"public_access": "disabled", "backup": "enabled", "logging": "enabled"} {
		if a[k] != v {
			t.Errorf("%s = %v, want %s", k, a[k], v)
		}
	}
	if b := bucketAttrs(decode(t, `{}`)); b["public_access"] != "unknown" || b["backup"] != "disabled" {
		t.Errorf("bare bucket = %v", b)
	}
}

func TestSQLAttrs(t *testing.T) {
	a := sqlAttrs(decode(t, `{"region":"r","settings":{"backupConfiguration":{"enabled":false},
		"ipConfiguration":{"ipv4Enabled":true,"requireSsl":true,"authorizedNetworks":[{"value":"0.0.0.0/0"}]}}}`))
	for k, v := range map[string]string{"encryption_at_rest": "enabled", "encryption_in_transit": "enabled",
		"public_access": "enabled", "backup": "disabled", "logging": "unknown"} {
		if a[k] != v {
			t.Errorf("%s = %v, want %s", k, a[k], v)
		}
	}
	if b := sqlAttrs(decode(t, `{}`)); b["public_access"] != "unknown" || b["backup"] != "unknown" {
		t.Errorf("bare instance = %v", b)
	}
}
