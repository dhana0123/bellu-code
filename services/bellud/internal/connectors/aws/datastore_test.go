package aws

import (
	"context"
	"testing"
)

func dataAttrs(t *testing.T, c *netClient, arn string) (map[string]any, *collector) {
	t.Helper()
	col := netCollector(c)
	b, err := col.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range b.Entities {
		if e.Identity["arn"] == arn {
			return e.Attributes, col
		}
	}
	t.Fatalf("entity %s not collected", arn)
	return nil, nil
}

func TestBucketSecurityAttributes(t *testing.T) {
	c := newNetClient()
	c.buckets = []Bucket{{Name: "ok", Region: "eu-west-1"}, {Name: "denied", Region: "eu-west-1"}}
	c.bucketSec = map[string]DataSecurity{
		"ok": {EncryptionAtRest: StateEnabled, EncryptionInTransit: StateUnknown, PublicAccess: StateDisabled,
			Backup: StateEnabled, Logging: StateDisabled},
		"denied": {EncryptionAtRest: StateUnknown, EncryptionInTransit: StateUnknown, PublicAccess: StateUnknown,
			Backup: StateUnknown, Logging: StateUnknown, Gaps: []string{"s3:GetBucketEncryption", "s3:GetBucketLogging"}},
	}
	a, _ := dataAttrs(t, c, "arn:aws:s3:::ok")
	want := map[string]string{"encryption_at_rest": "enabled", "encryption_in_transit": "unknown",
		"public_access": "disabled", "backup": "enabled", "logging": "disabled"}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("ok %s = %v, want %s", k, a[k], v)
		}
	}
	if _, has := a["missing_data"]; has {
		t.Errorf("ok bucket has missing_data %v", a["missing_data"])
	}
	a, col := dataAttrs(t, c, "arn:aws:s3:::denied")
	for k := range want {
		if a[k] != "unknown" {
			t.Errorf("denied %s = %v, want unknown", k, a[k])
		}
	}
	if a["missing_data"] != "s3:GetBucketEncryption,s3:GetBucketLogging" {
		t.Errorf("missing_data = %v", a["missing_data"])
	}
	if len(col.RunStatus().DeniedScopes) != 2 {
		t.Errorf("gaps = %v, want 2", col.RunStatus().DeniedScopes)
	}
}

func TestRDSSecurityAttributes(t *testing.T) {
	c := newNetClient()
	c.dbs = []DBInstance{
		{ARN: "arn:aws:rds:eu-west-1:123456789012:db:a", ID: "a", StorageEncrypted: true, BackupRetention: 7, LogExports: []string{"postgresql"}},
		{ARN: "arn:aws:rds:eu-west-1:123456789012:db:b", ID: "b", PubliclyAccessible: true},
	}
	a, _ := dataAttrs(t, c, c.dbs[0].ARN)
	for k, v := range map[string]string{"encryption_at_rest": "enabled", "encryption_in_transit": "unknown",
		"public_access": "disabled", "backup": "enabled", "logging": "enabled"} {
		if a[k] != v {
			t.Errorf("a %s = %v, want %s", k, a[k], v)
		}
	}
	b, _ := dataAttrs(t, c, c.dbs[1].ARN)
	for k, v := range map[string]string{"encryption_at_rest": "disabled", "public_access": "enabled",
		"backup": "disabled", "logging": "disabled"} {
		if b[k] != v {
			t.Errorf("b %s = %v, want %s", k, b[k], v)
		}
	}
}
