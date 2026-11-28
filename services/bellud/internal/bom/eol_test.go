package bom

import (
	"testing"
	"time"
)

func TestEOLCheck(t *testing.T) {
	chk, err := EOLCheck()
	if err != nil {
		t.Fatal(err)
	}
	v := "5.7.44"
	p := Package{Name: "mysql", Version: &v}
	d := func(s string) time.Time { x, _ := time.Parse("2006-01-02", s); return x }
	if f := chk(p, d("2023-11-30")); len(f) != 1 || f[0].Severity != "medium" || f[0].Rule != EOLRule {
		t.Fatalf("recent: %+v", f)
	}
	a := chk(p, d("2024-06-01"))
	b := chk(p, d("2025-01-01"))
	if len(a) != 1 || a[0].Severity != "high" || a[0].ID != b[0].ID {
		t.Fatalf("old: %+v %+v", a, b)
	}
	if f := chk(p, d("2023-01-01")); len(f) != 0 {
		t.Fatalf("not yet EOL: %+v", f)
	}
}

func TestLicenseDeniedAndPostureData(t *testing.T) {
	if !LicenseDenied([]string{"GPL-3.0"})("gpl-3.0") || LicenseDenied(nil)("MIT") {
		t.Fatal("license deny")
	}
	if len(PostureData()["ai_unsafe_formats"].([]any)) == 0 {
		t.Fatal("no formats")
	}
}
