package effective

import (
	"testing"
	"time"
)

func TestHighRiskFindings(t *testing.T) {
	in := Inputs{Identity: []Policy{{{Actions: []string{"iam:*"}, Resources: []string{"*"}}}}}
	got := HighRiskFindings("u1", in, nil, nil, nil)
	if len(got) != 2 || got[0].Action != "iam:PassRole" || got[1].Action != "iam:*" || got[0].Severity != "high" {
		t.Fatalf("got %+v", got)
	}
	open := map[string]bool{FindingKey("u1", "iam:PassRole"): true}
	if got := HighRiskFindings("u1", in, nil, nil, open); len(got) != 1 {
		t.Fatalf("open pair not skipped: %+v", got)
	}
	sts := Inputs{Identity: []Policy{{{Actions: []string{"sts:AssumeRole"}, Resources: []string{"arn:aws:iam::1:role/admin"}}}}}
	if got := HighRiskFindings("u1", sts, nil, nil, nil); len(got) != 0 {
		t.Fatalf("assume without admin role: %+v", got)
	}
	if got := HighRiskFindings("u1", sts, nil, []string{"arn:aws:iam::1:role/admin"}, nil); len(got) != 1 {
		t.Fatalf("assume admin: %+v", got)
	}
}

func TestLastUsedFindings(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old, recent := now.Add(-91*24*time.Hour), now.Add(-89*24*time.Hour)
	got := LastUsedFindings(now, []Use{{"a", &old}, {"b", &recent}, {"c", nil}}, nil)
	if len(got) != 1 || got[0].Identity != "a" || got[0].Severity != "low" {
		t.Fatalf("got %+v", got)
	}
}

func TestCanAssumeRelations(t *testing.T) {
	got := CanAssumeRelations([]Trust{
		{AWS, "arn:aws:iam::222:role/x", "222", "arn:aws:iam::111:role/t", "111"},
		{AWS, "arn:aws:iam::333:root", "333", "arn:aws:iam::111:role/t", "111"},
		{AWS, "*", "", "arn:aws:iam::111:role/t", "111"},
		{AWS, "arn:aws:iam::111:role/y", "111", "arn:aws:iam::111:role/t", "111"},
		{GCP, "serviceAccount:a@p2.iam", "p2", "sa@p1", "p1"},
	})
	if len(got) != 4 {
		t.Fatalf("got %+v", got)
	}
	conf := map[string]Confidence{}
	for _, r := range got {
		conf[r.From] = r.Confidence
	}
	if conf["arn:aws:iam::222:role/x"] != Extracted || conf["arn:aws:iam::333:root"] != Inferred || conf["*"] != Inferred || conf["serviceAccount:a@p2.iam"] != Extracted {
		t.Fatalf("confidence %+v", conf)
	}
}

func TestGaps(t *testing.T) {
	got := Gaps("aws", []CollectionResult{{Kind: "role", Scope: "1", Denied: true, Permission: "iam:ListRoles"}, {Kind: "user", Scope: "1"}})
	if len(got) != 1 || got[0].Permission != "iam:ListRoles" || got[0].Reason != "missing_permission" {
		t.Fatalf("got %+v", got)
	}
}
