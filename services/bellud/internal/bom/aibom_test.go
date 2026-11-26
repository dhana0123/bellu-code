package bom

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBuildAI(t *testing.T) {
	ctx := context.Background()
	local := []AIItem{
		{Name: "langchain", Category: AIFramework, Version: "0.3", Source: Source{"manifest", "requirements.txt"}},
		{Name: "langchain", Category: AIFramework, Version: "0.3", Source: Source{"code", "a.py"}},
		{Name: "m.gguf", Category: AIModel, Source: Source{"code", "m.gguf"}},
	}
	ok := ProviderSource[AIItem]{Provider: "aws", Fetch: func(context.Context) ([]AIItem, error) {
		return []AIItem{{Name: "llama", Category: AIModel, License: "GPL-3.0", Source: Source{"cloud", "arn:1"}}}, nil
	}}
	doc := BuildAI(ctx, local, []ProviderSource[AIItem]{ok}, AIOptions{
		LicenseDenied: func(l string) bool { return strings.EqualFold(l, "gpl-3.0") },
	})
	if len(doc.Incomplete) != 0 || len(doc.SBOM.Packages) != 3 {
		t.Fatalf("got %d packages, gaps %v", len(doc.SBOM.Packages), doc.Incomplete)
	}
	by := map[string]Package{}
	for _, p := range doc.SBOM.Packages {
		by[p.Name] = p
	}
	if p := by["langchain"]; p.Type != "framework" || len(p.Locations) != 2 {
		t.Errorf("langchain: %+v", p)
	}
	if p := by["m.gguf"]; p.Type != "machine-learning-model" || *p.Version != "unknown" || p.Licenses[0] != "unknown" || p.Properties[PropLicenseDeny] != "" {
		t.Errorf("m.gguf: %+v", p)
	}
	if by["llama"].Properties[PropLicenseDeny] != "true" {
		t.Errorf("llama not flagged")
	}
	var buf bytes.Buffer
	if err := Write(ctx, &buf, doc.SBOM, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildCloudFailureKeepsPrior(t *testing.T) {
	ctx := context.Background()
	aws := ProviderSource[CloudItem]{Provider: "aws", Fetch: func(context.Context) ([]CloudItem, error) {
		return []CloudItem{
			{Service: "rds", ResourceType: "db", Region: "us-east-1", Version: "postgres 11", Endpoint: "db.example:5432"},
			{Service: "rds", ResourceType: "db", Region: "us-east-1", Version: "postgres 11"},
			{Service: "s3", ResourceType: "bucket", Region: "eu-west-1"},
		}, nil
	}}
	prev := BuildCloud(ctx, []ProviderSource[CloudItem]{aws}, CloudOptions{})
	if len(prev.SBOM.Packages) != 2 {
		t.Fatalf("packages: %+v", prev.SBOM.Packages)
	}
	for _, p := range prev.SBOM.Packages {
		if p.Name == "rds" && (p.Properties[PropCount] != "2" || p.Properties[PropEndpoint] == "") {
			t.Errorf("rds: %+v", p.Properties)
		}
		if p.Name == "s3" && (p.Properties[PropEndpoint] != "" || p.Properties[PropDataFlow] != "") {
			t.Errorf("s3 has endpoint/data flow: %+v", p.Properties)
		}
	}
	bad := ProviderSource[CloudItem]{Provider: "aws", Fetch: func(context.Context) ([]CloudItem, error) { return nil, errors.New("credentials rejected") }}
	slow := ProviderSource[CloudItem]{Provider: "gcp", Fetch: func(ctx context.Context) ([]CloudItem, error) { <-ctx.Done(); return nil, ctx.Err() }}
	gcp := ProviderSource[CloudItem]{Provider: "azure", Fetch: func(context.Context) ([]CloudItem, error) {
		return []CloudItem{{Service: "aks", ResourceType: "cluster", Region: "westus", Version: "1.27"}}, nil
	}}
	check := func(p Package, _ time.Time) []Finding {
		if p.Name == "aks" {
			return []Finding{{Rule: "test", Component: p.Name}}
		}
		return nil
	}
	doc := BuildCloud(ctx, []ProviderSource[CloudItem]{bad, slow, gcp}, CloudOptions{Prev: &prev, Timeout: 50 * time.Millisecond, Checks: []CloudCheck{check}})
	if len(doc.Incomplete) != 2 || !strings.Contains(doc.Incomplete[0].Cause, "credentials rejected") || !strings.Contains(doc.Incomplete[1].Cause, "no response within") {
		t.Fatalf("gaps: %+v", doc.Incomplete)
	}
	if len(doc.SBOM.Packages) != 3 || len(doc.Findings) != 1 {
		t.Fatalf("packages %d findings %d", len(doc.SBOM.Packages), len(doc.Findings))
	}
	var buf bytes.Buffer
	if err := Write(ctx, &buf, doc.SBOM, Options{}); err != nil {
		t.Fatal(err)
	}
}
