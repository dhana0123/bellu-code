package overview

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

// TestCardTextsMatchRequirements checks Requirement 1.1 order and 1.2 subtitles.
func TestCardTextsMatchRequirements(t *testing.T) {
	titles := []string{"Cloud infrastructure", "Identity", "Vulnerabilities", "Network exposure", "Secrets",
		"Data security", "Code and dependencies", "Runtime", "AI security"}
	subtitles := []string{"Resources and networks", "Users and permissions", "CVEs and packages",
		"Connectivity and reachability", "Credentials and access", "Databases and sensitive data",
		"Repositories and IaC", "Activity and threats", "Models and agents"}
	e := newEnv(t)
	s, err := e.svc.Summaries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Categories) != 9 {
		t.Fatalf("%d cards", len(s.Categories))
	}
	for i, c := range s.Categories {
		if c.Title != titles[i] {
			t.Errorf("card %d title %q, want %q", i, c.Title, titles[i])
		}
		if c.Subtitle != subtitles[i] {
			t.Errorf("card %d subtitle %q, want %q", i, c.Subtitle, subtitles[i])
		}
	}
}

// TestSummaries100kTiming records the p95 of Summaries on a 100,000 entity
// graph (Requirement 1.6).
func TestSummaries100kTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("100k entity timing test skipped under -short")
	}
	const total, batchSize, calls = 100_000, 5_000, 30
	e := newEnv(t)
	types := []string{"ec2:instance", "iam:role", "s3:bucket", "ec2:security-group", "ec2:eni", "iam:user"}
	built := time.Now()
	for start := 0; start < total; start += batchSize {
		b := batch.Batch{Collector: fmt.Sprintf("aws-%d", start), ObservedAt: time.Now().UTC()}
		for i := start; i < start+batchSize; i++ {
			b.Entities = append(b.Entities, batch.Entity{Type: "aws_resource",
				Identity:   map[string]string{"connection": "c1", "arn": fmt.Sprintf("arn:%d", i)},
				Attributes: map[string]any{"resource_type": types[i%len(types)]}})
		}
		if _, err := e.eng.Ingest().Apply(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("built %d entities in %s", total, time.Since(built).Round(time.Millisecond))
	// Start was called on an empty graph; recount through the service.
	t0 := time.Now()
	if err := e.svc.rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Logf("rebuild over %d entities: %s", total, time.Since(t0).Round(time.Millisecond))
	sum := 0
	s, err := e.svc.Summaries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Categories {
		sum += c.EntityCount
	}
	if sum != total {
		t.Fatalf("counted %d entities, want %d", sum, total)
	}
	lat := make([]time.Duration, calls)
	for i := range lat {
		t1 := time.Now()
		if _, err := e.svc.Summaries(context.Background()); err != nil {
			t.Fatal(err)
		}
		lat[i] = time.Since(t1)
	}
	slices.SortFunc(lat, func(a, b time.Duration) int { return int(a - b) })
	p95 := lat[int(float64(len(lat))*0.95)-1]
	t.Logf("Summaries over %d calls: min=%s p50=%s p95=%s max=%s", calls, lat[0], lat[len(lat)/2], p95, lat[len(lat)-1])
	if p95 >= 2*time.Second {
		t.Fatalf("p95 %s, want < 2s", p95)
	}
}

func TestScannerFindingsCountInSecretsAndCodeCards(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id string, typ findings.Type, cat schema.OverviewCategory) findings.Finding {
		return findings.Finding{ID: findings.ID("r", id, "x"), RuleID: "r", Title: id, Category: cat, Type: typ,
			Severity: findings.SevHigh, Status: findings.StatusOpen, AssetID: id, FirstSeen: now, LastSeen: now, Source: "t"}
	}
	fs := []findings.Finding{mk("a", findings.TypeSecret, schema.OvSecrets), mk("b", findings.TypeMisconfiguration, schema.OvCode)}
	if _, err := e.fs.Report(context.Background(), findings.ScanRef{JobID: "j1"}, fs); err != nil {
		t.Fatal(err)
	}
	e.svc.Refresh()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, _ := e.card(t, schema.OvSecrets)
		if c.Severity[findings.SevHigh] == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, c := range []schema.OverviewCategory{schema.OvSecrets, schema.OvCode} {
		if card, _ := e.card(t, c); card.Severity[findings.SevHigh] != 1 {
			t.Errorf("%s: %v", c, card.Severity)
		}
	}
}
