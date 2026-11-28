package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

type aiFake struct {
	*fakeClient
	eps    []AIEndpoint
	agents []AIAgent
	fail   bool
}

func (a aiFake) SageMakerEndpoints(context.Context, string) ([]AIEndpoint, error) {
	if a.fail {
		return nil, ErrAccessDenied
	}
	return a.eps, nil
}
func (a aiFake) BedrockAgents(context.Context, string) ([]AIAgent, error) { return a.agents, nil }

func TestCollectAIEntities(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/r"
	f := aiFake{fakeClient: newFake(nil),
		eps:    []AIEndpoint{{ARN: "arn:aws:sagemaker:eu-west-1:123456789012:endpoint/e", Name: "e", Status: "InService", Criticality: "high"}},
		agents: []AIAgent{{ARN: "arn:aws:bedrock:eu-west-1:123456789012:agent/A1", ID: "A1", Name: "bot", RoleARN: role}}}
	b, err := newTestCollector(f).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var svc, agent map[string]any
	for _, e := range b.Entities {
		switch e.Type {
		case aischema.KindService:
			svc = e.Attributes
		case aischema.KindAgent:
			agent = e.Attributes
		}
	}
	if svc == nil || svc["criticality"] != 0.75 || svc["id"] == "" {
		t.Fatalf("service = %v", svc)
	}
	if agent == nil || agent["role_arn"] != role {
		t.Fatalf("agent = %v", agent)
	}
	uses := 0
	for _, r := range b.Relations {
		if r.Type == aischema.RelUsesIdentity {
			uses++
		}
	}
	if uses != 1 {
		t.Fatalf("ai_uses_identity relations = %d, want 1", uses)
	}
}

func TestCollectAIFailureKeepsPriorEntities(t *testing.T) {
	f := aiFake{fakeClient: newFake(nil), fail: true}
	b, err := newTestCollector(f).Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || len(pe.Types) != 1 || pe.Types[0] != "ai-sagemaker" {
		t.Fatalf("err = %v, want partial ai-sagemaker", err)
	}
	retained := false
	for _, e := range b.Entities {
		if e.Type == aischema.KindService {
			t.Fatal("failed scope must emit no ai_service")
		}
	}
	for _, r := range b.Retain {
		retained = retained || r.Kind == aischema.KindService
	}
	if !retained {
		t.Fatal("failed scope must retain ai_service entities")
	}
}
