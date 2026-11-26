package aws

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aiattr"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

// AI steps (task 49.3). A SageMaker endpoint becomes an ai_service and a
// Bedrock agent an ai_agent, both keyed by (connection, ARN). A failed call
// adds nothing for its region, so the step's Retain rule keeps what an earlier
// run stored. A Client that is not an AIClient is skipped.
//
// SageMaker and Bedrock expose no public-access or authentication setting on
// these listings (access is IAM-signed), so public_access and authentication
// are not emitted; ai_agent has_write_tool, external_input and input_validated
// are filled by the repository scanner.

func (r *run) sagemaker(ctx context.Context, rg string) error {
	ai, ok := r.c.client.(AIClient)
	if !ok {
		return nil
	}
	eps, err := ai.SageMakerEndpoints(ctx, rg)
	if err != nil {
		return err
	}
	for _, e := range eps {
		a := map[string]any{"name": e.Name, "state": e.Status, "service": "sagemaker", "ai_type": "sagemaker.endpoint"}
		aiattr.Set(a, e.Criticality)
		r.addAI(aischema.KindService, e.ARN, rg, a)
	}
	return nil
}

func (r *run) bedrockAgents(ctx context.Context, rg string) error {
	ai, ok := r.c.client.(AIClient)
	if !ok {
		return nil
	}
	agents, err := ai.BedrockAgents(ctx, rg)
	if err != nil {
		return err
	}
	for _, g := range agents {
		a := map[string]any{"name": g.Name, "state": g.Status, "service": "bedrock", "ai_type": "bedrock.agent",
			"agent_id": g.ID, "role_arn": g.RoleARN}
		aiattr.Set(a, g.Criticality)
		if r.addAI(aischema.KindAgent, g.ARN, rg, a) && g.RoleARN != "" {
			// Resolved after every step, so the role must be collected too.
			r.b.rel(aischema.RelUsesIdentity, aiKey(g.ARN), g.RoleARN, nil)
		}
	}
	return nil
}

func aiKey(arn string) string { return "ai:" + arn }

// addAI emits one AI entity with identity (connection, id=ARN).
func (r *run) addAI(kind, arn, region string, attrs map[string]any) bool {
	if arn == "" {
		return false
	}
	if _, dup := r.b.seen[aiKey(arn)]; dup {
		return false
	}
	idn := map[string]string{"connection": r.c.connID, "id": arn}
	id, err := identity.Hash(kind, idn)
	if err != nil {
		return false
	}
	a := map[string]any{"connection": r.c.connID, "id": arn, "arn": arn, "source": r.b.source, "region": region}
	for k, v := range attrs {
		a[k] = v
	}
	r.b.b.Entities = append(r.b.b.Entities, batch.Entity{Type: kind, Identity: idn, Attributes: a})
	r.b.seen[aiKey(arn)] = string(id)
	return true
}
