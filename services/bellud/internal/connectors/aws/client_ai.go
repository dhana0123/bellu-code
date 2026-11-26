package aws

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

// AIEndpoint is a SageMaker endpoint projection. Criticality is the
// value of its "criticality" tag.
type AIEndpoint struct {
	ARN, Name, Region, Status string
	Criticality               string
}

// AIAgent is a Bedrock agent projection. RoleARN is the agent's service role.
type AIAgent struct {
	ARN, ID, Name, Region, Status, RoleARN string
	Criticality                            string
}

// AIClient lists AI assets. The collector uses it when the Client also
// implements it, so fakes that do not are unaffected.
type AIClient interface {
	SageMakerEndpoints(ctx context.Context, region string) ([]AIEndpoint, error)
	BedrockAgents(ctx context.Context, region string) ([]AIAgent, error)
}

var _ AIClient = (*client)(nil)

func (c *client) SageMakerEndpoints(ctx context.Context, region string) ([]AIEndpoint, error) {
	cl := sagemaker.NewFromConfig(c.base(region))
	var res []AIEndpoint
	p := sagemaker.NewListEndpointsPaginator(cl, &sagemaker.ListEndpointsInput{})
	err := pager(ctx, p.HasMorePages, func(ctx context.Context) error {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, e := range page.Endpoints {
			ep := AIEndpoint{ARN: awssdk.ToString(e.EndpointArn), Name: awssdk.ToString(e.EndpointName),
				Region: region, Status: string(e.EndpointStatus)}
			// A tag read that fails only leaves criticality unset.
			if tags, err := cl.ListTags(ctx, &sagemaker.ListTagsInput{ResourceArn: e.EndpointArn}); err == nil {
				for _, t := range tags.Tags {
					if awssdk.ToString(t.Key) == "criticality" {
						ep.Criticality = awssdk.ToString(t.Value)
					}
				}
			}
			res = append(res, ep)
		}
		return nil
	})
	return res, err
}

func (c *client) BedrockAgents(ctx context.Context, region string) ([]AIAgent, error) {
	cl := bedrockagent.NewFromConfig(c.base(region))
	var res []AIAgent
	p := bedrockagent.NewListAgentsPaginator(cl, &bedrockagent.ListAgentsInput{})
	err := pager(ctx, p.HasMorePages, func(ctx context.Context) error {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, s := range page.AgentSummaries {
			a := AIAgent{ID: awssdk.ToString(s.AgentId), Name: awssdk.ToString(s.AgentName),
				Region: region, Status: string(s.AgentStatus)}
			got, err := cl.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: s.AgentId})
			if err != nil {
				return err
			}
			if got.Agent == nil {
				continue
			}
			a.ARN = awssdk.ToString(got.Agent.AgentArn)
			a.RoleARN = awssdk.ToString(got.Agent.AgentResourceRoleArn)
			if tags, err := cl.ListTagsForResource(ctx, &bedrockagent.ListTagsForResourceInput{ResourceArn: got.Agent.AgentArn}); err == nil {
				a.Criticality = tags.Tags["criticality"]
			}
			res = append(res, a)
		}
		return nil
	})
	return res, err
}
