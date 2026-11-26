package azure

import (
	"context"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aiattr"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

// AI inventory (task 49.3): Azure OpenAI accounts and their deployments
// (openaiDeployment) and Azure Machine Learning workspaces (mlWorkspace).
// Accounts and workspaces become ai_service, deployments ai_model. IDs come
// from the ARM id, lower-cased.

const (
	typeAI = "ai"

	cognitiveAPIVersion = "2023-05-01"
	mlAPIVersion        = "2024-04-01"
)

type armAIAccount struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		PublicNetworkAccess string `json:"publicNetworkAccess"`
		DisableLocalAuth    *bool  `json:"disableLocalAuth"`
		NetworkACLs         struct {
			DefaultAction string `json:"defaultAction"`
		} `json:"networkAcls"`
	} `json:"properties"`
}

type armDeployment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		Model             struct {
			Format  string `json:"format"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"model"`
	} `json:"properties"`
}

// collectAI reads one subscription's AI assets. It adds entities only when
// every call succeeded, so a failure leaves the scope to the Retain rules
// that retainAI returns.
func (b *builder) collectAI(ctx context.Context, sub string) error {
	subPath := "/subscriptions/" + sub
	accounts, err := list[armAIAccount](ctx, b.c, sub,
		armURL(subPath+"/providers/Microsoft.CognitiveServices/accounts", cognitiveAPIVersion))
	if err != nil {
		return err
	}
	workspaces, err := list[armAIAccount](ctx, b.c, sub,
		armURL(subPath+"/providers/Microsoft.MachineLearningServices/workspaces", mlAPIVersion))
	if err != nil {
		return err
	}
	type withDeployments struct {
		acct armAIAccount
		deps []armDeployment
	}
	var openai []withDeployments
	for _, a := range accounts {
		if !strings.EqualFold(a.Kind, "OpenAI") || strings.ContainsAny(a.ID, "?#") {
			continue
		}
		deps, err := list[armDeployment](ctx, b.c, sub, armURL(a.ID+"/deployments", cognitiveAPIVersion))
		if err != nil {
			return err
		}
		openai = append(openai, withDeployments{a, deps})
	}

	for _, o := range openai {
		a := o.acct
		attrs := aiAccountAttrs(a, sub, "azure:openai-account")
		attrs["authentication"] = "key"
		if a.Properties.DisableLocalAuth != nil && *a.Properties.DisableLocalAuth {
			attrs["authentication"] = "entra"
		}
		if _, ok := b.add(aischema.KindService, "id", a.ID, attrs); !ok {
			continue
		}
		for _, d := range o.deps {
			da := map[string]any{
				"ai_type": "azure:openai-deployment", "subscription_id": sub, "name": d.Name,
				"model_name": d.Properties.Model.Name, "model_format": d.Properties.Model.Format,
				"model_version": d.Properties.Model.Version, "state": d.Properties.ProvisioningState,
				"location": a.Location,
			}
			aiattr.Set(da, a.Tags["criticality"])
			if _, ok := b.add(aischema.KindModel, "id", d.ID, da); ok {
				b.rel(aischema.RelServes, a.ID, d.ID)
			}
		}
	}
	for _, w := range workspaces {
		attrs := aiAccountAttrs(w, sub, "azure:ml-workspace")
		attrs["authentication"] = "entra"
		b.add(aischema.KindService, "id", w.ID, attrs)
	}
	return nil
}

func aiAccountAttrs(a armAIAccount, sub, aiType string) map[string]any {
	attrs := map[string]any{"ai_type": aiType, "subscription_id": sub, "location": a.Location,
		"resource_group": resourceGroupOf(a.ID), "name": a.ID[strings.LastIndex(a.ID, "/")+1:]}
	if !strings.EqualFold(a.Properties.PublicNetworkAccess, "Disabled") && !strings.EqualFold(a.Properties.NetworkACLs.DefaultAction, "Deny") {
		attrs[aiattr.PublicAccess] = aiattr.Enabled
	}
	aiattr.Set(attrs, a.Tags["criticality"])
	return attrs
}

// retainAI keeps the AI entities an earlier run stored for a subscription.
func (b *builder) retainAI(sub string) {
	for _, k := range []string{aischema.KindService, aischema.KindModel} {
		b.b.Retain = append(b.b.Retain, batch.Retain{Kind: k, Attrs: map[string]string{"subscription_id": sub}})
	}
}
