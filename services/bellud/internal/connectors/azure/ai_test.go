package azure

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

func aiHandler(failDeployments bool) http.Handler {
	acct := "/subscriptions/" + sub + "/resourceGroups/RG1/providers/Microsoft.CognitiveServices/accounts/oai1"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.ToLower(r.URL.Path)
		switch {
		case p == "/subscriptions":
			w.Write([]byte(`{"value":[{"subscriptionId":"` + sub + `"}]}`))
		case strings.HasSuffix(p, "/microsoft.cognitiveservices/accounts"):
			w.Write([]byte(`{"value":[{"id":"` + acct + `","kind":"OpenAI","location":"westeurope","tags":{"criticality":"critical"},` +
				`"properties":{"publicNetworkAccess":"Enabled","disableLocalAuth":false}}]}`))
		case strings.HasSuffix(p, "/deployments"):
			if failDeployments {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Write([]byte(`{"value":[{"id":"` + acct + `/deployments/gpt","name":"gpt","properties":{"model":{"format":"OpenAI","name":"gpt-4o","version":"1"}}}]}`))
		case strings.HasSuffix(p, "/microsoft.machinelearningservices/workspaces"):
			w.Write([]byte(`{"value":[{"id":"/subscriptions/` + sub + `/resourceGroups/RG1/providers/Microsoft.MachineLearningServices/workspaces/ws1","location":"westeurope","properties":{"publicNetworkAccess":"Disabled"}}]}`))
		default:
			w.Write([]byte(`{"value":[]}`))
		}
	})
}

func TestCollectAIEntities(t *testing.T) {
	b, err := newTestCollector(t, aiHandler(false)).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var account, model, workspace map[string]any
	for _, e := range b.Entities {
		switch {
		case e.Type == aischema.KindModel:
			model = e.Attributes
		case e.Type == aischema.KindService && e.Attributes["ai_type"] == "azure:openai-account":
			account = e.Attributes
		case e.Type == aischema.KindService:
			workspace = e.Attributes
		}
	}
	if account == nil || account["public_access"] != "enabled" || account["authentication"] != "key" || account["criticality"] != 1.0 {
		t.Fatalf("account = %v", account)
	}
	if model == nil || model["model_name"] != "gpt-4o" || model["criticality"] != 1.0 {
		t.Fatalf("model = %v", model)
	}
	if workspace == nil || workspace["public_access"] != nil {
		t.Fatalf("workspace = %v", workspace)
	}
	serves := 0
	for _, r := range b.Relations {
		if r.Type == aischema.RelServes {
			serves++
		}
	}
	if serves != 1 {
		t.Fatalf("ai_serves = %d", serves)
	}
}

func TestCollectAIFailureAddsNothingAndRetains(t *testing.T) {
	b, err := newTestCollector(t, aiHandler(true)).Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || len(pe.Types) != 1 || pe.Types[0] != typeAI {
		t.Fatalf("err = %v, want partial ai", err)
	}
	for _, e := range b.Entities {
		if e.Type == aischema.KindService || e.Type == aischema.KindModel {
			t.Fatalf("failed scope emitted %s", e.Type)
		}
	}
	retained := 0
	for _, r := range b.Retain {
		if r.Kind == aischema.KindService || r.Kind == aischema.KindModel {
			retained++
		}
	}
	if retained != 2 {
		t.Fatalf("retain rules = %d, want 2", retained)
	}
}
