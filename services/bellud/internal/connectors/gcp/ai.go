package gcp

import (
	"context"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aiattr"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
)

// TypeAIEndpoint is the ai_type of a Vertex AI endpoint (task 49.3).
const TypeAIEndpoint = "aiplatform.endpoint"

// aiEndpoints is the Vertex AI endpoint listing. The "-" location asks for
// every region at once.
var aiEndpoints = resourceType{
	typ: TypeAIEndpoint, host: AIPlatformHost, path: "/v1/projects/{p}/locations/-/endpoints",
	items: list("endpoints"),
}

// collectAI reads the Vertex AI endpoints of one project and emits each as an
// ai_service entity keyed by (connection, resource name). A failed listing adds
// nothing and keeps the project's earlier ai_service entities through Retain.
// It returns false when the listing failed.
func (c *collector) collectAI(ctx context.Context, project, source string, b *batch.Batch) bool {
	objs, err := c.pages(ctx, project, aiEndpoints, project)
	if err != nil {
		if ctx.Err() == nil {
			c.status.FailType(TypeAIEndpoint, project, err)
		}
		b.Retain = append(b.Retain, batch.Retain{Kind: aischema.KindService,
			Attrs: map[string]string{"connection": c.connID, "project_id": project}})
		return false
	}
	seen := map[string]bool{}
	for _, o := range objs {
		name := str(o, "name")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		idn := map[string]string{"connection": c.connID, "id": name}
		if _, err := identity.Hash(aischema.KindService, idn); err != nil {
			continue
		}
		b.Entities = append(b.Entities, batch.Entity{Type: aischema.KindService, Identity: idn, Attributes: endpointAttrs(c.connID, project, source, name, o)})
	}
	return true
}

// endpointAttrs maps one endpoint. An endpoint on a private network or with
// Private Service Connect is not public; otherwise it is reachable from the
// internet. Vertex endpoints always require IAM, so authentication is not "none".
func endpointAttrs(conn, project, source, name string, o map[string]any) map[string]any {
	a := map[string]any{
		"connection": conn, "id": name, "resource_name": name, "project_id": project, "source": source,
		"ai_type": TypeAIEndpoint, "name": str(o, "displayName"),
		"authentication": "iam",
	}
	if i := strings.Index(name, "/locations/"); i >= 0 {
		a["location"], _, _ = strings.Cut(name[i+len("/locations/"):], "/")
	}
	psc, _ := o["privateServiceConnectConfig"].(map[string]any)
	if psc["enablePrivateServiceConnect"] != true && str(o, "network") == "" {
		a[aiattr.PublicAccess] = aiattr.Enabled
	}
	labels, _ := o["labels"].(map[string]any)
	if v, ok := labels["criticality"].(string); ok {
		aiattr.Set(a, v)
	}
	return a
}
