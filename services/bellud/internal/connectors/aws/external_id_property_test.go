package aws

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"gopkg.in/yaml.v3"
	"pgregory.net/rapid"
)

// Feature: cloud-connectors, Property 23: External ID and trust templates
//
// **Validates: Requirements 3.2, 3.3**

func TestPropertyExternalIDsLongAndDistinct(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 60).Draw(t, "n")
		seen := make(map[string]bool, n)
		for i := 0; i < n; i++ {
			id, err := GenerateExternalID()
			if err != nil {
				t.Fatal(err)
			}
			if len(id) < 32 {
				t.Fatalf("external id %q shorter than 32 chars", id)
			}
			if !externalIDRe.MatchString(id) {
				t.Fatalf("generated id %q rejected by validation", id)
			}
			if seen[id] {
				t.Fatalf("duplicate external id %q", id)
			}
			seen[id] = true
		}
	})
}

func trustParamsGen() *rapid.Generator[TrustParams] {
	return rapid.Custom(func(t *rapid.T) TrustParams {
		return TrustParams{
			RoleName: rapid.StringMatching(`[A-Za-z0-9+=,.@_-]{1,64}`).Draw(t, "role"),
			Principal: rapid.OneOf(
				rapid.StringMatching(`arn:aws:iam::[0-9]{12}:root`),
				rapid.StringMatching(`arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]{1,40}`),
				rapid.StringMatching(`arn:aws-cn:iam::[0-9]{12}:user/[A-Za-z0-9+=,.@_-]{1,40}`),
			).Draw(t, "principal"),
			ExternalID: externalIDGen().Draw(t, "externalID"),
		}
	})
}

// yamlLookup returns the value at the key path, descending through maps and
// the first element of sequences.
func yamlLookup(v any, path ...string) (any, bool) {
	for _, k := range path {
		switch x := v.(type) {
		case map[string]any:
			nv, ok := x[k]
			if !ok {
				return nil, false
			}
			v = nv
		case []any:
			if len(x) == 0 {
				return nil, false
			}
			m, ok := x[0].(map[string]any)
			if !ok {
				return nil, false
			}
			nv, ok := m[k]
			if !ok {
				return nil, false
			}
			v = nv
		default:
			return nil, false
		}
	}
	return v, true
}

func TestPropertyTrustTemplatesParseAndEmbedExternalID(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := trustParamsGen().Draw(t, "params")

		cfn, err := CloudFormationTemplate(p)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(cfn), &doc); err != nil {
			t.Fatalf("cloudformation is not valid YAML: %v\n%s", err, cfn)
		}
		got, ok := yamlLookup(doc, "Resources", "BelluRole", "Properties", "AssumeRolePolicyDocument",
			"Statement", "Condition", "StringEquals", "sts:ExternalId")
		if !ok || got != p.ExternalID {
			t.Fatalf("yaml external id = %v (found=%v), want %q", got, ok, p.ExternalID)
		}
		if pr, _ := yamlLookup(doc, "Resources", "BelluRole", "Properties", "AssumeRolePolicyDocument",
			"Statement", "Principal", "AWS"); pr != p.Principal {
			t.Fatalf("yaml principal = %v, want %q", pr, p.Principal)
		}
		if rn, _ := yamlLookup(doc, "Resources", "BelluRole", "Properties", "RoleName"); rn != p.RoleName {
			t.Fatalf("yaml role name = %v, want %q", rn, p.RoleName)
		}

		tf, err := TerraformSnippet(p)
		if err != nil {
			t.Fatal(err)
		}
		file, diags := hclsyntax.ParseConfig([]byte(tf), "main.tf", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("terraform is not valid HCL: %v\n%s", diags, tf)
		}
		literals := map[string]bool{}
		_ = hclsyntax.VisitAll(file.Body.(*hclsyntax.Body), func(n hclsyntax.Node) hcl.Diagnostics {
			if e, ok := n.(hclsyntax.Expression); ok {
				if _, isTpl := e.(*hclsyntax.TemplateExpr); isTpl {
					if v, d := e.Value(nil); !d.HasErrors() && v.IsKnown() && v.Type().FriendlyName() == "string" {
						literals[v.AsString()] = true
					}
				}
			}
			return nil
		})
		for _, want := range []string{p.ExternalID, p.Principal, p.RoleName} {
			if !literals[want] {
				t.Fatalf("hcl has no string literal %q", want)
			}
		}
	})
}

func TestPropertyEveryAssumeRoleCarriesExternalID(outer *testing.T) {
	rapid.Check(outer, func(t *rapid.T) {
		ext := rapid.StringMatching(`[A-Za-z0-9+=,.@:/_-]{32,120}`).Draw(t, "externalID")
		refreshes := rapid.IntRange(1, 6).Draw(t, "refreshes")
		failEvery := rapid.IntRange(0, 3).Draw(t, "failEvery") // 0 = never fail; else every Nth call is denied

		// Sessions expire inside the refresh window, so each Retrieve calls STS.
		rt := &countingRT{handle: func(n int, _ url.Values, _ *http.Request) (int, string) {
			if failEvery > 0 && n%(failEvery+1) == 0 {
				return 403, deniedXML
			}
			return 200, assumeXML(time.Now().Add(time.Second))
		}}
		p := newRoleProvider(outer, rt, func(c *AssumeRoleConfig) { c.ExternalID = ext })

		for i := 0; i < refreshes && !p.Expired(); i++ {
			_, _ = p.Retrieve(context.Background())
		}
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if len(rt.forms) == 0 {
			t.Fatal("no AssumeRole call was sent")
		}
		for i, f := range rt.forms {
			if f.Get("Action") != "AssumeRole" || f.Get("ExternalId") != ext {
				t.Fatalf("call %d lacks external id %q: %v", i, ext, f)
			}
		}
	})
}

// externalIDGen mixes real generated IDs with arbitrary valid ones.
func externalIDGen() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		if rapid.Bool().Draw(t, "generated") {
			id, err := GenerateExternalID()
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		return rapid.StringMatching(`[A-Za-z0-9+=,.@:/_-]{32,200}`).Draw(t, "literal")
	})
}
