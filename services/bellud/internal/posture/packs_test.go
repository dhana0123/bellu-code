package posture

import (
	"context"
	"testing"
)

func bundledEngine(t *testing.T) *Engine {
	t.Helper()
	ps, errs, err := LoadAll(Bundled())
	if err != nil || len(errs) != 0 {
		t.Fatalf("load: %v %v", err, errs)
	}
	e, cerrs := NewEngine(context.Background(), ps, fakeReader{})
	if len(cerrs) != 0 {
		t.Fatal(cerrs)
	}
	return e
}

func fired(t *testing.T, e *Engine, typ string, attrs map[string]any) map[string]bool {
	t.Helper()
	ms, errs := e.EvalEntity(context.Background(), Input{ID: typ + ":1", Type: typ, Attributes: attrs})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	out := map[string]bool{}
	for _, m := range ms {
		out[m.PackID+"/"+m.RuleID] = true
	}
	return out
}

func TestBundledPacksRules(t *testing.T) {
	e := bundledEngine(t)
	type c struct {
		typ   string
		attrs map[string]any
		rule  string
	}
	bad := []c{
		{"aws_resource", map[string]any{"resource_type": "s3:bucket", "public_access": "enabled"}, "cis_aws/s3_public_access"},
		{"aws_resource", map[string]any{"resource_type": "s3:bucket", "encryption_at_rest": "disabled"}, "cis_aws/s3_encryption_at_rest"},
		{"aws_resource", map[string]any{"resource_type": "s3:bucket", "logging": "disabled"}, "cis_aws/s3_logging"},
		{"aws_resource", map[string]any{"resource_type": "rds:instance", "encryption_at_rest": "disabled"}, "cis_aws/rds_encrypted"},
		{"aws_resource", map[string]any{"resource_type": "rds:instance", "public_access": "enabled"}, "cis_aws/rds_not_public"},
		{"aws_resource", map[string]any{"resource_type": "rds:instance", "backup": "disabled"}, "cis_aws/rds_backups"},
		{"aws_sg_rule", map[string]any{"direction": "ingress", "internet_open": "true", "from_port": 20, "to_port": 30, "sg": "sg"}, "cis_aws/sg_ssh_open"},
		{"aws_sg_rule", map[string]any{"direction": "ingress", "internet_open": "true", "sg": "sg"}, "cis_aws/sg_rdp_open"},
		{"aws_policy_statement", map[string]any{"effect": "Allow", "actions": "*", "resources": []any{"*"}}, "cis_aws/iam_admin_policy"},
		{"aws_sg_rule", map[string]any{"direction": "ingress", "internet_open": "true", "from_port": 8080, "to_port": 8080, "sg": "sg"}, "bellu/open_ingress"},
		{"aws_sg_rule", map[string]any{"direction": "ingress", "internet_open": "true", "from_port": 80, "to_port": 90, "sg": "sg"}, "bellu/open_ingress"},
		{"k8s_service", map[string]any{"direction": "ingress", "internet_open": "true", "from_port": 6379, "to_port": 6379}, "bellu/open_ingress"},
		{"aws_resource", map[string]any{"public_access": "enabled", "data_classes": []any{"PII"}}, "bellu/data_exposure"},
		{"ai_agent", map[string]any{"has_write_tool": "true", "external_input": "true"}, "bellu/ai_agent_write_tool_external_input"},
		{"ai_service", map[string]any{"public_access": "enabled", "authentication": "none"}, "bellu/ai_endpoint_public_unauthenticated"},
		{"ai_model", map[string]any{"serialization_format": "Pickle"}, "bellu/ai_model_unsafe_serialization"},
		{"github_repo", map[string]any{"visibility": "public"}, "repo_hygiene/repo_public"},
		{"github_repo", map[string]any{"default_branch": "main", "default_branch_protected": false}, "repo_hygiene/repo_branch_protection"},
		{"github_alert", map[string]any{"alert_type": "dependabot", "state": "open"}, "repo_hygiene/open_dependabot_alert"},
		{"github_alert", map[string]any{"alert_type": "secret_scanning", "state": "open"}, "repo_hygiene/open_secret_scanning_alert"},
		{"gcp_resource", map[string]any{"gcp_type": "storage.googleapis.com/Bucket", "public_access": "enabled"}, "cis_gcp/gcs_public_access"},
		{"gcp_resource", map[string]any{"gcp_type": "compute.googleapis.com/Firewall", "direction": "ingress", "internet_open": "true"}, "cis_gcp/firewall_ssh_open"},
		{"gcp_iam_binding", map[string]any{"role": "roles/owner"}, "cis_gcp/iam_owner_binding"},
		{"azure_resource", map[string]any{"azure_type": "azure:storage-account", "https_only": "disabled"}, "cis_azure/storage_https_only"},
		{"azure_resource", map[string]any{"azure_type": "azure:nsg", "direction": "ingress", "internet_open": "true", "from_port": 3380, "to_port": 3400}, "cis_azure/nsg_rdp_open"},
		{"k8s_pod", map[string]any{"privileged": "true"}, "cis_k8s/privileged_pod"},
		{"k8s_binding", map[string]any{"role_ref": "cluster-admin"}, "cis_k8s/cluster_admin_binding"},
	}
	for _, b := range bad {
		if !fired(t, e, b.typ, b.attrs)[b.rule] {
			t.Errorf("%s did not fire", b.rule)
		}
	}
	good := []c{
		{"ai_agent", map[string]any{"has_write_tool": "true", "external_input": "true", "input_validated": "true"}, "bellu/ai_agent_write_tool_external_input"},
		{"ai_service", map[string]any{"public_access": "enabled", "authentication": "oauth"}, "bellu/ai_endpoint_public_unauthenticated"},
		{"ai_model", map[string]any{"serialization_format": "safetensors"}, "bellu/ai_model_unsafe_serialization"},
		{"aws_resource", map[string]any{"resource_type": "s3:bucket", "public_access": "disabled", "encryption_at_rest": "enabled", "logging": "enabled", "encryption_in_transit": "enabled"}, ""},
		{"aws_resource", map[string]any{"resource_type": "rds:instance", "public_access": "disabled", "encryption_at_rest": "enabled", "backup": "enabled"}, ""},
		{"aws_sg_rule", map[string]any{"direction": "ingress", "internet_open": "false", "from_port": 22, "to_port": 22}, ""},
		{"aws_sg_rule", map[string]any{"direction": "ingress", "internet_open": "true", "from_port": 443, "to_port": 443}, ""},
		{"aws_policy_statement", map[string]any{"effect": "Allow", "actions": []any{"s3:GetObject"}, "resources": "*"}, ""},
		{"aws_resource", map[string]any{"public_access": "enabled", "data_classes": []any{"public_docs"}}, ""},
		{"github_repo", map[string]any{"visibility": "private", "default_branch_protected": true}, ""},
		{"github_alert", map[string]any{"alert_type": "dependabot", "state": "fixed"}, ""},
		{"gcp_resource", map[string]any{"gcp_type": "storage.googleapis.com/Bucket", "public_access": "disabled"}, ""},
		{"azure_resource", map[string]any{"azure_type": "azure:nsg", "direction": "ingress", "internet_open": "true", "from_port": 443, "to_port": 443}, ""},
		{"k8s_pod", map[string]any{"privileged": "false", "host_network": "false", "run_as_root": "false"}, ""},
		{"k8s_binding", map[string]any{"role_ref": "view"}, ""},
	}
	for _, g := range good {
		if f := fired(t, e, g.typ, g.attrs); len(f) != 0 {
			t.Errorf("compliant %v fired %v", g.attrs, f)
		}
	}
	// Unknown values never violate.
	unknown := []c{
		{"aws_resource", map[string]any{"resource_type": "s3:bucket", "public_access": "unknown", "encryption_at_rest": "unknown", "logging": "unknown", "encryption_in_transit": "unknown"}, ""},
		{"aws_resource", map[string]any{"resource_type": "rds:instance", "public_access": "unknown", "encryption_at_rest": "unknown", "backup": "unknown"}, ""},
		{"aws_resource", map[string]any{"public_access": "unknown", "encryption_at_rest": "unknown", "data_classes": []any{"pii"}}, ""},
		{"aws_sg_rule", map[string]any{"direction": "ingress", "internet_open": "unknown", "from_port": 22, "to_port": 22}, ""},
		{"github_repo", map[string]any{}, ""},
		{"k8s_pod", map[string]any{"privileged": "unknown"}, ""},
		{"gcp_resource", map[string]any{"gcp_type": "sqladmin.googleapis.com/Instance", "public_access": "unknown"}, ""},
	}
	for _, u := range unknown {
		if f := fired(t, e, u.typ, u.attrs); len(f) != 0 {
			t.Errorf("unknown %v fired %v", u.attrs, f)
		}
	}
}
