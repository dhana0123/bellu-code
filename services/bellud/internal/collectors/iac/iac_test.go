package iac

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
)

var _ collectors.Collector = (*Collector)(nil)

const tf = `
# comment
provider "aws" { region = "us-east-1" }

resource "aws_s3_bucket" "logs" {
  acl = "public-read"
  tags = {
    Name = "x"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
}

module "vpc" {
  source = "./vpc"
}

resource "aws_db_instance" "db"
{
  publicly_accessible = true
}
`

const manifests = `
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: prod}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod, labels: {app: web}}
spec:
  template:
    spec:
      serviceAccountName: app
      hostNetwork: true
      containers:
        - name: c
          image: nginx:1
          securityContext: {privileged: true}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: reader}
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: rb}
roleRef: {kind: ClusterRole, name: reader}
---
foo: bar
`

func TestCollect(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o600)
	os.WriteFile(filepath.Join(dir, "k.yaml"), []byte(manifests), 0o600)
	os.MkdirAll(filepath.Join(dir, "node_modules"), 0o700)
	os.WriteFile(filepath.Join(dir, "node_modules", "x.tf"), []byte(tf), 0o600)

	b, err := New(dir).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addrs := map[string]map[string]any{}
	kinds := map[string]map[string]any{}
	for _, e := range b.Entities {
		switch e.Type {
		case "iac_resource":
			addrs[e.Identity["address"]] = e.Attributes
		case "k8s_object":
			kinds[e.Identity["kind"]+"/"+e.Identity["namespace"]+"/"+e.Identity["name"]] = e.Attributes
		}
	}
	for _, a := range []string{"aws_s3_bucket.logs", "data.aws_ami.ubuntu", "module.vpc", "aws_db_instance.db"} {
		if addrs[a] == nil {
			t.Errorf("missing %s: %v", a, addrs)
		}
	}
	if len(addrs) != 4 {
		t.Errorf("want 4 iac resources, got %d", len(addrs))
	}
	if addrs["aws_s3_bucket.logs"]["acl"] != "public-read" || addrs["aws_s3_bucket.logs"]["provider"] != "aws" {
		t.Errorf("attrs: %v", addrs["aws_s3_bucket.logs"])
	}
	if addrs["aws_db_instance.db"]["publicly_accessible"] != true {
		t.Errorf("pending-brace block attrs: %v", addrs["aws_db_instance.db"])
	}
	if addrs["module.vpc"]["source"] != "./vpc" {
		t.Errorf("module: %v", addrs["module.vpc"])
	}
	for _, k := range []string{"ServiceAccount/prod/app", "Deployment/prod/web", "ClusterRole/-/reader", "ClusterRoleBinding/-/rb"} {
		if kinds[k] == nil {
			t.Errorf("missing k8s %s: %v", k, kinds)
		}
	}
	d := kinds["Deployment/prod/web"]
	if d["privileged"] != true || d["host_network"] != true || d["service_account_name"] != "app" {
		t.Errorf("deployment attrs: %v", d)
	}
	if len(b.Relations) != 2 {
		t.Fatalf("want 2 relations, got %+v", b.Relations)
	}
	types := map[string]bool{}
	for _, r := range b.Relations {
		types[r.Type] = true
		if r.Attributes != nil {
			t.Error("relation has attributes")
		}
	}
	if !types["uses_service_account"] || !types["binds"] {
		t.Errorf("relation types: %v", types)
	}
}

func TestSizeCap(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, MaxFileSize+1)
	copy(big, tf)
	os.WriteFile(filepath.Join(dir, "big.tf"), big, 0o600)
	b, _ := New(dir).Collect(context.Background())
	if len(b.Entities) != 0 {
		t.Errorf("oversized file read: %d entities", len(b.Entities))
	}
}
