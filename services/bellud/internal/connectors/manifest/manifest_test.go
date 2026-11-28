package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func valid() Manifest {
	return Manifest{
		ID:      "aws",
		Version: "1.0.0",
		Name:    "AWS",
		Icon:    "aws",
		AuthMethods: []AuthMethod{
			{ID: "assume-role", Name: "Assume role", Enabled: true},
			{ID: "sso", Name: "SSO", Enabled: false, DisabledReason: "Available in a later release"},
		},
		Permissions: []Permission{{Name: "ReadOnlyAccess", ReadOnly: true}},
		Operations: []Operation{
			{Name: "ec2:DescribeInstances", Class: ClassRead, Host: "ec2.{region}.amazonaws.com"},
			{Name: "sts:AssumeRole", Class: ClassAuth, Host: "sts.{region}.amazonaws.com"},
			{Name: "GET /repos/{o}/{r}/pulls", Class: ClassRead, Method: "GET", Host: "api.github.com", Path: "/repos/{o}/{r}/pulls", MaxBytes: 1 << 20},
			{Name: "POST /graphql", Class: ClassRead, Method: "POST", Host: "api.github.com", Path: "/graphql", Query: true, StripKeys: []string{"secret"}},
		},
		Egress:   []string{"sts.{region}.amazonaws.com", "*.s3.{region}.amazonaws.com"},
		Entities: []string{"aws_account", "aws_resource"},
	}
}

func fields(errs []FieldError) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Field
	}
	return out
}

func TestValidateAcceptsValid(t *testing.T) {
	if errs := Validate(valid()); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]struct {
		mut   func(*Manifest)
		field string
	}{
		"id upper":        {func(m *Manifest) { m.ID = "AWS" }, "id"},
		"id empty":        {func(m *Manifest) { m.ID = "" }, "id"},
		"id long":         {func(m *Manifest) { m.ID = strings.Repeat("a", 65) }, "id"},
		"version":         {func(m *Manifest) { m.Version = "1.0" }, "version"},
		"name empty":      {func(m *Manifest) { m.Name = "" }, "name"},
		"name long":       {func(m *Manifest) { m.Name = strings.Repeat("é", 65) }, "name"},
		"no auth":         {func(m *Manifest) { m.AuthMethods = nil }, "auth_methods"},
		"six auth":        {func(m *Manifest) { m.AuthMethods = make([]AuthMethod, 6) }, "auth_methods"},
		"perm not read":   {func(m *Manifest) { m.Permissions[0].ReadOnly = false }, "permissions[0].read_only"},
		"51 perms":        {func(m *Manifest) { m.Permissions = make([]Permission, 51) }, "permissions"},
		"201 ops":         {func(m *Manifest) { m.Operations = make([]Operation, 201) }, "operations"},
		"51 egress":       {func(m *Manifest) { m.Egress = make([]string, 51) }, "egress"},
		"egress scheme":   {func(m *Manifest) { m.Egress[0] = "https://x.com" }, "egress[0]"},
		"no entities":     {func(m *Manifest) { m.Entities = nil }, "entities"},
		"101 entities":    {func(m *Manifest) { m.Entities = make([]string, 101) }, "entities"},
		"bad class":       {func(m *Manifest) { m.Operations[0].Class = "write" }, "operations[0].class"},
		"bad method":      {func(m *Manifest) { m.Operations[2].Method = "get" }, "operations[2].method"},
		"disabled no why": {func(m *Manifest) { m.AuthMethods[1].DisabledReason = "" }, "auth_methods[1].disabled_reason"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := valid()
			c.mut(&m)
			got := fields(Validate(m))
			for _, f := range got {
				if f == c.field {
					return
				}
			}
			t.Fatalf("want field %q in %v", c.field, got)
		})
	}
}

func TestValidateRejectsWriteListedAsRead(t *testing.T) {
	for _, op := range []Operation{
		{Name: "ec2:TerminateInstances", Class: ClassRead, Host: "ec2.amazonaws.com"},
		{Name: "DELETE /x", Class: ClassRead, Method: "DELETE", Host: "api.github.com"},
		{Name: "POST /x", Class: ClassRead, Method: "POST", Host: "api.github.com"},
		{Name: "unknown", Class: ClassRead, Host: "x.com"},
	} {
		m := valid()
		m.Operations = []Operation{op}
		errs := Validate(m)
		if len(errs) != 1 || errs[0].Field != "operations[0].class" {
			t.Fatalf("%s: got %v", op.Name, errs)
		}
	}
}

func TestErrorsDoNotEchoValues(t *testing.T) {
	m := valid()
	m.ID = "SECRET-VALUE-ID"
	m.Egress[0] = "SECRET://host"
	for _, e := range Validate(m) {
		if strings.Contains(e.Error(), "SECRET") {
			t.Fatalf("value echoed: %v", e)
		}
	}
}

func TestIsWrite(t *testing.T) {
	cases := []struct {
		op   Operation
		want bool
	}{
		{Operation{Method: "GET"}, false},
		{Operation{Method: "HEAD"}, false},
		{Operation{Method: "OPTIONS"}, false},
		{Operation{Method: "POST"}, true},
		{Operation{Method: "POST", Query: true}, false},
		{Operation{Method: "PUT", Query: true}, true},
		{Operation{Method: "PATCH"}, true},
		{Operation{Method: "DELETE"}, true},
		{Operation{Method: "TRACE"}, true},
		{Operation{Name: "ec2:DescribeInstances"}, false},
		{Operation{Name: "s3:ListBuckets"}, false},
		{Operation{Name: "iam:SimulatePrincipalPolicy"}, false},
		{Operation{Name: "sts:GetCallerIdentity"}, false},
		{Operation{Name: "ec2:RunInstances"}, true},
		{Operation{Name: "s3:PutObject"}, true},
		{Operation{Name: "sts:AssumeRole"}, true},
		{Operation{Name: "ec2:Listing"}, true},
		{Operation{Name: "DescribeInstances"}, true},
		{Operation{Name: "ec2:"}, true},
	}
	for _, c := range cases {
		if got := IsWrite(c.op); got != c.want {
			t.Errorf("IsWrite(%+v) = %v, want %v", c.op, got, c.want)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	m := valid()
	data, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip mismatch:\n%+v\n%+v", got, m)
	}
	if _, err := Parse([]byte(`{"id":"x","bogus":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func resolved(t *testing.T) *jsonschema.Resolved {
	t.Helper()
	var s jsonschema.Schema
	if err := json.Unmarshal(Schema(), &s); err != nil {
		t.Fatal(err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func asInstance(t *testing.T, m Manifest) any {
	t.Helper()
	data, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSchemaAcceptsValidManifest(t *testing.T) {
	if err := resolved(t).Validate(asInstance(t, valid())); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaAgreesWithValidate(t *testing.T) {
	rs := resolved(t)
	muts := map[string]func(*Manifest){
		"id":          func(m *Manifest) { m.ID = "Bad_ID" },
		"version":     func(m *Manifest) { m.Version = "x" },
		"no auth":     func(m *Manifest) { m.AuthMethods = nil },
		"perm write":  func(m *Manifest) { m.Permissions[0].ReadOnly = false },
		"no entities": func(m *Manifest) { m.Entities = nil },
		"egress":      func(m *Manifest) { m.Egress = []string{"HTTP://x"} },
		"class":       func(m *Manifest) { m.Operations[0].Class = "write" },
		"disabled":    func(m *Manifest) { m.AuthMethods[1].DisabledReason = "" },
	}
	for name, mut := range muts {
		m := valid()
		mut(&m)
		if len(Validate(m)) == 0 {
			t.Fatalf("%s: Validate accepted", name)
		}
		if err := rs.Validate(asInstance(t, m)); err == nil {
			t.Errorf("%s: schema accepted", name)
		}
	}
}

func TestPublishedSchemaMatchesEmbedded(t *testing.T) {
	pub, err := os.ReadFile("../../../../../docs/connectors/manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, Schema()) {
		t.Fatal("docs/connectors/manifest.schema.json differs from the embedded schema")
	}
}
